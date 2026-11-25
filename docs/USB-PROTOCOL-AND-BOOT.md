# USB Protocol, Bootloader, and Safe Flashing

## USB Enumeration & Interfaces

The Bloody W95 Max enumerates in two distinct USB modes on the **same physical USB port**:

| Mode | VID:PID | `bcdDevice` | Control Interface | Transport | Feature Report |
| --- | --- | --- | --- | --- | --- |
| **Normal (factory `0028`)** | `09DA:712F` | `0x0028` | USB Interface `2` (`hidraw`) | Linux `hidraw` (`HIDIOCSFEATURE` / `HIDIOCGFEATURE`) | Report ID `0x07`, 64 bytes total (ID + 63 data) |
| **Normal (prepared `0034`)** | `09DA:712F` | `0x0034` | USB Interface `2` (`hidraw`) | Linux `hidraw` | Report ID `0x07`, 64 bytes total |
| **Bootloader (Rev 2 / Rev 3)** | `09DA:D023` | `0x0002` or `0x0003` | USB Interface `0` (**raw USB control**) | `libusb` / `rusb` control transfers (`SET_REPORT` / `GET_REPORT`) | Report ID `0x07`, 64 bytes total |

In normal mode, the composite device exposes three HID interfaces:
- Interface `0`: Keyboard HID (used to emit keyboard macro events)
- Interface `1`: Mouse HID (pointer movement, wheel, mouse clicks)
- Interface `2`: Vendor control interface (Usage Page `0xFF33`, Usage `0x0578..0x057B`, Feature Report ID `0x07`, 64 bytes)

### Critical Linux Bootloader Gotcha (`hidraw` vs. Raw USB Control)

**Do NOT use Linux `hidraw` to communicate with bootloader `09DA:D023`!**

The bootloader advertises an Interrupt-IN endpoint in its HID interface descriptor, but its firmware is feature-only and does not service continuous host interrupt-IN polls. Under Linux `usbhid`, the kernel repeatedly polls that endpoint; after ~4 seconds of failed zero-length interrupt transfers (`EPROTO`), the Linux HID layer triggers a USB bus reset right in the middle of bootloader reads or flashing.

**Solution (implemented in `src/boot_roundtrip/boot_usb/`):**
1. Detach `usbhid` from `09DA:D023` interface `0` via `libusb`/`rusb` and claim interface `0` directly.
2. Perform all 64-byte Report-07 exchanges using USB control transfers (`bmRequestType = 0x21`/`0xA1`, `bRequest = SET_REPORT (0x09)` / `GET_REPORT (0x01)`, `wValue = 0x0307`, `wIndex = 0`) with **zero interrupt-IN polling**.
3. Release interface `0` cleanly on close so the OS can re-enumerate normally after reset.

## Feature Report `0x07` Command Reference

Every command is a 64-byte buffer starting with `byte[0] = 0x07` and `byte[1] = opcode`. Unused bytes are zero unless explicitly seeded.

| Opcode (`byte[1]`) | Subcmd | Mode | Direction | Purpose |
| --- | --- | --- | --- | --- |
| `0x1F` | — | Normal | Set + Get | Query identity: `u16@10` = `model_id \| core_index`, `u16@12` = firmware version word (`0x0028` / `0x0034`) |
| `0x2D` | — | Normal & Boot | Set + Get | Query device state (`u32@8`; high byte `<= 1` in normal mode) and display version (`u16@12`) |
| `0x05` | — | Normal | Set + Get | Query runtime profile layout addresses (`E000` sensitivity, `E200` main profile, `FE9C` additional vector) |
| `0x2F` | `byte[2]=0x00` | Normal | Set + Get | Read 8-byte profile header (restricted by firmware low-byte guard to page headers only) |
| `0x2F` | `byte[2]=0x01` | Normal | Set (+ Get) | Program 32-byte chunk into internal configuration flash (`0xE000..0xFE9C` / `0xFF40..0xFF7F`) |
| `0x25` | — | Normal & Boot | Set | Set/clear the temporary RAM read-gate key (`0x22184952` unlocks `0x02` memory reads; `0x00000000` closes the gate) |
| `0x02` | — | Normal & Boot | Set + Get | Direct 32-byte memory read (gated by `0x25`): `u32@4` = address, `byte[24]` = `8` (8 DWORDs = 32 bytes); data returned in `bytes[32..64]` |
| `0x28` | `byte[2]=0x01` | Normal & Boot | Set | Program the `0xFEFC` startup marker (`0x00000000` to request bootloader entry; `0xA4A4A4A4` to return to normal app) |
| `0x28` | `byte[2]=0x02` | Normal & Boot | Set | Trigger MCU software reset (device disconnects and re-enumerates on the same USB port) |
| `0x0D` | — | Normal | Set + Get | Apply / query runtime CPI slot and parameters without reset |
| `0x0E` | — | Normal | Set + Get | Query / set runtime shooting slot (`0` Normal, `1` Double, `2` Triple) on Core 2 / Core 3; preserve all other fields |
| `0x11` | `byte[4]=0x00/0x80` | Normal | Set + Get | Read (`0x00`) or persist (`0x80`) RGB brightness level (`byte[8]` in `0..=3` → PWM `0x00/0x3F/0x7F/0xFF`) |
| `0x03` | `06 00/01/02/05` | Normal | Set (+ Get) | Live RAM SLED RGB control: `00` enable/disable preview, `01` breathing speed (`0..4`), `02` 15-LED RGB frame (`bytes[8..53]`), `05` status read |
| `0x29` | — | Boot | Set + Get | Read 8-byte factory unit key `U/V` (mirrors `0xFFD0..0xFFD7`) |
| `0x2B` | `byte[2]=0x00/0x01` | Boot | Set + Get | Read (`0x00`) or write (`0x01`) the 28-byte finalization block (`0xFEE0..0xFEFB`) |
| `0x01` | `byte[2]=0x01` | Boot | Set + Get | Program one 36-byte encoded firmware record (`bytes[28..64]`); reply echoes header + 32-byte decoded plaintext in `bytes[32..64]` |

### Anti-Echo Seeded Memory Reads (`0x02`)

When the RAM read gate (`0x25`) is closed or a read fails silently, the firmware simply echoes back the host's 64-byte request buffer unchanged!

To guarantee a selector echo can never be mistaken for real memory data:
1. For **unknown memory** (backups, initial reads): read every 32-byte block twice with complementary seeds (`0xA5` and `0x5A` in request `bytes[32..64]`) and require exact equality between passes.
2. For **verification against known expected bytes**: fill request `bytes[32..64]` with the bitwise complement `!expected[i]` of every expected byte. Even a single echoed byte is guaranteed to fail comparison!
3. Always close the RAM read gate (`0x25` with key `0`) and verify closure with a probe read before finishing.

## Firmware `.hexEncode` Record Format & Cipher

Stock W95 Max `v0034` firmware files (`W95Max_P3332A_578_{idx}_34.hexEncode`) are `60,912` bytes = `1,692` fixed 36-byte records covering two internal-flash address ranges:
- `[0x0000, 0x5460)` (675 records)
- `[0x7FE0, 0xFF00)` (1,017 records)

Each 36-byte record consists of 9 little-endian `u32` words (`header`, `cipher[0..8]`):

```text
Decoding (36-byte record -> address + 32-byte plaintext):
  address  = cipher[0] - header + 0xA4A4_55AA                  (mod 2^32)
  for i in 0..8:
    mask     = (i == 7) ? 0x8913_9813 : 0
    plain[i] = ((cipher[i] ^ mask) + 0xA4A4_55AA) ^ 0x2218_4952

Encoding (address + 32-byte plaintext -> 36-byte record):
  for i in 0..8:
    mask      = (i == 7) ? 0x8913_9813 : 0
    cipher[i] = ((plain[i] ^ 0x2218_4952) - 0xA4A4_55AA) ^ mask
  header = cipher[0] + 0xA4A4_55AA - address                   (mod 2^32)
```

When sent to the bootloader over `0x01`, the 36-byte record is placed at `frame[28..64]` after the 28-byte header:
`[0x07, 0x01, 0x01, 0, ..., 0, 0x08, 0, 0, 0]` (`frame[24] = 8` DWORDs).

## Boot Entry, Safe Flashing, and Recovery Sequence

1. **Pre-entry validation (Normal mode):**
   - Verify exact USB binding, model/Core/version (`0x1F` / `0x2D`), active boot bank (`0x1FFF0000..0x1FFF0BFF`), and protected unit bytes (`0xFF00..0xFF3F`, `0xFF80..0xFFFF`).
2. **Enter Bootloader (`09DA:D023`):**
   - Clear startup marker `0xFEFC` to `0x00000000` (`07 28 01`), verify page neighbors `0xFEC0..0xFEFF` are intact, then reset (`07 28 02`).
   - Re-bind strictly on the **same USB port** to `09DA:D023` via raw USB control transfer (`rusb`).
3. **Stream firmware records (`0x01`) with pre-commit prefix verification:**
   - Send records `0..N-2`, keeping the final `0xFEE0` record (which writes `0xFEFC = 0xA4A4A4A4`) **withheld**.
   - Read back the **entire** programmed flash prefix using inverted-byte seeds and verify exact equality against expected memory.
   - Only after the full prefix is verified and durably persisted, transmit the final `0xFEE0` marker-bearing record!
4. **Finalization (`0x29` / `0x2B`) & Return to Normal:**
   - Verify unit key `U/V` (`0x29`), write the unit-matched finalization block (`0x2B`, preserving `09DA:712F`), verify `0xFEC0..0xFEFF`, close the read gate, and reset (`07 28 02`).
   - Re-bind in normal mode (`09DA:712F`) and verify the expected Core descriptor hash.
5. **Failure & Recovery Policy:**
   - Never resume a partial flash stream mid-way.
   - If a failure occurs **before** any `0x01` firmware record was sent, restore `0xFEFC = 0xA4A4A4A4` and reboot back to the intact application.
   - If a failure occurs **after** any `0x01` record was sent, reflash the entire 64 KiB original factory backup from address `0x0000` (2,042 records: `0x0000..0xFEDC`, `0xFF40`, `0xFF60`, and `0xFEE0` last) while leaving protected `0xFF00..0xFF3F` and `0xFF80..0xFFFF` untouched.
