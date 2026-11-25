# Hardware Architecture & Memory Map (Bloody W95 Max)

## Device Overview

| Property | Value |
| --- | --- |
| Target model | Bloody W95 Max (ordinary edition) |
| Internal model ID | `0x0578` (`1400` decimal) |
| MCU family | ARM Cortex-M0 (`USB_M0` firmware family), little-endian |
| Internal application flash | 64 KiB (`0x0000..=0xFFFF`), 64-byte logical pages / 32-byte transfer blocks |
| Active bootloader bank | 3 KiB (`0x1FFF0000..=0x1FFF0BFF`), mirrored in application flash at `0x3C60..=0x485F` |
| External SPI NOR flash | Mapped logically at `0x40000+` (`bit 31 = 1` in 32-bit profile pointers); **never written by Ratmax** |
| Optical sensor class | PixArt 3327 / 3332A-class (`SENSOR_3327` 63-entry base curve + high-DPI encoding up to `12000` DPI) |
| RGB LEDs | 15 addressable RGB zones (`15 × 3 = 45` color bytes padded to 54 bytes in framebuffers) |

## Internal Flash Memory Map (`0x0000..=0xFFFF`)

```text
0x0000 .. 0x3C5F   Application vector table & firmware code
0x3C60 .. 0x485F   Embedded copy of the 3 KiB bootloader bank (rev 2 in v0028; rev 3 in v0034)
0x4860 .. 0x545F   Application firmware code (end of first encoded firmware range)
0x5460 .. 0x7FDF   Unencoded / gap region (preserved across stock firmware updates)
0x7FE0 .. 0xDFFF   Application firmware code, tables, and built-in stock profile/macro ROM
0xE000 .. 0xE0FF   Sensitivity / CPI / Polling-rate block (256 bytes, header 0xA4A4A4A4)
0xE100 .. 0xE1FF   Unused / reserved page pair
0xE200 .. 0xE6D7   Stock materialized main profile (1,240 bytes: header, button triggers, lighting pointers, built-in click programs)
0xE6D8 .. 0xE6FF   Stock profile tail (40 zero bytes in canonical stock images; compact custom storage)
0xE700 .. 0xFE7F   Extended zero-filled internal profile area (92 × 64-byte pages = 5,888 bytes)
                   Used by Ratmax for multi-button macros (A9xx), extended GunA (A78x), and permanent RGB (A801)
0xFE80 .. 0xFEBF   Reserved page containing the 0xFE9C additional-vector marker (NEVER overwritten by Ratmax)
0xFEC0 .. 0xFEDF   Device status & model/Core identity header (32 bytes; packed model|core at 0xFEC6)
0xFEE0 .. 0xFEFB   Finalization block (28 bytes; USB VID/PID at 0xFEE0, packed model|core at 0xFEE8)
0xFEFC .. 0xFEFF   Startup marker (0xA4A4A4A4 = boot into application; 0x00000000 = enter bootloader)
0xFF00 .. 0xFF3F   PROTECTED unit metadata (never programmed during normal/restore flashing; model|core at 0xFF06)
0xFF40 .. 0xFF7F   Saved-state / runtime commit pages (64 bytes; 0xFF45 advances as a runtime table selector)
0xFF80 .. 0xFFFF   PROTECTED factory calibration / unit identity (never programmed; 8-byte U/V unit key at 0xFFD0..0xFFD7)
```

### Active Bootloader Bank (`0x1FFF0000..=0x1FFF0BFF`)

- The active bootloader executes from `0x1FFF0000` (3,072 bytes = 96 × 32-byte blocks).
- The running application contains a matching copy of its expected loader at `0x3C60..=0x485F`.
- At application startup, if the active loader bank's revision word at `0x1FFF0BFC` differs from the embedded copy's revision word (e.g., `0xA4A40002` in factory `v0028` vs. `0xA4A40003` in `v0034`), the application firmware rewrites the active bank in-place before enumerating USB.
- **Safety consequence:** Never interrupt power during the first boot immediately following a firmware revision change (`v0028` ↔ `v0034`).

### External SPI NOR Boundary (`0x40000+`)

- The vendor Windows software allocates large macros and custom lighting animations into external SPI NOR (erased in 4 KiB sectors, programmed in 32-byte chunks) and references them from the main profile via 32-bit pointers with **bit 31 set**.
- Because the 64 KiB internal-flash backup does **not** back up external SPI NOR, **Ratmax never issues SPI NOR erase/write commands**.
- Instead, Ratmax stores custom button macros and permanent 15-LED RGB lighting inside the **internal flash extension region (`0xE6D8..0xFE7F`)**, which is 100% covered by the 64 KiB internal-flash backup and safely addressable by the firmware's internal-flash readers (`Cxxx` 14-bit word offsets for macros; `bit 31 == 0` pointers for lighting).

## Core 1–4 Architecture

The W95 Max uses four distinct stock firmware images (`v0034`), each setting a runtime Core index. Note the non-obvious firmware index encoding: **Core 4 uses index `0`**, not `4`.

| User Core | `firmware_index` | Stock filename pattern | Packed `model \| index` (`0x0578 \| idx`) | Capabilities |
| --- | :---: | --- | :---: | --- |
| **Core 1** | `1` | `W95Max_P3332A_578_1_34.hexEncode` | `0x0579` | DPI/Polling, button remaps, Precision/Direct Double/Triple, Permanent RGB |
| **Core 2** | `2` | `W95Max_P3332A_578_2_34.hexEncode` | `0x057A` | Core 1 + Left-click Shooting Mode (`Normal`/`Double`/`Triple`) & shooting-selector buttons |
| **Core 3** | `3` | `W95Max_P3332A_578_3_34.hexEncode` | `0x057B` | Core 2 + Custom Button Macros (`A8xx`/`A9xx`) + Custom Left-click GunA (`A7xx`) |
| **Core 4** | `0` | `W95Max_P3332A_578_0_34.hexEncode` | `0x0578` | Full-Key Custom Button Macros (`A8xx`/`A9xx`), DPI/Polling, buttons, Permanent RGB (**no Shooting Mode, shooting selectors, or GunA**) |

The factory-installed `v0028` image is an older Core 1 (`0x0579`) build that supports symmetric/asymmetric DPI, polling rate, basic button remaps, and live RGB preview, but lacks prepared-profile extras (`Precision`, `Double`/`Triple` stock click programs) and permanent internal-flash RGB.

## Profile & Settings Checksum Algorithm

Both the 256-byte sensitivity block (`0xE000..0xE0FF`) and the main profile (`0xE200..`) use a little-endian 16-bit word header:

| Byte offset | Word index | Field |
| --- | ---: | --- |
| `+0x00..+0x03` | `0..=1` | Validity commit marker: `0xA4A4`, `0xA4A4` (invalidated to `0xFFFF`/`0x0000` while staging) |
| `+0x04..+0x05` | `2` | `sum`: 16-bit wrapping sum of all covered data words |
| `+0x06..+0x07` | `3` | `weighted`: 16-bit wrapping sum of `(word_index * word_value)` |

For a contiguous slice of 16-bit little-endian words `w[0..N]`:

```text
sum      = Σ_{i = 4}^{N - 1} w[i]              (mod 65536)
weighted = Σ_{i = 4}^{N - 1} (i * w[i])        (mod 65536)
```

### Exact Delta-Update Property

Because both checksums are linear mod 65,536, changing a single 16-bit word at index `i >= 4` from `old` to `new` updates the header deterministically **even when unknown trailing/NOR contributions exist**:

```text
delta     = new.wrapping_sub(old)
sum'      = sum.wrapping_add(delta)
weighted' = weighted.wrapping_add(i.wrapping_mul(delta))
```

Ratmax uses exact delta updates whenever modifying button assignments or internal-flash lighting pointers so unrelated bytes remain untouched and verifiable.
