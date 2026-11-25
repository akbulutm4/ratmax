# Data Formats, Encodings & Zero-NOR Storage Layouts

## 1. Sensitivity Block (`0xE000..=0xE0FF`, 256 bytes)

Header (`0xE000..0xE007`): `A4 A4 A4 A4 <sum_lo> <sum_hi> <weighted_lo> <weighted_hi>`.

- **5 CPI Slots** (indices `0..=4`), supporting **22..=12,000 DPI** and **independent X/Y asymmetric DPI**.
- **Base Sensor Table (`SENSOR_3327`, 0..=6200 DPI in 100-DPI steps):**
  - 63 hardware register entries mapping target DPI to sensor register values (`src/settings.rs`: `SENSOR_3327_TABLE`).
  - Each CPI slot encodes 3 bytes (`[x_scale, y_scale, base_word]`):
    - Equal-axis CPI `<= 6200`: `x_scale = 0x40`, `y_scale = 0x40`, `base_word` from the table (`~44` DPI per step in lower range).
    - High CPI (`> 6200`, up to `12000`) and asymmetric `X × Y` CPI: scales the per-axis multiplier bytes alongside the base register word (exact encoder/decoder in `src/settings.rs`: `encode_cpi`, `encode_cpi_xy`, `decode_cpi_xy`).
- **Polling Rate** (stored at word offset `0x3C`):

| Rate (Hz) | Encoded Value |
| ---: | :---: |
| `125` | `0x08` |
| `250` | `0x04` |
| `500` | `0x02` |
| `1000` | `0x01` |
| `2000` | `0x11` |

### Staging & Commit Rule for Configuration Writes (`07 2F 01`)

Before modifying any 32-byte block in `0xE000..` or `0xE200..`:
1. Invalidate the 4-byte commit marker (`0xA4A4A4A4` → `0xFFFF`/`0x0000`).
2. Program all changed 32-byte blocks (`0xE008..` or `0xE208..`), verify staged bytes with inverted-seed reads.
3. Program the first 32-byte block (`0xE000` or `0xE200`) last to atomically restore `0xA4A4A4A4` + updated checksums.
4. Apply runtime settings via `07 0D` (CPI/rate) or `07 0E` (shooting slot) so changes take effect immediately without a USB reset.

## 2. Main Profile (`0xE200..=0xE6D7`) & Button Triggers

Each configurable physical control has a pair of 16-bit action words (`[press_word, release_word]`) stored in the main profile trigger table (`0xE2A0 + 4 * trigger_ordinal`):

| Physical Control | Trigger Ordinal | Main Profile Address | Notes |
| --- | ---: | :---: | --- |
| Back (side) | `3` | `0xE2B8` | Configurable & macro-capable |
| Forward (side) | `4` | `0xE2BC` | Configurable & macro-capable |
| Extra click button | `7` | `0xE2C8` | Dedicated top button |
| Aux wheel click (`Aux 1`) | `9` | `0xE2D0` | May overlap mechanically with rearward rotation |
| Aux wheel toward front (`Aux N`) | `10` | `0xE2D4` | — |
| Aux wheel toward rear (`Aux 3`) | `11` | `0xE2D8` | — |
| Precision button | `14` | `0xE2E4` | Dedicated thumb/sniper button |

Primary Left (`0`), Right (`1`), Middle (`2`), and main scroll wheel entries are intentionally left untouched by Ratmax so basic mouse operation is always preserved.

### Built-In Button Action Word Pairs `[press, release]`

| Action | `[press, release]` | Supported Cores |
| --- | :---: | --- |
| Left click | `[0x2501, 0x2401]` | All |
| Right click | `[0x2502, 0x2402]` | All |
| Middle click | `[0x2504, 0x2404]` | All |
| Back | `[0x2508, 0x2408]` | All |
| Forward | `[0x2510, 0x2410]` | All |
| Disabled (No-op) | `[0x262E, 0x262E]` | All |
| Next CPI preset | `[0x2626, 0x262E]` | All |
| Previous CPI preset | `[0x2624, 0x262E]` | All |
| Precision hold | `[0x2628, 0x2629]` | Prepared Core 1–4 (`v0034`) |
| Direct Double click | `[0xC1F0, 0x262E]` | Prepared Core 1–4 (`v0034`) |
| Direct Triple click | `[0xC1EC, 0x262E]` | Prepared Core 1–4 (`v0034`) |
| Select Normal shooting mode | `[0x2610, 0x262E]` | Core 2 & Core 3 only |
| Select Double shooting mode | `[0x2611, 0x262E]` | Core 2 & Core 3 only |
| Select Triple shooting mode | `[0x2612, 0x262E]` | Core 2 & Core 3 only |

## 3. Macro VM 16-Bit Instruction Set

A button trigger word of the form `0xC000 | word_offset` jumps into an instruction stream at internal flash address `0xE200 + 2 * word_offset` (14-bit word offset, reaching all the way through `0xFE7F`!). The firmware VM fetches 3 words at a time, so every stream is followed by a 4-byte (`2`-word) zero guard.

| Word Range / Encoding | Meaning |
| --- | --- |
| `0x2100 + usage` | USB HID Keyboard key **down** (`usage` in `0x04..=0x97`) |
| `0x2000 + usage` | USB HID Keyboard key **up** (`usage` in `0x04..=0x97`) |
| `0x2300 + bitmask` | USB HID Modifier key **down** (`bit 0..7` = `LCtrl, LShift, LAlt, LGui, RCtrl, RShift, RAlt, RGui`, `0xE0..=0xE7`) |
| `0x2200 + bitmask` | USB HID Modifier key **up** |
| `0x2500 + mask` | Mouse button **down** (`1`=Left, `2`=Right, `4`=Middle, `8`=Back, `16`=Forward) |
| `0x2400 + mask` | Mouse button **up** |
| `0x2801..=0x2BE7` | Delay `ms` milliseconds (`0x2800 + ms`, `1..=999` ms; longer delays split into multiple words) |
| `0x4000..=0x7FFF` | Relative pointer move: `0x4000 \| ((dx & 0x7F) << 7) \| (dy & 0x7F)` where `dx, dy` are signed 7-bit (`-64..=+63`) |
| `0x262E` | No-op (empty press or release trigger) |
| `0x262F` | End of macro stream (`macroending`) |

## 4. Ratmax Zero-NOR Internal Flash Storage (`0xE6D8..=0xFE7F`)

Canonical stock `v0034` profiles end at `0xE6D7` and have zero bytes from `0xE6D8` through `0xFE7F` (6,056 bytes = 40-byte tail + 92 × 64-byte pages). Ratmax packs self-describing blocks in this region so every custom item can be cleanly decoded, verified, updated, and restored byte-for-byte back to stock without touching SPI NOR:

### A. Compact Single-Button Macro (`0xE6D8..0xE6FF`, tag `0xA8xx`)
Used automatically for a single button macro `<= 14` total words (`<= 40` bytes, 0 extra pages):
- `+0x00`: `0xA800 | button_index`
- `+0x02..+0x05`: saved original `[prior_press, prior_release]` words (for exact restore on removal)
- `+0x06`: `(release_words << 8) | press_words`
- `+0x08..`: press words, release words, 4-byte zero guard.

### B. Extended / Multi-Button Macros (`0xE6D8..0xFE7F`, tag `0xA9xx`)
Used automatically for large single-button macros (up to `3,019` words) or up to all **7 configurable buttons simultaneously**:
- `+0x00`: `0xA900 | binding_count` (`1..=7`)
- `+0x02`: `extended_pages` (`0..=92`, number of 64-byte pages used above `0xE700`)
- Table of `binding_count` 10-byte entries (`button_id`, `prior_press`, `prior_release`, `press_words`, `release_words`), followed by concatenated instruction streams and a 4-byte zero guard.

### C. Core-3 Custom GunA Shooting Program (`0xE6D8..`, tag `0xA701..0xA702` / `0xA783..0xA785`)
- Restricted strictly to **Core 3** (shooting slot 1 pointer at `0xE222`), mutually exclusive with `A8xx`/`A9xx`.
- Stores bullet count, per-bullet `(interval_ms, move_x, move_y)`, and compiled words (`GunA` negates `Y` relative to screen down).

### D. Permanent Internal-Flash RGB Lighting (tag `0xA801`, 128 bytes = 2 pages)
How the firmware plays persistent lighting without external NOR:
1. Main profile header word `13` (`0xE21A`, masked with `0x3FFF`) locates the 5-slot lighting mode pointer table (`0x01D8` → `0xE5B0` in canonical `v0034` profiles).
2. Each of the 5 slots holds a 32-bit pointer `(lo: u16, hi: u16)`.
3. When reading animation words, the firmware inspects **bit 31**:
   - `bit 31 == 1` → read from external SPI NOR.
   - `bit 31 == 0` → mask `lo` (`uxth`) and read directly from **internal flash at `0xE200 + 2 * lo`**!
4. Ratmax packs a 128-byte (2-page) block immediately after any occupied macro/GunA pages at `block_addr = 0xE700 + 64 * preceding_ext_pages`:
   - `+0x00`: magic `0xA801`, `breathing` (`0..=4`), `flags = 0`
   - `+0x04..+0x17`: saved original 20-byte `0xE5B0..0xE5C3` pointer table (for exact byte-for-byte removal)
   - `+0x18..+0x5B`: 34-word (68-byte) animation stream:
     `[1, breathing]`, `[3, 50]` (frame ticks), 27 words (`45` RGB bytes for 15 LEDs + `9` zero pad bytes), `[4, 0]` (replay), `[0xA4A4]` (end)
   - `+0x5C..+0x7F`: zero padding
5. All 5 mode slots at `0xE5B0..0xE5C3` are delta-updated to `(stream_word, 0x0000)` (`bit 31 == 0`).
6. Sending `07 03 06 00 [8]=0` (`preview_enable_frame(false)`) immediately reloads the internal-flash lighting engine with **no replug or reset**.
