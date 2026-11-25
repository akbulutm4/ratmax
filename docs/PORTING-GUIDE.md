# Porting Guide (For Developers & AI Coding Agents)

Ratmax targets the **Bloody W95 Max (`0x0578`)**, but many Bloody / A4Tech ARM Cortex-M0 (`USB_M0`) mice share the same overarching protocol family, `.hexEncode` cipher, 64-byte Report-07 framing, and profile structure.

This guide gives human contributors and AI agents a **safe, staged clean-room methodology** to extend Ratmax (or a fork) to another model without bricking a mouse.

---

## Hard Safety Invariants (Do Not Violate)

1. **Zero writes before a verified full backup:** Never send a profile write (`07 2F 01`), marker clear (`07 28`), or firmware record (`07 01`) until you have captured two matching, seeded, full-flash backups of the target mouse and stored them outside your working tree.
2. **Never write external SPI NOR (`0x40000+`) without a full NOR backup:** Internal flash backups do not cover external NOR. Prefer internal-flash tail placement (`0xE6D8..` or the target model's equivalent verified zero tail) and verify exact byte-for-byte restoration.
3. **Never use Linux `hidraw` in bootloader mode:** Always use raw USB control transfers (`rusb`) on the bootloader interface to avoid kernel interrupt-IN polling bus resets.
4. **Always seed memory reads (`0x02`):** Use complementary seeds (`0xA5`/`0x5A`) for unknown reads and inverted expected bytes (`!expected`) for verification so silent selector echoes are always caught.
5. **Always verify the full programmed prefix before committing the startup marker (`0xFEFC`):** Withhold the final marker-bearing record until every preceding programmed byte reads back identically.
6. **Keep `unsafe_code = "forbid"` in `Cargo.toml`:** All HID/USB/sysfs I/O goes through safe Rust wrappers (`hidapi`, `rusb`, `std::fs`).

---

## Staged Discovery & Porting Workflow

### Phase 0 — Passive Sysfs Discovery (Zero Device I/O)
- Run `ratmax discover-passive --json` with the new mouse connected.
- Record:
  - USB `idVendor` (typically `0x09DA`), `idProduct`, `bcdDevice`, and composite interface layout.
  - Which interface exposes Vendor Usage Page `0xFF33` (or similar) with a 64-byte Feature Report ID `0x07`.
  - Exact HID report descriptor SHA-256 and byte length.

### Phase 1 — Read-Only Identity & Layout Queries
- Send only read-only Feature Report `0x07` queries (`0x1F` identity, `0x2D` status, `0x05` layout).
- Confirm:
  - Packed `model_id | core_index` (`u16@10` of `0x1F`).
  - Whether `core_index == 0` maps to Core 4 (as on W95 Max) and whether `model_id` matches the filename prefix in the vendor's `FW/USB_M0/` directory.
  - Runtime base addresses returned by `0x05` (sensitivity base, main profile base, additional-vector address).

### Phase 2 — Offline Firmware Verification (User's Local Copy)
- Obtain the stock `.hexEncode` images for the target model from your own installation of the vendor software (do **not** commit vendor files to git!).
- Test whether the 36-byte record transform in `src/firmware.rs` decodes cleanly into valid ARM Cortex-M0 vectors (`initial SP` in `0x2000xxxx`, Thumb reset vector with bit 0 set).
- Verify:
  - Occupied encoded address ranges (e.g., `[0x0000, 0x5460)` and `[0x7FE0, 0xFF00)` on W95 Max — check whether the gap or end address differs on the new model).
  - Embedded bootloader copy offset & size (`0x3C60..0x485F` on W95 Max) and bootloader USB VID:PID (`09DA:D023` or model-specific).
  - Sensor CPI lookup table and polling-rate encoding in the sensitivity block.
  - Profile lighting table offset (`word13 & 0x3FFF`) and whether `bit 31 == 0` reads internal flash.
  - Button trigger table ordinals for the target mouse's physical buttons.

### Phase 3 — Read-Only Full Backup & Boot Round-Trip
- Verify the RAM read gate (`07 25` unlock/close) and capture two seeded 64 KiB passes in normal mode (`07 02`).
- Verify the active bootloader bank at `0x1FFF0000` matches the embedded copy in your backup.
- Test a **zero-record** boot round-trip (`0xFEFC` → `0`, reset into bootloader, verify USB descriptors & `0x29` U/V, restore `0xFEFC` → `0xA4A4A4A4`, reset back to normal) before attempting any firmware record write.

### Phase 4 — Reversible Settings, Buttons, Macros & Lighting
- Test one reversible CPI edit and verify exact 320-byte restoration (`0xE000..0xE0FF` + `0xFF40..0xFF7F`).
- Map physical extra buttons by assigning distinct finite click counts (e.g. Double/Triple click) and observing input events, then restoring stock defaults.
- Verify live RGB (`07 11` + `07 03 06`) and LED count (some models have fewer or more than 15 LEDs).
- Verify internal-flash macro (`A8xx`/`A9xx`) and permanent lighting (`A801`) tail bounds stay strictly below the additional-vector marker page (`0xFE80` on W95 Max).

---

## Codebase Extension Map

Where each model-specific detail lives in Ratmax:

| Subsystem | Rust Module(s) | What to generalize for a new model |
| --- | --- | --- |
| Model ID & Core index mapping | `src/model.rs` | Add variant to `Model`, `TryFrom<u16>`, and Core-to-index mapping |
| Stock firmware hash allowlist & ranges | `src/assets.rs`, `src/firmware.rs` | Per-model manifest digest table, `RECORD_COUNT`, and encoded address ranges |
| USB/HID identity & descriptor pins | `src/boot_bank.rs`, `src/boot_roundtrip/connection.rs`, `src/boot_roundtrip/boot_usb.rs` | Normal VID:PID, per-Core descriptor SHA-256s, bootloader VID:PID & bank SHA-256s |
| Sensitivity, CPI & polling rate | `src/settings.rs` | Sensor CPI lookup table, max DPI, asymmetric scaling, report-rate bytes |
| Button triggers & Core feature gating | `src/workflow.rs`, `src/button_plan.rs` | `ExtraControl` trigger ordinals, `Button::supported(mode)`, Core capability predicates |
| Button macros & internal storage | `src/macros.rs`, `src/macros/storage.rs` | `Target` list, profile base `0xE200`, tail start `0xE6D8`, and `EXT_END` cap |
| RGB lighting (live & permanent) | `src/lighting.rs` | `LED_COUNT`, `07 11` / `07 03 06` opcodes, lighting table header word index |
| TUI presentation | `src/tui.rs`, `src/tui/device.rs`, `src/tui/macros.rs`, `src/tui/lighting.rs` | Button labels, Core capability descriptions, LED preview count |

---

## Testing Strategy for Contributions

- Keep **all** unit and integration tests (`cargo test`) 100% offline with synthetic in-memory images — never commit real mouse flash dumps or vendor `.hexEncode` files to the repository.
- Run both feature configurations before opening a PR:
  ```sh
  cargo clippy --all-targets -- -D warnings
  cargo clippy --no-default-features --all-targets -- -D warnings
  cargo test
  ```
