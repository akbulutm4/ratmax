# Ratmax Technical Documentation

Clean-room protocol, memory-map, bootloader, and porting reference for the **Bloody W95 Max** (`model_id = 0x0578`, ARM Cortex-M0 `USB_M0`), designed as an extensible starting point for developers and AI coding agents supporting other Bloody / A4Tech mice.

> **Clean-room notice:** This documentation describes wire protocols, memory layouts, data encodings, and safety invariants strictly at the specification level. It intentionally omits vendor binaries, decompiled source code, disassembly dumps, and unit-specific flash backups.

## Documents

| Document | Contents |
| --- | --- |
| [HARDWARE-ARCHITECTURE.md](HARDWARE-ARCHITECTURE.md) | 64 KiB internal flash map, active bootloader bank, external SPI NOR boundary, Core 1–4 differences, and profile checksum math |
| [USB-PROTOCOL-AND-BOOT.md](USB-PROTOCOL-AND-BOOT.md) | USB/HID interfaces (`09DA:712F` / `09DA:D023`), Linux boot-mode USB control transport gotcha, Feature Report `0x07` command reference, `.hexEncode` record cipher, and safe flashing/recovery |
| [DATA-FORMATS.md](DATA-FORMATS.md) | Symmetric/asymmetric CPI (`22..=12000`), polling rates, button trigger table, 16-bit macro VM opcodes, and zero-NOR internal-flash layouts for macros & permanent RGB |
| [PORTING-GUIDE.md](PORTING-GUIDE.md) | Staged workflow, module checklist, and hard safety invariants for humans and AI agents extending Ratmax to new mouse models |
