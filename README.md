# ratmax

Open-source Linux **TUI & CLI** configuration, macro, RGB lighting, and firmware tool for the **Bloody W95 Max** (`model 0x0578`).

Built in safe Rust (`unsafe_code = "forbid"`) with **zero external-NOR writes** — custom macros and permanent RGB lighting are stored cleanly inside internal flash alongside reversible settings and full factory backup/restore support.

## Features

- **3-Tab Terminal UI (`ratmax tui`)** with consistent controls across every page:
  - **1 Mouse**: Symmetric & asymmetric X×Y CPI (`22..=12,000` DPI), polling rate (`125..=2000` Hz), Core 1–4 switching (automatic flashing on Core change), Core-aware feature gating, button remapping (`Back`, `Forward`, `Extra Click`, `Precision`, `Aux Click/Front/Rear`), backup export, and factory restore.
  - **2 Macros** *(Core 3 & Core 4)*: Live keyboard key/chord recording (`k`, capturing `Ctrl+C`, `Alt+Tab`, `F1..F12`, etc.), mouse click picker (`m`), delays (`d`), shorthand custom steps (`t`), separate **On Press** / **On Release** sequences, and simultaneous multi-button macros (up to all 7 configurable buttons, zero NOR writes).
  - **3 Lighting**: Persistent brightness (`0% / 25% / 50% / 100%`), live RAM RGB preview (`Stock`, `Solid`, `Gradient`, `Rainbow`, 15-zone `Per-LED`, breathing speeds `0..4`), and **permanent internal-flash RGB save** that survives unplug/reboot and activates immediately without reset.
- **Core-Aware Feature Gating**: Automatically disables options unsupported by the active Core (e.g., Core 4 Full-Key Macros disables Shooting Mode / GunA; Cores 1 & 2 disable the Macros tab; Original Core 1 disables permanent internal-flash RGB while keeping Live Preview active).
- **Safe Bootloader Transport**: Uses raw USB control transfers (`rusb`) in bootloader mode (`09DA:D023`) to avoid Linux `hidraw` interrupt-IN bus resets, with full-prefix verification before committing the startup marker.

## Quick Start

### 1. Install with Cargo

On Linux, install the system libraries required by `hidapi` and `rusb` (`libudev` and `libusb-1.0`, plus `pkg-config`):

- **Arch Linux:** `sudo pacman -S pkgconf libusb systemd-libs`
- **Debian / Ubuntu:** `sudo apt install pkg-config libudev-dev libusb-1.0-0-dev`
- **Fedora:** `sudo dnf install pkgconf-pkg-config systemd-devel libusb1-devel`

Then install `ratmax` into `~/.cargo/bin` directly via Cargo:

```sh
cargo install --path . --locked
```

(Or build without installing via `cargo build --release --locked`; uninstall later with `cargo uninstall ratmax`.)

### 2. Non-root Linux access (`udev` rules)

To run `ratmax` without `sudo` (also printed by `ratmax --help`):

```sh
sudo tee /etc/udev/rules.d/99-bloody-w95max.rules <<'EOF'
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="09da", ATTRS{idProduct}=="712f", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="09da", ATTR{idProduct}=="d023", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="09da", ATTRS{idProduct}=="d023", MODE="0660", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 3. Extract Stock Firmware Assets (using `7z`) & Configure Workspace

Ratmax does **not** redistribute proprietary Bloody firmware binaries or device backups. Download the free official **Bloody WorkShop 8** installer (`BloodyWorkShop8_*.exe`) from Bloody's website and extract only the four W95 Max firmware files (~240 KiB total — no Windows required) with `7z` (also printed by `ratmax --help`):

```sh
7z x BloodyWorkShop8_*.exe \
  -o~/.local/share/ratmax/vendor \
  'program files/BloodyWorkShop8/FW/USB_M0/W95Max_P3332A_578_*_34.hexEncode'
```

Verify the extracted files match the expected SHA-256 digests:

```sh
ratmax inspect --assets "$HOME/.local/share/ratmax/vendor/program files/BloodyWorkShop8"
```

Then point `"assets"` (along with your mouse's verified `baseline`, `backup`, and `sessions` directories) in `~/.config/ratmax/workspace.json` (see [examples/workspace.example.json](examples/workspace.example.json)), or set `RATMAX_WORKSPACE`, and launch:

```sh
ratmax tui
```

See [USAGE.md](USAGE.md) for full TUI keybindings, Core feature matrix, and CLI lighting shortcuts.

## Documentation & Extending to Other Models

Want to understand how the W95 Max works or extend Ratmax to another Bloody / A4Tech mouse (manually or with an AI coding agent)? Start with the clean-room technical documentation in [docs/](docs/README.md):

- [docs/HARDWARE-ARCHITECTURE.md](docs/HARDWARE-ARCHITECTURE.md) — 64 KiB internal flash map, bootloader bank, SPI NOR boundary, Core 1–4 differences, and checksum math
- [docs/USB-PROTOCOL-AND-BOOT.md](docs/USB-PROTOCOL-AND-BOOT.md) — USB/HID interfaces, Feature Report `0x07` commands, Linux boot-mode transport, `.hexEncode` cipher, and safe flashing
- [docs/DATA-FORMATS.md](docs/DATA-FORMATS.md) — CPI/asymmetric CPI encoding, button triggers, macro VM opcodes, and zero-NOR internal-flash storage layouts
- [docs/PORTING-GUIDE.md](docs/PORTING-GUIDE.md) — Staged discovery workflow, Rust module checklist, and safety invariants for contributors & AI agents

## License

Licensed under the [Zero-Clause BSD (0BSD)](LICENSE) license.

## Disclaimer

This is an independent open-source project unaffiliated with A4Tech / Bloody. No proprietary firmware, vendor executables, disassembly, or device dumps are distributed in this repository. Flashing and modifying mouse firmware is done at your own risk — always keep an offline copy of your mouse's verified factory backup.
