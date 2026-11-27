# Using Ratmax on the Bloody W95 Max

Install via Cargo (or build locally with `cargo build --release --locked`) and launch `ratmax tui` directly (workspace resolves automatically from `RATMAX_WORKSPACE`, `$XDG_CONFIG_HOME/ratmax/workspace.json`, or `~/.config/ratmax/workspace.json`; use `sudo -E` if running under `sudo`):

```sh
cargo install --path . --locked
ratmax tui
```

On first launch without a baseline/backup, the TUI detects your connected W95 Max and prompts you to initialize your verified backup, baseline, and `workspace.json` directly from the mouse (read-only 2-pass capture, zero writes). You can also run `ratmax init` from the CLI.

### Non-root Linux access (udev rules)

To run `ratmax` without `sudo` (covering both normal mode `09da:712f` and bootloader mode `09da:d023` for Core switching / factory restore; also printed by `ratmax --help`):

```sh
sudo tee /etc/udev/rules.d/99-bloody-w95max.rules <<'EOF'
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="09da", ATTRS{idProduct}=="712f", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="09da", ATTR{idProduct}=="d023", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="09da", ATTRS{idProduct}=="d023", MODE="0660", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
```

*(Or run `sudo -E ratmax tui` if you prefer `sudo` without `udev` rules.)*

### Extracting Stock Firmware Assets (`7z`)

Extract only the four W95 Max `.hexEncode` images from the official Bloody WorkShop 8 installer using `7z` (also printed by `ratmax --help`), then verify with `ratmax inspect`:

```sh
7z x BloodyWorkShop8_*.exe \
  -o~/.local/share/ratmax/vendor \
  'program files/BloodyWorkShop8/FW/USB_M0/W95Max_P3332A_578_*_34.hexEncode'
ratmax inspect --assets "$HOME/.local/share/ratmax/vendor/program files/BloodyWorkShop8"
```

Ratmax finds `~/.local/share/ratmax/vendor/program files/BloodyWorkShop8` automatically during TUI initialization or `ratmax init` (or pass `--assets PATH`).

## Core Support & Feature Gating

The TUI automatically enables or disables features based on the selected/installed Core so only hardware-supported options are shown:

| Core | DPI & Polling | Extra Buttons (`Precision`, `Double`/`Triple`) | Shooting Mode & Selectors | Custom Button Macros | Permanent RGB |
| --- | :---: | :---: | :---: | :---: | :---: |
| **Original Core 1 (`0028`)** | Yes | No | No | No | Live preview only |
| **Core 1 (`0034`)** | Yes | Yes | No | No | Yes |
| **Core 2 (`0034`)** | Yes | Yes | Yes | No | Yes |
| **Core 3 (`0034`)** | Yes | Yes | Yes | Yes | Yes |
| **Core 4 (`0034` Full Key)** | Yes | Yes | No (no Shooting / GunA) | Yes | Yes |

## TUI Overview (3 Tabs, Consistent Controls)

Ratmax opens with **3 focused tabs**: **1 Mouse**, **2 Macros**, and **3 Lighting**.

### Global Keys (Every Tab)

| Key | Action |
| --- | --- |
| `1` / `2` / `3` or `Tab` / `Shift+Tab` | Switch between **Mouse**, **Macros**, and **Lighting** |
| `↑` / `↓` | Select row / step |
| `←` / `→` | Change value / switch mouse button |
| `Enter` | Edit selected value (DPI, macro step, hex color) |
| `Del` / `Backspace` | Revert / delete selected item |
| `s` | **Save / Apply to Mouse** (opens confirmation modal → `y` applies, `Esc` cancels) |
| `r` | Refresh / read current state from mouse |
| `q` / `Ctrl+C` | Quit |

---

### Tab 1 — Mouse

- **DPI 1–5** (`22..=12000` DPI, symmetric or asymmetric X×Y):
  - `←` / `→`: adjust X (or both X & Y while equal)
  - `Shift+←` / `Shift+→` (or `[` / `]`): adjust **Y independently**
  - `Enter` or `e`: type exact value (`1600`, `10000`, or `1600x800`)
  - `x`: quick-type Y starting from `<current_X>x`
- **Polling Rate**: `125 / 250 / 500 / 1000 / 2000 Hz`
- **Active Core**: changing Core to a different Core automatically flashes that Core on `s` → `y`; leaving it unchanged applies settings without reset or firmware flash.
- **Buttons**: assign `Back`, `Forward`, `Extra Click`, `Precision`, `Aux Click`, `Aux Front`, and `Aux Rear`.
- **Backup & Restore**: `B` exports a verified copy of your factory backup; `R` restores the original Core 1 / 0028 factory backup.

---

### Tab 2 — Macros

Automatically targets your mouse's installed Core (Core 3 or Core 4) and visually separates **TUI controls** (dimmed bottom bar) from **embedded mouse macro steps** (colored badges: `KEY`, `MOUSE`, `WAIT`, `MOVE`).

- `↑` / `↓`: pick which mouse button to configure (`●` = active on mouse); press `Enter` to focus the steps list to select/edit/reorder (`[`/`]`) individual steps (`Esc` returns to buttons)
- `←` / `→`: switch between **On Press** and **On Release** steps
- `k`: **Record Key / Combo** — pauses TUI shortcuts and captures your next keypress or chord (e.g. `Ctrl+C`, `Alt+Tab`, `F1..F12`, `Space`, arrows) directly into the mouse macro (`Esc` cancels)
- `m`: **Add Mouse Click** (`1` Left · `2` Right · `3` Middle · `4` Back · `5` Forward)
- `d`: **Add Delay** (`1..999 ms`)
- `t`: **Type Custom Step** — accepts shorthand (`f13`, `esc`, `tab`, `win+r`, `ctrl+shift+v`) or full steps (`down ctrl`, `up ctrl`, `delay 100`, `move 0 -12`)
- `+` / `-`: adjust repeat count (`1..16`)
- `s`: **Save** all configured button macros to the mouse (internal flash, zero NOR writes)
- `u`: **Clear** custom macros from the mouse and restore original button actions

---

### Tab 3 — Lighting

Controls RGB lighting with **zero external-NOR writes**:

- `←` / `→`: change **Brightness** (`0% / 25% / 50% / 100%`), **Effect** (`Stock`, `Solid`, `Gradient`, `Rainbow`, `Per-LED`), **Colors** (with live RGB swatches), and **Breathing** (`Off / Slow / Medium / Fast / Fastest`).
- `Enter`: type `#RRGGBB` hex color on any color row.
- `p` / `Space`: **Live Preview** (instant RAM preview + brightness, no flash write).
- `s`: **Save Permanently to Mouse** (writes 15-LED RGB + breathing to internal flash + sets `07 11` brightness + activates immediately; survives reboot/unplug).
- `l`: load currently saved permanent lighting from mouse; `u`: restore stock lighting; `x`: stop live preview.

CLI lighting shortcuts are also available:

```sh
ratmax lighting-status [--model]
ratmax lighting-set --brightness 2 --color 00ffcc --breathing 2 [--model]
ratmax lighting-set --gradient ff0000:0000ff [--model]
ratmax lighting-set --rainbow [--model]
ratmax lighting-set --normal [--model]
```
