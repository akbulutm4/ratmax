use ratmax::{
    boot_roundtrip::Mode,
    model::Core,
    workflow::{
        self, Button, Operation, Settings,
    },
};
use std::process::Command;

fn base_settings(entry: Mode, operation: Operation) -> Settings {
    Settings {
        operation,
        entry,
        cpi: [None; 5],
        cpi_xy: [None; 5],
        report_rate_hz: None,
        shooting_slot: None,
        custom_shooting: None,
        button_macro: None,
        custom_lighting: None,
        side_buttons: [Button::Preserve; 2],
        extra_buttons: [Button::Preserve; 5],
        restore_after: false,
        budget: None,
        model_entry: None,
    }
}

#[test]
fn core_capability_matrix_enforces_hardware_limits_across_all_cores() {
    // Shooting Mode & shooting selectors: Core 2 and Core 3 only (excluded on Core 1 and Core 4).
    assert!(!workflow::shooting_supported(Mode::Normal));
    assert!(!workflow::shooting_supported(Mode::Target(Core::One)));
    assert!(workflow::shooting_supported(Mode::Target(Core::Two)));
    assert!(workflow::shooting_supported(Mode::Target(Core::Three)));
    assert!(!workflow::shooting_supported(Mode::Target(Core::Four)));

    // GunA custom shooting: Core 3 only (explicitly excluded on Core 4).
    assert!(!workflow::gun_a_supported(Mode::Target(Core::Four)));
    assert!(workflow::gun_a_supported(Mode::Target(Core::Three)));

    // Custom button macros: Core 3 and Core 4 only.
    assert!(!workflow::macros_supported(Mode::Normal));
    assert!(!workflow::macros_supported(Mode::Target(Core::One)));
    assert!(!workflow::macros_supported(Mode::Target(Core::Two)));
    assert!(workflow::macros_supported(Mode::Target(Core::Three)));
    assert!(workflow::macros_supported(Mode::Target(Core::Four)));

    // Permanent internal-flash RGB: prepared Core 1-4 (not Original Core 1).
    assert!(!workflow::permanent_lighting_supported(Mode::Normal));
    for core in Core::ALL {
        assert!(workflow::permanent_lighting_supported(Mode::Target(core)));
    }

    // Core 4 rejects shooting slot & shooting selector buttons while accepting Precision/Double/Triple.
    let mut c4_shoot = base_settings(Mode::Target(Core::Four), Operation::Configure);
    c4_shoot.shooting_slot = Some(1);
    assert!(c4_shoot.validate(Core::Four).is_err());

    let mut c4_sel = base_settings(Mode::Target(Core::Four), Operation::Configure);
    c4_sel.side_buttons[0] = Button::SelectDouble;
    assert!(c4_sel.validate(Core::Four).is_err());

    let mut c4_ok = base_settings(Mode::Target(Core::Four), Operation::Configure);
    c4_ok.side_buttons = [Button::Precision, Button::DoubleClick];
    c4_ok.cpi_xy[0] = Some([1600, 800]);
    assert!(c4_ok.validate(Core::Four).is_ok());
}

#[test]
fn workspace_cli_flag_is_disabled_and_empty_env_refuses_cleanly() {
    for args in [
        vec!["tui", "--workspace", "unused.json"],
        vec!["workspace-inspect", "--workspace", "unused.json"],
        vec![
            "workspace-export-backup",
            "--workspace",
            "unused.json",
            "--output",
            "/tmp/ratmax-unused",
        ],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_ratmax"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }

    let disabled = Command::new(env!("CARGO_BIN_EXE_ratmax"))
        .arg("workspace-inspect")
        .env("RATMAX_WORKSPACE", "")
        .output()
        .unwrap();
    assert_eq!(disabled.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&disabled.stderr).contains("workspace not found"));
}

#[test]
fn workflow_run_rejects_raw_device_override_and_bad_input_without_creating_output() {
    let out = std::env::temp_dir().join(format!("ratmax-wf-refuse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let result = Command::new(env!("CARGO_BIN_EXE_ratmax"))
        .args([
            "workflow-run",
            "--project",
            "/dev/null",
            "--device",
            "/dev/hidraw3",
            "--output",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.exists());
}

#[test]
fn w95max_identity_validator_accepts_arbitrary_units_and_rejects_other_models() {
    let mut ident = [0u8; 96];
    // Synthetic W95 Max Core 1 identity block with arbitrary per-unit bytes.
    ident[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    ident[6..8].copy_from_slice(&0x0579u16.to_le_bytes());
    ident[32..36].copy_from_slice(&0x09da_712fu32.to_le_bytes());
    ident[40..42].copy_from_slice(&0x0579u16.to_le_bytes());
    ident[60..64].copy_from_slice(&[0xa4; 4]);
    ident[70..72].copy_from_slice(&0x0579u16.to_le_bytes());
    ident[80..96].fill(0x7e); // Arbitrary unit-specific calibration/metadata
    assert!(ratmax::boot_bank::valid_w95max_identity(&ident));

    // Any Core index 0..=3 for model 0x0578 is accepted.
    for packed in [0x0578u16, 0x0579, 0x057a, 0x057b] {
        let mut c = ident;
        c[6..8].copy_from_slice(&packed.to_le_bytes());
        c[40..42].copy_from_slice(&packed.to_le_bytes());
        c[70..72].copy_from_slice(&packed.to_le_bytes());
        assert!(ratmax::boot_bank::valid_w95max_identity(&c));
    }

    // Wrong model ID, wrong USB VID/PID, or cleared startup marker fails closed.
    let mut wrong_model = ident;
    wrong_model[6..8].copy_from_slice(&0x057cu16.to_le_bytes());
    assert!(!ratmax::boot_bank::valid_w95max_identity(&wrong_model));

    let mut wrong_pid = ident;
    wrong_pid[32..36].copy_from_slice(&0x09da_9999u32.to_le_bytes());
    assert!(!ratmax::boot_bank::valid_w95max_identity(&wrong_pid));

    let mut cleared_marker = ident;
    cleared_marker[60..64].fill(0);
    assert!(!ratmax::boot_bank::valid_w95max_identity(&cleared_marker));
}
