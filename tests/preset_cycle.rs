use std::{path::PathBuf, process::Command};
#[test]
fn live_preset_entries_refuse_before_local_inputs_or_device_access() {
    let output =
        std::env::temp_dir().join(format!("ratmax-preset-disabled-{}", std::process::id()));
    for args in [
        vec![
            "preset-cycle-run",
            "--project",
            "/dev/null",
            "--output",
            output.to_str().unwrap(),
        ],
        vec![
            "preset-cycle-restore",
            "--session",
            "/dev/null",
            "--output",
            output.to_str().unwrap(),
        ],
        vec!["__preset-cycle-worker", "/dev/null"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_ratmax"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        if args[0] != "__preset-cycle-worker"
            || !cfg!(all(target_os = "linux", feature = "linux-query"))
        {
            assert!(String::from_utf8_lossy(&result.stderr).contains("disabled in this build"));
        }
        assert!(!output.exists());
    }
}
#[test]
fn preset_cli_does_not_accept_device_paths_resume_offsets_or_read_pass_overrides() {
    let output = PathBuf::from(format!("/tmp/ratmax-preset-options-{}", std::process::id()));
    for (option, value) in [
        ("--device", "/dev/hidraw3"),
        ("--resume", "100"),
        ("--passes", "2"),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_ratmax"))
            .args([
                "preset-cycle-run",
                "--project",
                "missing",
                "--output",
                output.to_str().unwrap(),
                option,
                value,
            ])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(!output.exists());
    }
}
