use std::{
    path::Path,
    process::{Command, Output},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratmax"))
        .args(args)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap()
}

#[test]
fn unknown_hardware_commands_invalid_options_and_nonterminal_tui_fail() {
    for args in [
        vec!["query-info"],
        vec!["query-info", "--snapshot", "unused"],
        vec![
            "query-info",
            "--snapshot",
            "unused",
            "--output",
            "unused",
            "--device",
            "/dev/hidraw3",
        ],
        vec!["__query-worker", "--device", "/dev/hidraw3"],
        vec!["flash"],
        vec!["discover"],
        vec!["inspect", "--core", "0"],
        vec!["inspect", "--core"],
        vec!["inspect", "--assets", "--json"],
        vec!["inspect", "--core", "1", "--core", "2"],
        vec!["tui", "--json"],
        vec!["tui", "--workspace", "unused.json"],
        vec!["tui", "--w1-project", "unused.json"],
        vec!["tui"],
        vec!["plan"],
        vec!["simulate"],
        vec!["plan", "--core", "4", "--scenario", "nominal"],
        vec!["simulate", "--core", "4", "--scenario", "unknown"],
        vec!["simulate", "--core", "4", "--record-index", "0"],
        vec!["query-audit", "--device", "/dev/hidraw0"],
        vec!["query-audit", "--assets", "/unused"],
        vec!["query-audit", "--json", "--json"],
        vec![
            "simulate",
            "--core",
            "4",
            "--scenario",
            "record-rejected",
            "--record-index",
            "1692",
        ],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn query_audit_needs_no_assets_or_device_and_advertises_only_normal_queries() {
    let output = Command::new(env!("CARGO_BIN_EXE_ratmax"))
        .args(["query-audit", "--json"])
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["mode"], "offline_query_audit");
    assert_eq!(result["live_queries_enabled"], false);
    assert_eq!(result["device_enumerated"], false);
    let allowed = result["normal_query_allowlist"].as_array().unwrap();
    assert_eq!(allowed.len(), 2);
    assert_eq!(allowed[0]["opcode"], 0x1F);
    assert_eq!(allowed[1]["opcode"], 0x2D);
}

#[test]
fn missing_asset_directory_is_an_error_without_partial_success_json() {
    let output = run(&["inspect", "--assets", "/ratmax-missing-assets", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("W95Max_P3332A_578_1_34.hexEncode"));
}

#[test]
fn help_is_noninteractive_and_includes_udev_rule_helper() {
    for args in [&[][..], &["--help"][..]] {
        let output = run(args);
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(
            "Workflow/TUI physical writes are enabled in default Linux builds; models never access the device."
        ));
        assert!(text.contains("99-bloody-w95max.rules"));
        assert!(text.contains("09da"));
        assert!(text.contains("712f"));
        assert!(text.contains("d023"));
        assert!(text.contains("udevadm control --reload-rules"));
        assert!(text.contains("7z x BloodyWorkShop8_*.exe"));
        assert!(text.contains("W95Max_P3332A_578_*_34.hexEncode"));
    }
}

#[test]
fn preview_compiles_bundled_macro_and_shooting_examples_offline() {
    for example in [
        "examples/button-macros.json",
        "examples/core3-custom-shooting.json",
        "examples/r4-programs.json",
    ] {
        let output = run(&["preview", "--project", example, "--json"]);
        assert!(
            output.status.success(),
            "{example}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["write_ready"], false);
    }
}

#[test]
fn invalid_saved_query_snapshot_fails_without_creating_output_or_opening_device() {
    let directory = std::env::temp_dir().join(format!("ratmax-p2-cli-{}", std::process::id()));
    assert!(!directory.exists());
    let result = run(&[
        "query-info",
        "--snapshot",
        "/ratmax-missing-snapshot",
        "--output",
        directory.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(!directory.exists());
}
