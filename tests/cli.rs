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
fn unknown_commands_invalid_options_and_nonterminal_tui_fail() {
    for args in [
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
        vec!["init", "--unknown"],
        vec!["init", "--assets"],
        vec!["lighting-set"],
        vec!["lighting-status", "--invalid"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn missing_asset_directory_is_an_error_without_partial_success_json() {
    let output = run(&["inspect", "--assets", "/ratmax-missing-assets", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("W95Max_P3332A_578_1_34.hexEncode"));
}

#[test]
fn help_is_noninteractive_and_includes_setup_helpers() {
    for args in [&[][..], &["--help"][..]] {
        let output = run(args);
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("ratmax init"));
        assert!(text.contains("ratmax tui"));
        assert!(text.contains("sudo -E"));
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
        "examples/shooting-programs.json",
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
