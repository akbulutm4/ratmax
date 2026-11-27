use std::{
    env,
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
};

use ratmax::{
    assets::{self, Inspection, Manifest},
    boot_roundtrip, discovery,
    model::Core,
    preview,
};
use serde::Serialize;

const HELP: &str = "ratmax 0.2.1 — Bloody W95 Max configuration, lighting, macros, and firmware tooling

Usage:
  ratmax tui     [--workflow-model] [--restore-session JOB]
                 [--core 1|2|3|4] [--project FILE]
  ratmax init    [--assets PATH] [--dir DIR] [--workspace FILE] [--json]
  ratmax inspect [--assets PATH] [--core 1|2|3|4] [--json]
  ratmax lighting-status [--model]
  ratmax lighting-set [--brightness 0..3] [--color RRGGBB | --gradient RRGGBB:RRGGBB | --rainbow | --normal] [--breathing 0..4] [--model]
  ratmax workspace-inspect
  ratmax workspace-export-backup --output NEW-DIR
  ratmax workflow-plan|workflow-simulate|workflow-run --project FILE --output NEW-DIR
  ratmax workflow-restore|workflow-restore-simulate --session JOB --output NEW-DIR
  ratmax discover-passive [--sysfs-root PATH] [--output NEW-DIR] [--json]
  ratmax preview --project FILE [--json]
  ratmax --help

Notes:
  - Launch `ratmax tui` (or run `ratmax init`) on first setup to create your verified
    read-only backup, baseline, and ~/.config/ratmax/workspace.json from your mouse.
  - Workspace lookup uses RATMAX_WORKSPACE (empty disables), $XDG_CONFIG_HOME/ratmax/workspace.json,
    or ~/.config/ratmax/workspace.json (use `sudo -E` if running with sudo).
  - PATH for --assets is the extracted BloodyWorkShop8 directory containing FW/.
    By default ratmax checks ~/.local/share/ratmax/vendor/program files/BloodyWorkShop8.
  - Workflow/TUI physical writes are enabled in default Linux builds; models never access the device.
  - discover-passive reads cached sysfs files only; it never opens hidraw nodes.

Non-root Linux access (udev rules for Bloody W95 Max normal 09da:712f & bootloader 09da:d023):
  sudo tee /etc/udev/rules.d/99-bloody-w95max.rules <<'EOF'
  SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"09da\", ATTRS{idProduct}==\"712f\", MODE=\"0660\", TAG+=\"uaccess\"
  SUBSYSTEM==\"usb\", ATTR{idVendor}==\"09da\", ATTR{idProduct}==\"d023\", MODE=\"0660\", TAG+=\"uaccess\"
  SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"09da\", ATTRS{idProduct}==\"d023\", MODE=\"0660\", TAG+=\"uaccess\"
  EOF
  sudo udevadm control --reload-rules && sudo udevadm trigger
  # Or run with `sudo -E ratmax tui` to preserve your $HOME and XDG paths.

Extracting stock W95 Max firmware assets with 7z (from the official Bloody WorkShop 8 installer):
  7z x BloodyWorkShop8_*.exe -o~/.local/share/ratmax/vendor 'program files/BloodyWorkShop8/FW/USB_M0/W95Max_P3332A_578_*_34.hexEncode'
  ratmax inspect --assets ~/.local/share/ratmax/vendor/\"program files/BloodyWorkShop8\"
  # Then launch `ratmax tui` (or run `ratmax init`) to create your verified backup, baseline, and workspace.json from your mouse.
";

#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    fn operation(error: impl std::fmt::Display) -> Self {
        Self {
            code: 1,
            message: error.to_string(),
        }
    }
}

enum Command {
    Help,
    Tui {
        core: Option<Core>,
        project: Option<PathBuf>,
        workflow_model: bool,
        workflow_session: Option<PathBuf>,
    },
    Init {
        options: ratmax::init::InitOptions,
        json: bool,
    },
    Inspect {
        assets: Option<PathBuf>,
        core: Option<Core>,
        json: bool,
    },
    LightingStatus {
        model: bool,
    },
    LightingSet {
        brightness: Option<ratmax::lighting::Brightness>,
        effect: Option<ratmax::lighting::Effect>,
        breathing: ratmax::lighting::Breathing,
        model: bool,
    },
    Workspace {
        output: Option<PathBuf>,
        export: bool,
    },
    Workflow {
        input: PathBuf,
        output: PathBuf,
        operation: String,
    },
    WorkflowWorker(PathBuf),
    DiscoverPassive {
        sysfs_root: Option<PathBuf>,
        output: Option<PathBuf>,
        json: bool,
    },
    Preview {
        project: PathBuf,
        json: bool,
    },
}

fn next_path(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<PathBuf, Failure> {
    let value = args
        .next()
        .filter(|v| !v.to_string_lossy().starts_with("--"))
        .ok_or_else(|| Failure::usage(format!("{flag} requires a path")))?;
    Ok(PathBuf::from(value))
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Command, Failure> {
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };
    let name = first
        .to_str()
        .ok_or_else(|| Failure::usage("command must be valid UTF-8"))?;
    match name {
        "--help" | "-h" | "help" => {
            if args.next().is_some() {
                return Err(Failure::usage("help accepts no additional arguments"));
            }
            Ok(Command::Help)
        }
        "__preset-cycle-worker" => {
            let path = args
                .next()
                .ok_or_else(|| Failure::usage("worker requires a request path"))?;
            if args.next().is_some() {
                return Err(Failure::usage("unexpected worker argument"));
            }
            Ok(Command::WorkflowWorker(PathBuf::from(path)))
        }
        "init" => {
            let mut options = ratmax::init::InitOptions::default();
            let mut json = false;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--json") if !json => json = true,
                    Some("--assets") if options.assets.is_none() => {
                        options.assets = Some(next_path(&mut args, "--assets")?);
                    }
                    Some("--dir") if options.data_dir.is_none() => {
                        options.data_dir = Some(next_path(&mut args, "--dir")?);
                    }
                    Some("--workspace") if options.workspace.is_none() => {
                        options.workspace = Some(next_path(&mut args, "--workspace")?);
                    }
                    Some("--progress-file") if options.progress_file.is_none() => {
                        options.progress_file = Some(next_path(&mut args, "--progress-file")?);
                    }
                    _ => return Err(Failure::usage("unknown or duplicate init option")),
                }
            }
            Ok(Command::Init { options, json })
        }
        "tui" => {
            let mut core = None;
            let mut project = None;
            let mut workflow_model = false;
            let mut workflow_session = None;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--core") if core.is_none() => {
                        let raw = args
                            .next()
                            .ok_or_else(|| Failure::usage("--core requires 1, 2, 3, or 4"))?;
                        let text = raw
                            .to_str()
                            .ok_or_else(|| Failure::usage("--core value must be valid UTF-8"))?;
                        core = Some(Core::from_str(text).map_err(|e| Failure::usage(e.to_string()))?);
                    }
                    Some("--project") if project.is_none() => {
                        project = Some(next_path(&mut args, "--project")?);
                    }
                    Some("--workflow-model") if !workflow_model => workflow_model = true,
                    Some("--restore-session") if workflow_session.is_none() => {
                        workflow_session = Some(next_path(&mut args, "--restore-session")?);
                    }
                    _ => return Err(Failure::usage("unknown or duplicate tui option")),
                }
            }
            Ok(Command::Tui {
                core,
                project,
                workflow_model,
                workflow_session,
            })
        }
        "inspect" => {
            let mut assets = None;
            let mut core = None;
            let mut json = false;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--assets") if assets.is_none() => {
                        assets = Some(next_path(&mut args, "--assets")?);
                    }
                    Some("--core") if core.is_none() => {
                        let raw = args
                            .next()
                            .ok_or_else(|| Failure::usage("--core requires 1, 2, 3, or 4"))?;
                        let text = raw
                            .to_str()
                            .ok_or_else(|| Failure::usage("--core value must be valid UTF-8"))?;
                        core = Some(Core::from_str(text).map_err(|e| Failure::usage(e.to_string()))?);
                    }
                    Some("--json") if !json => json = true,
                    _ => return Err(Failure::usage("unknown or duplicate inspect option")),
                }
            }
            Ok(Command::Inspect { assets, core, json })
        }
        "lighting-status" => {
            let mut model = false;
            for flag in args {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--model") if !model => model = true,
                    _ => return Err(Failure::usage("lighting-status accepts only --model")),
                }
            }
            Ok(Command::LightingStatus { model })
        }
        "lighting-set" => {
            let mut brightness = None;
            let mut effect = None;
            let mut breathing = ratmax::lighting::Breathing::Off;
            let mut breathing_set = false;
            let mut model = false;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--model") if !model => model = true,
                    Some("--rainbow") if effect.is_none() => {
                        effect = Some(ratmax::lighting::Effect::Rainbow);
                    }
                    Some("--normal") if effect.is_none() => {
                        effect = Some(ratmax::lighting::Effect::Normal);
                    }
                    Some("--brightness") if brightness.is_none() => {
                        let raw = args
                            .next()
                            .ok_or_else(|| Failure::usage("--brightness requires 0..3"))?;
                        let level = raw
                            .to_string_lossy()
                            .parse::<u8>()
                            .map_err(|_| Failure::usage("--brightness must be 0..3"))?;
                        brightness = Some(
                            ratmax::lighting::Brightness::from_level(level)
                                .map_err(Failure::usage)?,
                        );
                    }
                    Some("--color") if effect.is_none() => {
                        let raw = args
                            .next()
                            .ok_or_else(|| Failure::usage("--color requires RRGGBB"))?;
                        let rgb = ratmax::lighting::Rgb::parse_hex(&raw.to_string_lossy())
                            .map_err(Failure::usage)?;
                        effect = Some(ratmax::lighting::Effect::Solid { color: rgb });
                    }
                    Some("--gradient") if effect.is_none() => {
                        let raw = args
                            .next()
                            .ok_or_else(|| Failure::usage("--gradient requires RRGGBB:RRGGBB"))?;
                        let text = raw.to_string_lossy();
                        let (a, b) = text
                            .split_once(':')
                            .ok_or_else(|| Failure::usage("--gradient requires RRGGBB:RRGGBB"))?;
                        let start = ratmax::lighting::Rgb::parse_hex(a).map_err(Failure::usage)?;
                        let end = ratmax::lighting::Rgb::parse_hex(b).map_err(Failure::usage)?;
                        effect = Some(ratmax::lighting::Effect::Gradient { start, end });
                    }
                    Some("--breathing") if !breathing_set => {
                        let raw = args
                            .next()
                            .ok_or_else(|| Failure::usage("--breathing requires 0..4"))?;
                        let speed = raw
                            .to_string_lossy()
                            .parse::<u8>()
                            .map_err(|_| Failure::usage("--breathing must be 0..4"))?;
                        breathing = ratmax::lighting::Breathing::from_speed(speed)
                            .map_err(Failure::usage)?;
                        breathing_set = true;
                    }
                    _ => return Err(Failure::usage("unknown or duplicate lighting-set option")),
                }
            }
            if brightness.is_none() && effect.is_none() {
                return Err(Failure::usage(
                    "lighting-set needs --brightness, --color, --gradient, --rainbow, or --normal",
                ));
            }
            Ok(Command::LightingSet {
                brightness,
                effect,
                breathing,
                model,
            })
        }
        "workspace-inspect" | "workspace-export-backup" => {
            let mut output = None;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--output") if name == "workspace-export-backup" && output.is_none() => {
                        output = Some(next_path(&mut args, "--output")?);
                    }
                    _ => return Err(Failure::usage("unknown or duplicate workspace option")),
                }
            }
            if name == "workspace-export-backup" && output.is_none() {
                return Err(Failure::usage("workspace-export-backup requires --output"));
            }
            Ok(Command::Workspace {
                output,
                export: name == "workspace-export-backup",
            })
        }
        "workflow-plan"
        | "workflow-simulate"
        | "workflow-run"
        | "workflow-restore"
        | "workflow-restore-simulate" => {
            let restore = name.starts_with("workflow-restore");
            let mut input = None;
            let mut output = None;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--project") if !restore && input.is_none() => {
                        input = Some(next_path(&mut args, "--project")?);
                    }
                    Some("--session") if restore && input.is_none() => {
                        input = Some(next_path(&mut args, "--session")?);
                    }
                    Some("--output") if output.is_none() => {
                        output = Some(next_path(&mut args, "--output")?);
                    }
                    _ => return Err(Failure::usage("unknown or duplicate workflow option")),
                }
            }
            Ok(Command::Workflow {
                input: input.ok_or_else(|| Failure::usage("workflow needs --project or --session"))?,
                output: output.ok_or_else(|| Failure::usage("workflow needs --output"))?,
                operation: name.into(),
            })
        }
        "discover-passive" => {
            let mut sysfs_root = None;
            let mut output = None;
            let mut json = false;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--sysfs-root") if sysfs_root.is_none() => {
                        sysfs_root = Some(next_path(&mut args, "--sysfs-root")?);
                    }
                    Some("--output") if output.is_none() => {
                        output = Some(next_path(&mut args, "--output")?);
                    }
                    Some("--json") if !json => json = true,
                    _ => {
                        return Err(Failure::usage(
                            "unknown or duplicate discover-passive option",
                        ));
                    }
                }
            }
            Ok(Command::DiscoverPassive {
                sysfs_root,
                output,
                json,
            })
        }
        "preview" => {
            let mut project = None;
            let mut json = false;
            while let Some(flag) = args.next() {
                match flag.to_str() {
                    Some("--help" | "-h") => return Ok(Command::Help),
                    Some("--project") if project.is_none() => {
                        project = Some(next_path(&mut args, "--project")?);
                    }
                    Some("--json") if !json => json = true,
                    _ => return Err(Failure::usage("unknown or duplicate preview option")),
                }
            }
            Ok(Command::Preview {
                project: project.ok_or_else(|| Failure::usage("preview requires --project FILE"))?,
                json,
            })
        }
        _ => Err(Failure::usage(format!(
            "unknown command \"{name}\"; use --help"
        ))),
    }
}

#[derive(Serialize)]
struct InspectionReport<'a> {
    schema_version: u32,
    mode: &'static str,
    asset_root: String,
    scope: &'a str,
    images: Vec<Inspection>,
}

fn run() -> Result<(), Failure> {
    match parse(env::args_os().skip(1))? {
        Command::Help => {
            output(HELP)?;
            Ok(())
        }
        Command::WorkflowWorker(path) => {
            boot_roundtrip::pipeline::worker(&path).map_err(Failure::operation)
        }
        Command::Init { options, json } => {
            let report = ratmax::init::run(&options).map_err(Failure::operation)?;
            if json {
                output(
                    &(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"),
                )?;
            } else {
                output(&format!(
                    "Initialized ratmax workspace for Bloody W95 Max ({:?})\n  Device:    {} ({})\n  Workspace: {}\n  Baseline:  {}\n  Backup:    {} (SHA-256 {})\n  Assets:    {}\n  Writes:    {} (read-only)\n",
                    report.mode,
                    report.node,
                    report.usb_parent,
                    report.workspace.display(),
                    report.baseline.display(),
                    report.backup.display(),
                    report.backup_sha256,
                    report.assets.display(),
                    report.device_writes,
                ))?;
            }
            Ok(())
        }
        Command::Tui {
            core,
            project,
            workflow_model,
            workflow_session,
        } => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return Err(Failure::usage(
                    "tui requires an interactive terminal; use inspect --json for noninteractive output",
                ));
            }
            let existing_workspace = ratmax::workflow::Workspace::default_path();
            if (workflow_model || workflow_session.is_some()) && existing_workspace.is_none() {
                return Err(Failure::usage(
                    "workflow options require RATMAX_WORKSPACE or ~/.config/ratmax/workspace.json",
                ));
            }
            let workspace = existing_workspace
                .clone()
                .unwrap_or_else(ratmax::workflow::Workspace::preferred_config_path);
            ratmax::tui::run(
                core.unwrap_or(if existing_workspace.is_some() {
                    Core::Three
                } else {
                    Core::One
                }),
                project,
                Some(ratmax::tui::WorkflowOptions {
                    workspace,
                    model: workflow_model,
                    session: workflow_session,
                }),
            )
            .map_err(Failure::operation)
        }
        Command::Inspect { assets, core, json } => {
            let root = assets
                .or_else(assets::default_asset_root)
                .ok_or_else(|| {
                    Failure::usage(
                        "assets directory not found; pass --assets PATH or extract to ~/.local/share/ratmax/vendor/program files/BloodyWorkShop8 (see --help)",
                    )
                })?;
            let manifest = Manifest::embedded().map_err(Failure::operation)?;
            let cores: Vec<Core> = match core {
                Some(c) => vec![c],
                None => Core::ALL.to_vec(),
            };
            let mut images = Vec::with_capacity(cores.len());
            for c in cores {
                images.push(
                    manifest
                        .inspect_file(&root, c)
                        .map_err(Failure::operation)?
                        .inspection()
                        .clone(),
                );
            }
            if json {
                let report = InspectionReport {
                    schema_version: 1,
                    mode: "offline_asset_inspection",
                    asset_root: root.display().to_string(),
                    scope: manifest.scope(),
                    images,
                };
                output(
                    &(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"),
                )?;
            } else {
                let mut text = format!(
                    "ratmax | OFFLINE | {}\nAssets: {}\n",
                    manifest.model(),
                    root.display()
                );
                for img in &images {
                    text.push_str(&format!(
                        "\nCore {} -> firmware index {}: verified local asset\n  {}\n  {} bytes | {} encoded records\n  Source SHA-256: {}\n  Buffer SHA-256: {}\n",
                        img.core.number(),
                        img.firmware_index.get(),
                        img.source,
                        img.source_bytes,
                        img.record_count,
                        img.source_sha256,
                        img.scratch_buffer_sha256,
                    ));
                }
                output(&text)?;
            }
            Ok(())
        }
        Command::LightingStatus { model } => {
            let input = ratmax::workflow::Workspace::resolve_default().map_err(Failure::operation)?;
            let workspace =
                ratmax::workflow::Workspace::load(&input).map_err(Failure::operation)?;
            let status =
                ratmax::lighting::read_status(&workspace, model).map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&status).map_err(Failure::operation)? + "\n"))
        }
        Command::LightingSet {
            brightness,
            effect,
            breathing,
            model,
        } => {
            let input = ratmax::workflow::Workspace::resolve_default().map_err(Failure::operation)?;
            let workspace =
                ratmax::workflow::Workspace::load(&input).map_err(Failure::operation)?;
            let report = ratmax::lighting::apply(
                &workspace,
                brightness,
                effect.as_ref(),
                breathing,
                model,
            )
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))
        }
        Command::Workspace {
            output: directory,
            export,
        } => {
            let input = ratmax::workflow::Workspace::resolve_default().map_err(Failure::operation)?;
            let workspace =
                ratmax::workflow::Workspace::load(&input).map_err(Failure::operation)?;
            let report = if export {
                workspace.export_backup(&directory.expect("validated output"))
            } else {
                workspace.inspect()
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))
        }
        Command::Workflow {
            input,
            output: directory,
            operation,
        } => {
            let report = match operation.as_str() {
                "workflow-run" => ratmax::workflow::run(&input, &directory),
                "workflow-restore" => ratmax::workflow::restore(&input, &directory),
                "workflow-restore-simulate" => {
                    ratmax::workflow::simulate_restore(&input, &directory)
                }
                _ => ratmax::workflow::prepare(&input, &directory, operation == "workflow-simulate"),
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            if matches!(operation.as_str(), "workflow-run" | "workflow-restore")
                && report["complete"] != true
            {
                return Err(Failure::operation("workflow job did not complete cleanly"));
            }
            Ok(())
        }
        Command::DiscoverPassive {
            sysfs_root,
            output: out_dir,
            json,
        } => {
            let root = sysfs_root.unwrap_or_else(|| PathBuf::from("/sys"));
            let report = discovery::collect(&root).map_err(Failure::operation)?;
            if let Some(dir) = out_dir {
                report.save(&dir).map_err(Failure::operation)?;
            }
            if json {
                output(
                    &(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"),
                )?;
            } else {
                output(&report.text())?;
            }
            if !report.complete() {
                return Err(Failure::operation("passive discovery analysis incomplete"));
            }
            Ok(())
        }
        Command::Preview { project, json } => {
            let report = preview::load(&project).map_err(Failure::operation)?;
            if json {
                output(
                    &(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"),
                )?;
            } else {
                output(&report.text())?;
            }
            Ok(())
        }
    }
}

fn output(text: &str) -> Result<(), Failure> {
    io::stdout()
        .write_all(text.as_bytes())
        .map_err(Failure::operation)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(io::stderr(), "ratmax: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}
