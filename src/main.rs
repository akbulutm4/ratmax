use std::{
    env,
    ffi::OsString,
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use ratmax::{
    access_job::CaptureScope,
    access_session,
    access_simulation::AccessScenario,
    assets::{self, Inspection, Manifest},
    boot_roundtrip, discovery,
    model::Core,
    plan::FirmwarePlan,
    preview, queries, query_session, readback, recovery, settings_cycle,
    simulation::{self, Scenario, SimulationConfig},
    w1,
};
use serde::Serialize;

const HELP: &str = "ratmax 0.2.1 — Bloody W95 Max configuration, lighting, macros, and firmware tooling

Usage:
  ratmax inspect [--assets PATH] [--core 1|2|3|4] [--json]
  ratmax tui     [--workflow-model] [--restore-session JOB]
                 [--core 1|2|3|4] [--project FILE]
  ratmax preview --project FILE [--json]
  ratmax settings-recovery-replay --project FILE
  ratmax settings-cycle-simulate --project FILE
  ratmax button-plan --project FILE
  ratmax button-cycle-simulate --project FILE --baseline BOOT-BANK-SESSION-DIR
                 --output NEW-DIR [--fault NAME]
  ratmax button-cycle-check|button-cycle-run --project FILE --baseline BOOT-BANK-SESSION-DIR
                 --output NEW-DIR [--observe-seconds 0..300 (run only)]
  ratmax button-cycle-restore --session PREVIOUS-RUN-DIR --output NEW-DIR
  ratmax workflow-plan|workflow-simulate|workflow-run --project FILE --output NEW-DIR
  ratmax workflow-restore|workflow-restore-simulate --session JOB --output NEW-DIR
  ratmax workspace-inspect
  ratmax workspace-export-backup --output NEW-DIR
  ratmax lighting-status [--model]
  ratmax lighting-set [--brightness 0..3] [--color RRGGBB | --gradient RRGGBB:RRGGBB | --rainbow | --normal] [--breathing 0..4] [--model]
  ratmax preset-cycle-plan|preset-cycle-simulate|preset-cycle-run --project FILE --output NEW-DIR
  ratmax preset-cycle-restore --session PREVIOUS-CYCLE-DIR --output NEW-DIR
  ratmax w1-run --project FILE --output NEW-DIR
  ratmax boot-roundtrip-plan|boot-roundtrip-simulate|boot-roundtrip-run
                 --baseline BOOT-BANK-SESSION-DIR --output NEW-DIR
                 [--scenario NAME (simulation only)]
  ratmax plan     --core 1|2|3|4 [--assets PATH] [--json]
  ratmax prepared-plan|prepared-simulate --core 1|2|3|4 [--assets PATH] [--json]
  ratmax firmware-job-plan|firmware-job-simulate|firmware-job-run
                 --baseline BOOT-BANK-SESSION-DIR --core 1|2|3|4 --output NEW-DIR
                 [--assets PATH]
  ratmax firmware-restore-plan|firmware-restore-simulate|firmware-restore-run
                 --baseline BOOT-BANK-SESSION-DIR --backup VERIFIED-BACKUP-SESSION-DIR
                 --output NEW-DIR [--attempts N] [--from-normal] [--failures N (simulation only)]
  ratmax firmware-return-plan|firmware-return-simulate|firmware-return-run
                 --baseline BOOT-BANK-SESSION-DIR --backup VERIFIED-BACKUP-SESSION-DIR
                 --prepared-session COMPLETED-NATIVE-FIRMWARE-DIR --output NEW-DIR
                 [offline plan/simulation: --core 1|2|3|4 replaces --prepared-session]
  ratmax firmware-backup-plan|firmware-backup-simulate|firmware-backup-run
                 --baseline BOOT-BANK-SESSION-DIR --output NEW-DIR
  ratmax simulate --core 1|2|3|4 [--assets PATH] [--json]
                  [--scenario NAME] [--record-index N]
  ratmax --help
  ratmax query-audit [--json]
  ratmax discover-passive [--sysfs-root PATH] [--output NEW-DIR] [--json]
  ratmax query-info --snapshot P1-JSON --output NEW-DIR
  ratmax query-layout --snapshot P1-JSON --baseline INFO-SESSION --output NEW-DIR
  ratmax query-headers --snapshot P1-JSON --baseline INFO-SESSION
                       --layout-session LAYOUT-SESSION --output NEW-DIR
  ratmax query-sensitivity-body --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR
  ratmax query-sensitivity-block --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR
  ratmax query-sensitivity-memory02 --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR
  ratmax access-plan|access-simulate|access-run --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR [--scenario NAME (simulation only)]
  ratmax access-read-settings --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR
  ratmax access-read-recovery --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR
  ratmax access-read-boot-bank --snapshot P1-JSON --baseline INFO-SESSION
                         --layout-session LAYOUT-SESSION --headers-session HEADERS-SESSION
                         --output NEW-DIR
  ratmax readback-inspect --layout-reply FILE [--sensitivity-header-reply FILE]
                         [--main-header-reply FILE] [--json]

PATH is the extracted BloodyWorkShop8 application directory (containing FW/).
From the mouse workspace or ratmax directory, the extraction is found locally.
inspect validates all four images unless --core selects one.
--core selects the initial image in the TUI; it does not change the mouse.
plan and simulate require an explicit Core. Simulation defaults to nominal.
--record-index is zero-based, for record fault scenarios only (default 846).
An injected fault is reported in the result; exit 0 means the simulation ran.

discover-passive reads cached sysfs files only; it never opens hidraw nodes.
readback-inspect reads local 64-byte reply files only; it sends no queries.
preview compiles local settings candidates and isolated program fragments.
settings-recovery-replay compares two saved settings passes in an offline replay.
settings-cycle-simulate models one CPI edit, verification and restoration offline.
query-info requires linux-query and permits only 07 1F / 07 2D.
query-layout adds one 07 05 pair after fresh identity/state match a saved baseline.
query-headers adds two eight-byte 2F00 header observations after a matching fresh layout.
query-sensitivity-body instead adds one sensitivity+8 pair after a matching fresh header.
query-sensitivity-block bounds capture to 256 bytes; invalid first checksum stops it.
query-sensitivity-memory02 checks one 02 header before conditional full capture; no unlock.
Workspace lookup uses RATMAX_WORKSPACE (empty disables), $XDG_CONFIG_HOME/ratmax/workspace.json, or ~/.config/ratmax/workspace.json (including SUDO_USER).
Workflow/TUI physical writes are enabled in default Linux builds; models never access the device.
Physical access-key changes remain disabled pending review, including in linux-query builds.
access-plan/access-simulate read local baselines only. Standard builds disable physical access scopes.
prepared-plan/prepared-simulate use local stock assets only and have no device executor.
The measured boot transport uses 64-byte Feature buffers. Legacy simulate retains abstract events.

Non-root Linux access (udev rules for Bloody W95 Max normal 09da:712f & bootloader 09da:d023):
  sudo tee /etc/udev/rules.d/99-bloody-w95max.rules <<'EOF'
  SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"09da\", ATTRS{idProduct}==\"712f\", MODE=\"0660\", TAG+=\"uaccess\"
  SUBSYSTEM==\"usb\", ATTR{idVendor}==\"09da\", ATTR{idProduct}==\"d023\", MODE=\"0660\", TAG+=\"uaccess\"
  SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"09da\", ATTRS{idProduct}==\"d023\", MODE=\"0660\", TAG+=\"uaccess\"
  EOF
  sudo udevadm control --reload-rules && sudo udevadm trigger

Extracting stock W95 Max firmware assets with 7z (from the official Bloody WorkShop 8 installer):
  7z x BloodyWorkShop8_*.exe -o~/.local/share/ratmax/vendor 'program files/BloodyWorkShop8/FW/USB_M0/W95Max_P3332A_578_*_34.hexEncode'
  ratmax inspect --assets ~/.local/share/ratmax/vendor/\"program files/BloodyWorkShop8\"
  # Then set \"assets\" in ~/.config/ratmax/workspace.json to that BloodyWorkShop8 directory.
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

struct Options {
    assets: Option<PathBuf>,
    core: Option<Core>,
    project: Option<PathBuf>,
    workflow_model: bool,
    workflow_session: Option<PathBuf>,
    json: bool,
    simulation: SimulationConfig,
}

enum AccessOperation {
    Plan,
    Simulate(AccessScenario),
    Run(CaptureScope),
}
enum BootOperation {
    Plan,
    Simulate(boot_roundtrip::Scenario),
    Run,
}
enum Command {
    Workflow {
        input: PathBuf,
        output: PathBuf,
        operation: String,
    },
    Workspace {
        output: Option<PathBuf>,
        export: bool,
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
    PresetCycle {
        input: PathBuf,
        output: PathBuf,
        operation: String,
    },
    PresetWorker(PathBuf),
    TargetReturn {
        baseline: PathBuf,
        backup: PathBuf,
        prepared: Option<PathBuf>,
        core: Option<Core>,
        output: PathBuf,
        operation: String,
    },
    TargetReturnWorker {
        baseline: PathBuf,
        backup: PathBuf,
        proof: PathBuf,
        entry: Option<PathBuf>,
        boot: bool,
    },
    BootReadback {
        baseline: PathBuf,
        backup: PathBuf,
        output: PathBuf,
        operation: String,
    },
    BootReadbackWorker {
        baseline: PathBuf,
        backup: PathBuf,
    },
    EntryReturnWorker {
        baseline: PathBuf,
        proof: PathBuf,
        mode: boot_roundtrip::Mode,
    },
    FirmwareBackup {
        baseline: PathBuf,
        output: PathBuf,
        operation: String,
    },
    BackupWorker(PathBuf),
    GateClose {
        baseline: PathBuf,
        output: PathBuf,
    },
    GateCloseWorker(PathBuf),
    FirmwareRestore {
        baseline: PathBuf,
        backup: PathBuf,
        output: PathBuf,
        operation: String,
        attempts: Option<u32>,
        failures: u32,
        from_normal: bool,
    },
    RestoreWorker {
        baseline: PathBuf,
        backup: PathBuf,
        from_normal: bool,
    },
    FirmwareJob {
        baseline: PathBuf,
        output: PathBuf,
        assets: PathBuf,
        core: Core,
        operation: String,
    },
    FirmwareWorker {
        baseline: PathBuf,
        assets: PathBuf,
        core: Core,
    },
    Prepared {
        core: Core,
        assets: Option<PathBuf>,
        simulate: bool,
    },
    BootRoundtrip {
        baseline: PathBuf,
        output: PathBuf,
        operation: BootOperation,
    },
    BootWorker(PathBuf),
    Access {
        snapshot: PathBuf,
        baseline: PathBuf,
        layout: PathBuf,
        headers: PathBuf,
        output: PathBuf,
        operation: AccessOperation,
    },
    AccessWorker,
    SettingsRecoveryReplay(PathBuf),
    SettingsCycleSimulate(PathBuf),
    ButtonPlan(PathBuf),
    ButtonCycle {
        project: PathBuf,
        baseline: PathBuf,
        output: PathBuf,
        fault: String,
        physical: bool,
        read_only: bool,
        observe_seconds: u16,
    },
    ButtonRestore {
        session: PathBuf,
        output: PathBuf,
    },
    ButtonCycleWorker {
        source: PathBuf,
        proof: Option<PathBuf>,
    },
    W1 {
        project: PathBuf,
        output: PathBuf,
        worker: bool,
    },
    Help,
    QueryWorker,
    Readback {
        layout: PathBuf,
        sensitivity: Option<PathBuf>,
        main: Option<PathBuf>,
        json: bool,
    },
    QueryLayout {
        snapshot: PathBuf,
        baseline: PathBuf,
        output: PathBuf,
    },
    QueryHeaders {
        snapshot: PathBuf,
        baseline: PathBuf,
        layout_session: PathBuf,
        output: PathBuf,
    },
    QueryBody {
        snapshot: PathBuf,
        baseline: PathBuf,
        layout_session: PathBuf,
        headers_session: PathBuf,
        block: bool,
        memory02: bool,
        output: PathBuf,
    },
    QueryInfo {
        snapshot: PathBuf,
        output: PathBuf,
    },
    Inspect(Options),
    Tui(Options),
    Preview {
        project: PathBuf,
        json: bool,
    },
    Plan(Options),
    Simulate(Options),
    QueryAudit {
        json: bool,
    },
    Passive {
        root: PathBuf,
        output: Option<PathBuf>,
        json: bool,
    },
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Command, Failure> {
    let Some(command) = args.next() else {
        return Ok(Command::Help);
    };
    let name = command
        .to_str()
        .ok_or_else(|| Failure::usage("command must be UTF-8"))?;
    if matches!(name, "--help" | "-h" | "help") {
        return Ok(Command::Help);
    }
    if matches!(
        name,
        "workflow-plan"
            | "workflow-simulate"
            | "workflow-run"
            | "workflow-restore"
            | "workflow-restore-simulate"
    ) {
        let mut input = None;
        let mut output = None;
        while let Some(flag) = args.next() {
            let slot = match flag.to_str() {
                Some("--project") if !name.contains("restore") => &mut input,
                Some("--session") if name.contains("restore") => &mut input,
                Some("--output") => &mut output,
                _ => return Err(Failure::usage("unknown workflow option")),
            };
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("workflow option needs a value"))?;
            if slot.replace(PathBuf::from(value)).is_some() {
                return Err(Failure::usage("duplicate workflow option"));
            }
        }
        return Ok(Command::Workflow {
            input: input.ok_or_else(|| Failure::usage("workflow needs --project or --session"))?,
            output: output.ok_or_else(|| Failure::usage("workflow needs --output"))?,
            operation: name.into(),
        });
    }
    if matches!(name, "workspace-inspect" | "workspace-export-backup") {
        let mut output = None;
        while let Some(flag) = args.next() {
            match flag.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--output") if name == "workspace-export-backup" => {
                    let value = args
                        .next()
                        .filter(|v| !v.to_string_lossy().starts_with("--"))
                        .ok_or_else(|| Failure::usage("workspace option needs a path"))?;
                    if output.replace(PathBuf::from(value)).is_some() {
                        return Err(Failure::usage("duplicate workspace option"));
                    }
                }
                _ => return Err(Failure::usage("unknown workspace option")),
            }
        }
        if name == "workspace-export-backup" && output.is_none() {
            return Err(Failure::usage("backup export needs --output"));
        }
        return Ok(Command::Workspace {
            output,
            export: name == "workspace-export-backup",
        });
    }
    if name == "lighting-status" {
        let mut model = false;
        for flag in args {
            match flag.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--model") if !model => model = true,
                _ => return Err(Failure::usage("lighting-status accepts only --model")),
            }
        }
        return Ok(Command::LightingStatus { model });
    }
    if name == "lighting-set" {
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
                    let v = args
                        .next()
                        .ok_or_else(|| Failure::usage("--brightness requires 0..3"))?
                        .to_string_lossy()
                        .parse::<u8>()
                        .map_err(|_| Failure::usage("--brightness must be 0..3"))?;
                    brightness = Some(
                        ratmax::lighting::Brightness::from_level(v).map_err(Failure::usage)?,
                    );
                }
                Some("--breathing") if !breathing_set => {
                    let v = args
                        .next()
                        .ok_or_else(|| Failure::usage("--breathing requires 0..4"))?
                        .to_string_lossy()
                        .parse::<u8>()
                        .map_err(|_| Failure::usage("--breathing must be 0..4"))?;
                    breathing =
                        ratmax::lighting::Breathing::from_speed(v).map_err(Failure::usage)?;
                    breathing_set = true;
                }
                Some("--color") if effect.is_none() => {
                    let raw = args
                        .next()
                        .ok_or_else(|| Failure::usage("--color requires RRGGBB"))?;
                    let color = ratmax::lighting::Rgb::parse_hex(&raw.to_string_lossy())
                        .map_err(Failure::usage)?;
                    effect = Some(ratmax::lighting::Effect::Solid { color });
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
                _ => return Err(Failure::usage("unknown or conflicting lighting-set option")),
            }
        }
        if brightness.is_none() && effect.is_none() {
            return Err(Failure::usage(
                "lighting-set requires --brightness and/or --color/--gradient/--rainbow/--normal",
            ));
        }
        return Ok(Command::LightingSet {
            brightness,
            effect,
            breathing,
            model,
        });
    }
    if name == "__preset-cycle-worker" {
        let path = args
            .next()
            .ok_or_else(|| Failure::usage("preset worker needs its frozen request"))?;
        if args.next().is_some() {
            return Err(Failure::usage("extra preset worker argument"));
        }
        return Ok(Command::PresetWorker(path.into()));
    }
    if matches!(
        name,
        "preset-cycle-plan" | "preset-cycle-simulate" | "preset-cycle-run" | "preset-cycle-restore"
    ) {
        let mut input = None;
        let mut output = None;
        while let Some(option) = args.next() {
            let slot = match option.to_str() {
                Some("--project") if name != "preset-cycle-restore" => &mut input,
                Some("--session") if name == "preset-cycle-restore" => &mut input,
                Some("--output") => &mut output,
                _ => return Err(Failure::usage("unknown preset-cycle option")),
            };
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("preset-cycle option needs a value"))?;
            if slot.replace(value).is_some() {
                return Err(Failure::usage("duplicate preset-cycle option"));
            }
        }
        return Ok(Command::PresetCycle {
            input: input
                .ok_or_else(|| Failure::usage("preset-cycle needs its input"))?
                .into(),
            output: output
                .ok_or_else(|| Failure::usage("preset-cycle needs --output"))?
                .into(),
            operation: name.into(),
        });
    }
    if name == "__button-cycle-worker" {
        let source = args
            .next()
            .ok_or_else(|| Failure::usage("button worker requires source"))?
            .into();
        let proof = args.next().map(PathBuf::from);
        if args.next().is_some() {
            return Err(Failure::usage("extra button worker argument"));
        }
        return Ok(Command::ButtonCycleWorker { source, proof });
    }
    if name == "button-cycle-restore" {
        let mut session = None;
        let mut output = None;
        while let Some(option) = args.next() {
            let slot = match option.to_str() {
                Some("--session") => &mut session,
                Some("--output") => &mut output,
                _ => return Err(Failure::usage("unknown button restoration option")),
            };
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("button restoration option requires a value"))?;
            if slot.replace(value).is_some() {
                return Err(Failure::usage("duplicate button restoration option"));
            }
        }
        return Ok(Command::ButtonRestore {
            session: session
                .ok_or_else(|| Failure::usage("restoration requires --session"))?
                .into(),
            output: output
                .ok_or_else(|| Failure::usage("restoration requires --output"))?
                .into(),
        });
    }
    if matches!(
        name,
        "button-cycle-simulate" | "button-cycle-run" | "button-cycle-check"
    ) {
        let physical = name != "button-cycle-simulate";
        let read_only = name == "button-cycle-check";
        let mut project = None;
        let mut baseline = None;
        let mut output = None;
        let mut fault = None;
        let mut observation = None;
        while let Some(option) = args.next() {
            let slot = match option.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--project") => &mut project,
                Some("--baseline") => &mut baseline,
                Some("--output") => &mut output,
                Some("--fault") if !physical => &mut fault,
                Some("--observe-seconds") if physical && !read_only => &mut observation,
                _ => return Err(Failure::usage("unknown button-cycle option")),
            };
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("button-cycle option requires a value"))?;
            if slot.replace(value).is_some() {
                return Err(Failure::usage("duplicate button-cycle option"));
            }
        }
        return Ok(Command::ButtonCycle {
            physical,
            read_only,
            observe_seconds: observation
                .unwrap_or_else(|| "45".into())
                .into_string()
                .map_err(|_| Failure::usage("observation interval must be numeric"))?
                .parse::<u16>()
                .ok()
                .filter(|v| *v <= 300)
                .ok_or_else(|| Failure::usage("observation interval must be 0..300"))?,
            project: project
                .ok_or_else(|| Failure::usage("button-cycle requires --project"))?
                .into(),
            baseline: baseline
                .ok_or_else(|| Failure::usage("button-cycle requires --baseline"))?
                .into(),
            output: output
                .ok_or_else(|| Failure::usage("button-cycle requires --output"))?
                .into(),
            fault: fault
                .unwrap_or_else(|| "none".into())
                .into_string()
                .map_err(|_| Failure::usage("fault must be UTF-8"))?,
        });
    }
    if name == "__firmware-target-worker" {
        let baseline = args
            .next()
            .ok_or_else(|| Failure::usage("target worker requires baseline"))?;
        let backup = args
            .next()
            .ok_or_else(|| Failure::usage("target worker requires backup"))?;
        let proof = args
            .next()
            .ok_or_else(|| Failure::usage("target worker requires proof"))?;
        let mode = args
            .next()
            .ok_or_else(|| Failure::usage("target worker requires entry mode"))?;
        let (entry, boot) = match mode.to_str() {
            Some("entry") => (None, false),
            Some("cleanup-boot" | "cleanup-target") => (
                Some(PathBuf::from(args.next().ok_or_else(|| {
                    Failure::usage("target cleanup requires stopped entry")
                })?)),
                mode == "cleanup-boot",
            ),
            _ => return Err(Failure::usage("invalid target worker mode")),
        };
        if args.next().is_some() {
            return Err(Failure::usage("extra target worker argument"));
        }
        return Ok(Command::TargetReturnWorker {
            baseline: baseline.into(),
            backup: backup.into(),
            proof: proof.into(),
            entry,
            boot,
        });
    }
    if matches!(
        name,
        "firmware-return-plan" | "firmware-return-simulate" | "firmware-return-run"
    ) {
        let (mut baseline, mut backup, mut prepared, mut core, mut output) =
            (None, None, None, None, None);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("target-return option requires value"))?;
            match flag.to_str() {
                Some("--baseline") if baseline.is_none() => baseline = Some(PathBuf::from(value)),
                Some("--backup") if backup.is_none() => backup = Some(PathBuf::from(value)),
                Some("--prepared-session") if prepared.is_none() => {
                    prepared = Some(PathBuf::from(value))
                }
                Some("--core") if core.is_none() => {
                    core = Some(
                        value
                            .to_string_lossy()
                            .parse()
                            .map_err(Failure::usage_from_display)?,
                    )
                }
                Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err(Failure::usage("unknown or duplicate target-return option")),
            }
        }
        if prepared.is_some() == core.is_some()
            || (name == "firmware-return-run" && prepared.is_none())
        {
            return Err(Failure::usage(
                "target return requires --prepared-session; offline plan/simulation alternatively accepts --core",
            ));
        }
        return Ok(Command::TargetReturn {
            baseline: baseline.ok_or_else(|| Failure::usage("target return requires baseline"))?,
            backup: backup.ok_or_else(|| Failure::usage("target return requires backup"))?,
            prepared,
            core,
            output: output.ok_or_else(|| Failure::usage("target return requires output"))?,
            operation: name.into(),
        });
    }
    if name == "__boot-readback-worker" {
        let baseline = args
            .next()
            .ok_or_else(|| Failure::usage("boot readback worker requires baseline"))?;
        let backup = args
            .next()
            .ok_or_else(|| Failure::usage("boot readback worker requires backup"))?;
        if args.next().is_some() {
            return Err(Failure::usage("extra boot readback worker argument"));
        }
        return Ok(Command::BootReadbackWorker {
            baseline: baseline.into(),
            backup: backup.into(),
        });
    }
    if matches!(
        name,
        "boot-readback-plan" | "boot-readback-simulate" | "boot-readback-run"
    ) {
        let (mut baseline, mut backup, mut output) = (None, None, None);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("boot readback option requires value"))?;
            match flag.to_str() {
                Some("--baseline") if baseline.is_none() => baseline = Some(PathBuf::from(value)),
                Some("--backup") if backup.is_none() => backup = Some(PathBuf::from(value)),
                Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err(Failure::usage("unknown or duplicate boot readback option")),
            }
        }
        return Ok(Command::BootReadback {
            baseline: baseline.ok_or_else(|| Failure::usage("boot readback requires baseline"))?,
            backup: backup.ok_or_else(|| Failure::usage("boot readback requires backup"))?,
            output: output.ok_or_else(|| Failure::usage("boot readback requires output"))?,
            operation: name.into(),
        });
    }
    if name == "__entry-return-worker" {
        let baseline = args
            .next()
            .ok_or_else(|| Failure::usage("entry-return worker requires baseline"))?;
        let proof = args
            .next()
            .ok_or_else(|| Failure::usage("entry-return worker requires proof"))?;
        let mode = match args.next().as_deref().and_then(|s| s.to_str()) {
            Some("boot") => boot_roundtrip::Mode::Boot,
            Some("normal") => boot_roundtrip::Mode::Normal,
            _ => return Err(Failure::usage("entry-return worker requires a fixed mode")),
        };
        if args.next().is_some() {
            return Err(Failure::usage("extra entry-return worker argument"));
        }
        return Ok(Command::EntryReturnWorker {
            baseline: baseline.into(),
            proof: proof.into(),
            mode,
        });
    }
    if name == "__firmware-restore-worker" {
        let baseline = args
            .next()
            .ok_or_else(|| Failure::usage("restore worker requires baseline and backup"))?;
        let backup = args
            .next()
            .ok_or_else(|| Failure::usage("restore worker requires backup"))?;
        let from_normal = match args.next().as_deref().and_then(|v| v.to_str()) {
            Some("normal") => true,
            None | Some("boot") => false,
            _ => return Err(Failure::usage("invalid restore entry mode")),
        };
        if args.next().is_some() {
            return Err(Failure::usage("extra restore worker argument"));
        }
        return Ok(Command::RestoreWorker {
            baseline: baseline.into(),
            backup: backup.into(),
            from_normal,
        });
    }
    if matches!(
        name,
        "firmware-restore-plan" | "firmware-restore-simulate" | "firmware-restore-run"
    ) {
        let mut baseline = None;
        let mut backup = None;
        let mut output = None;
        let mut attempts = None;
        let mut failures = None;
        let mut from_normal = false;
        while let Some(flag) = args.next() {
            if matches!(flag.to_str(), Some("--help" | "-h")) {
                return Ok(Command::Help);
            }
            if flag == "--from-normal" {
                if from_normal {
                    return Err(Failure::usage("duplicate --from-normal"));
                }
                from_normal = true;
                continue;
            }
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("restore option requires a value"))?;
            match flag.to_str() {
                Some("--baseline") if baseline.is_none() => baseline = Some(PathBuf::from(value)),
                Some("--backup") if backup.is_none() => backup = Some(PathBuf::from(value)),
                Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
                Some("--attempts") if attempts.is_none() => {
                    let n = value
                        .to_string_lossy()
                        .parse::<u32>()
                        .map_err(Failure::usage_from_display)?;
                    if n == 0 {
                        return Err(Failure::usage("attempt limit must be positive"));
                    }
                    attempts = Some(n);
                }
                Some("--failures") if failures.is_none() && name == "firmware-restore-simulate" => {
                    failures = Some(
                        value
                            .to_string_lossy()
                            .parse::<u32>()
                            .map_err(Failure::usage_from_display)?,
                    )
                }
                _ => {
                    return Err(Failure::usage(
                        "unknown, duplicate or inapplicable restore option",
                    ));
                }
            }
        }
        return Ok(Command::FirmwareRestore {
            baseline: baseline.ok_or_else(|| Failure::usage("restore requires --baseline"))?,
            backup: backup.ok_or_else(|| Failure::usage("restore requires --backup"))?,
            output: output.ok_or_else(|| Failure::usage("restore requires --output"))?,
            operation: name.into(),
            attempts,
            failures: failures.unwrap_or(0),
            from_normal,
        });
    }
    if name == "__firmware-job-worker" {
        let baseline = args
            .next()
            .ok_or_else(|| Failure::usage("firmware worker requires baseline, assets and Core"))?;
        let assets = args
            .next()
            .ok_or_else(|| Failure::usage("firmware worker requires assets"))?;
        let core = args
            .next()
            .ok_or_else(|| Failure::usage("firmware worker requires Core"))?
            .to_string_lossy()
            .parse()
            .map_err(Failure::usage_from_display)?;
        if args.next().is_some() {
            return Err(Failure::usage("unexpected firmware worker argument"));
        }
        return Ok(Command::FirmwareWorker {
            baseline: baseline.into(),
            assets: assets.into(),
            core,
        });
    }
    if matches!(
        name,
        "__firmware-backup-worker" | "__firmware-gate-close-worker"
    ) {
        let reference = args
            .next()
            .ok_or_else(|| Failure::usage("backup worker requires its baseline directory"))?;
        if args.next().is_some() {
            return Err(Failure::usage("unexpected backup worker argument"));
        }
        return Ok(if name == "__firmware-backup-worker" {
            Command::BackupWorker(reference.into())
        } else {
            Command::GateCloseWorker(reference.into())
        });
    }
    if matches!(
        name,
        "firmware-backup-plan"
            | "firmware-backup-simulate"
            | "firmware-backup-run"
            | "firmware-gate-close-run"
    ) {
        let mut baseline = None;
        let mut output = None;
        while let Some(flag) = args.next() {
            if matches!(flag.to_str(), Some("--help" | "-h")) {
                return Ok(Command::Help);
            }
            let slot = match flag.to_str() {
                Some("--baseline") => &mut baseline,
                Some("--output") => &mut output,
                _ => {
                    return Err(Failure::usage(
                        "backup accepts --baseline and --output only",
                    ));
                }
            };
            if slot.is_some() {
                return Err(Failure::usage("duplicate backup option"));
            }
            *slot = Some(PathBuf::from(
                args.next()
                    .filter(|v| !v.to_string_lossy().starts_with("--"))
                    .ok_or_else(|| Failure::usage("backup option requires a path"))?,
            ));
        }
        if name == "firmware-gate-close-run" {
            return Ok(Command::GateClose {
                baseline: baseline
                    .ok_or_else(|| Failure::usage("gate-close requires --baseline"))?,
                output: output.ok_or_else(|| Failure::usage("gate-close requires --output"))?,
            });
        }
        return Ok(Command::FirmwareBackup {
            baseline: baseline.ok_or_else(|| Failure::usage("backup requires --baseline"))?,
            output: output.ok_or_else(|| Failure::usage("backup requires --output"))?,
            operation: name.into(),
        });
    }
    if matches!(
        name,
        "firmware-job-plan" | "firmware-job-simulate" | "firmware-job-run"
    ) {
        let mut baseline = None;
        let mut directory = None;
        let mut asset_root = None;
        let mut core = None;
        while let Some(flag) = args.next() {
            if matches!(flag.to_str(), Some("--help" | "-h")) {
                return Ok(Command::Help);
            }
            let value = args
                .next()
                .filter(|v| !v.to_string_lossy().starts_with("--"))
                .ok_or_else(|| Failure::usage("firmware option requires a value"))?;
            match flag.to_str() {
                Some("--baseline") if baseline.is_none() => baseline = Some(PathBuf::from(value)),
                Some("--output") if directory.is_none() => directory = Some(PathBuf::from(value)),
                Some("--assets") if asset_root.is_none() => asset_root = Some(PathBuf::from(value)),
                Some("--core") if core.is_none() => {
                    core = Some(
                        value
                            .to_string_lossy()
                            .parse()
                            .map_err(Failure::usage_from_display)?,
                    )
                }
                _ => {
                    return Err(Failure::usage(
                        "firmware job accepts saved baseline, Core, assets and new output only",
                    ));
                }
            }
        }
        return Ok(Command::FirmwareJob {
            baseline: baseline.ok_or_else(|| Failure::usage("firmware job requires --baseline"))?,
            output: directory.ok_or_else(|| Failure::usage("firmware job requires --output"))?,
            assets: asset_root
                .or_else(assets::default_asset_root)
                .ok_or_else(|| Failure::usage("firmware job requires stock assets"))?,
            core: core.ok_or_else(|| Failure::usage("firmware job requires --core"))?,
            operation: name.into(),
        });
    }
    if matches!(name, "prepared-plan" | "prepared-simulate") {
        let mut core = None;
        let mut assets = None;
        let mut json = false;
        while let Some(flag) = args.next() {
            match flag.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--json") if !json => json = true,
                Some("--core") if core.is_none() => {
                    core = Some(
                        args.next()
                            .ok_or_else(|| Failure::usage("--core requires 1, 2, 3 or 4"))?
                            .to_str()
                            .ok_or_else(|| Failure::usage("invalid Core"))?
                            .parse()
                            .map_err(Failure::usage_from_display)?,
                    );
                }
                Some("--assets") if assets.is_none() => {
                    assets = Some(PathBuf::from(
                        args.next()
                            .filter(|v| !v.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| Failure::usage("--assets requires a directory"))?,
                    ));
                }
                _ => {
                    return Err(Failure::usage(
                        "prepared replay accepts --core, --assets and --json only",
                    ));
                }
            }
        }
        return Ok(Command::Prepared {
            core: core.ok_or_else(|| Failure::usage("prepared replay requires --core"))?,
            assets,
            simulate: name == "prepared-simulate",
        });
    }
    if name == "__boot-roundtrip-worker" {
        let baseline = args
            .next()
            .ok_or_else(|| Failure::usage("boot worker requires its baseline directory"))?;
        if args.next().is_some() {
            return Err(Failure::usage("boot worker accepts one baseline directory"));
        }
        return Ok(Command::BootWorker(baseline.into()));
    }
    if matches!(
        name,
        "boot-roundtrip-plan" | "boot-roundtrip-simulate" | "boot-roundtrip-run"
    ) {
        let mut baseline = None;
        let mut output = None;
        let mut scenario = None;
        while let Some(flag) = args.next() {
            let flag = flag
                .to_str()
                .ok_or_else(|| Failure::usage("boot option must be UTF-8"))?;
            if matches!(flag, "--help" | "-h") {
                return Ok(Command::Help);
            }
            if flag == "--scenario" && name == "boot-roundtrip-simulate" && scenario.is_none() {
                let value = args
                    .next()
                    .ok_or_else(|| Failure::usage("scenario name required"))?;
                scenario = Some(
                    boot_roundtrip::Scenario::parse(&value.to_string_lossy())
                        .map_err(Failure::usage)?,
                );
                continue;
            }
            let slot = match flag {
                "--baseline" => &mut baseline,
                "--output" => &mut output,
                _ => {
                    return Err(Failure::usage(
                        "boot round trip accepts a saved baseline and new output directory",
                    ));
                }
            };
            if slot.is_some() {
                return Err(Failure::usage("duplicate boot option"));
            }
            *slot = Some(PathBuf::from(
                args.next()
                    .filter(|value| !value.to_string_lossy().starts_with("--"))
                    .ok_or_else(|| Failure::usage("boot option requires a path"))?,
            ));
        }
        return Ok(Command::BootRoundtrip {
            baseline: baseline
                .ok_or_else(|| Failure::usage("boot round trip requires --baseline"))?,
            output: output.ok_or_else(|| Failure::usage("boot round trip requires --output"))?,
            operation: match name {
                "boot-roundtrip-plan" => BootOperation::Plan,
                "boot-roundtrip-simulate" => {
                    BootOperation::Simulate(scenario.unwrap_or(boot_roundtrip::Scenario::Nominal))
                }
                _ => BootOperation::Run,
            },
        });
    }
    if name == "__w1-worker" {
        let project = args
            .next()
            .ok_or_else(|| Failure::usage("missing W1 worker project"))?;
        let output = args
            .next()
            .ok_or_else(|| Failure::usage("missing W1 worker output"))?;
        if args.next().is_some() {
            return Err(Failure::usage("unexpected W1 worker argument"));
        }
        return Ok(Command::W1 {
            project: project.into(),
            output: output.into(),
            worker: true,
        });
    }
    if name == "w1-run" {
        let tokens: Vec<_> = args.collect();
        if matches!(tokens.as_slice(), [arg] if arg == "--help" || arg == "-h") {
            return Ok(Command::Help);
        }
        if let [p, project, o, output] = tokens.as_slice()
            && p == "--project"
            && o == "--output"
            && !project.to_string_lossy().starts_with("--")
            && !output.to_string_lossy().starts_with("--")
        {
            return Ok(Command::W1 {
                project: project.into(),
                output: output.into(),
                worker: false,
            });
        }
        return Err(Failure::usage(
            "w1-run requires --project FILE --output NEW-DIR",
        ));
    }
    if name == "__access-worker" {
        if args.next().is_some() {
            return Err(Failure::usage("access worker accepts no arguments"));
        }
        return Ok(Command::AccessWorker);
    }
    if matches!(
        name,
        "settings-recovery-replay" | "settings-cycle-simulate" | "button-plan"
    ) {
        let option = args.next();
        if matches!(
            option.as_deref().and_then(|s| s.to_str()),
            Some("--help" | "-h")
        ) {
            return Ok(Command::Help);
        }
        if option.as_deref().and_then(|s| s.to_str()) == Some("--project")
            && let Some(path) = args
                .next()
                .filter(|value| !value.to_string_lossy().starts_with("--"))
            && args.next().is_none()
        {
            let path = PathBuf::from(path);
            return Ok(if name == "settings-recovery-replay" {
                Command::SettingsRecoveryReplay(path)
            } else if name == "settings-cycle-simulate" {
                Command::SettingsCycleSimulate(path)
            } else {
                Command::ButtonPlan(path)
            });
        }
        return Err(Failure::usage(format!("{name} requires --project FILE")));
    }
    if matches!(
        name,
        "access-plan"
            | "access-simulate"
            | "access-run"
            | "access-read-settings"
            | "access-read-recovery"
            | "access-read-boot-bank"
    ) {
        let mut paths: [Option<PathBuf>; 5] = Default::default();
        let mut scenario = None;
        while let Some(arg) = args.next() {
            let key = arg
                .to_str()
                .ok_or_else(|| Failure::usage("access option must be UTF-8"))?;
            if matches!(key, "--help" | "-h") {
                return Ok(Command::Help);
            }
            if key == "--scenario" && name == "access-simulate" && scenario.is_none() {
                let s = args
                    .next()
                    .ok_or_else(|| Failure::usage("scenario name required"))?;
                scenario =
                    Some(AccessScenario::parse(&s.to_string_lossy()).map_err(Failure::usage)?);
                continue;
            }
            let i = match key {
                "--snapshot" => 0,
                "--baseline" => 1,
                "--layout-session" => 2,
                "--headers-session" => 3,
                "--output" => 4,
                _ => {
                    return Err(Failure::usage(
                        "access modes accept fixed saved baselines/output only; no raw addresses, keys, counts, writes, reset or enable flag",
                    ));
                }
            };
            if paths[i].is_some() {
                return Err(Failure::usage("duplicate access option"));
            }
            paths[i] = Some(PathBuf::from(
                args.next()
                    .filter(|v| !v.to_string_lossy().starts_with("--"))
                    .ok_or_else(|| Failure::usage("access option requires a path"))?,
            ));
        }
        let [snapshot, baseline, layout, headers, output] = paths;
        return Ok(Command::Access {
            snapshot: snapshot.ok_or_else(|| Failure::usage("access mode requires --snapshot"))?,
            baseline: baseline.ok_or_else(|| Failure::usage("access mode requires --baseline"))?,
            layout: layout
                .ok_or_else(|| Failure::usage("access mode requires --layout-session"))?,
            headers: headers
                .ok_or_else(|| Failure::usage("access mode requires --headers-session"))?,
            output: output.ok_or_else(|| Failure::usage("access mode requires --output"))?,
            operation: match name {
                "access-plan" => AccessOperation::Plan,
                "access-simulate" => {
                    AccessOperation::Simulate(scenario.unwrap_or(AccessScenario::Nominal))
                }
                "access-read-settings" => AccessOperation::Run(CaptureScope::SettingsPages),
                "access-read-recovery" => AccessOperation::Run(CaptureScope::SettingsRecovery),
                "access-read-boot-bank" => AccessOperation::Run(CaptureScope::BootBank),
                _ => AccessOperation::Run(CaptureScope::Firmware),
            },
        });
    }
    if name == "readback-inspect" {
        let mut layout = None;
        let mut sensitivity = None;
        let mut main = None;
        let mut json = false;
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--json") if !json => json = true,
                Some(
                    option @ ("--layout-reply"
                    | "--sensitivity-header-reply"
                    | "--main-header-reply"),
                ) => {
                    let target = match option {
                        "--layout-reply" => &mut layout,
                        "--sensitivity-header-reply" => &mut sensitivity,
                        _ => &mut main,
                    };
                    if target.is_some() {
                        return Err(Failure::usage("repeated readback input option"));
                    }
                    *target = Some(PathBuf::from(
                        args.next()
                            .filter(|p| !p.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| {
                                Failure::usage("readback input requires a local reply file")
                            })?,
                    ));
                }
                _ => {
                    return Err(Failure::usage(
                        "readback-inspect accepts local reply files and --json only; no hardware/backup/write options",
                    ));
                }
            }
        }
        return Ok(Command::Readback {
            layout: layout
                .ok_or_else(|| Failure::usage("readback-inspect requires --layout-reply"))?,
            sensitivity,
            main,
            json,
        });
    }
    if name == "__query-worker" {
        if args.next().is_some() {
            return Err(Failure::usage("worker accepts no arguments"));
        }
        return Ok(Command::QueryWorker);
    }
    if matches!(
        name,
        "query-info"
            | "query-layout"
            | "query-headers"
            | "query-sensitivity-body"
            | "query-sensitivity-block"
            | "query-sensitivity-memory02"
    ) {
        let mut snapshot = None;
        let mut baseline = None;
        let mut layout_session = None;
        let mut headers_session = None;
        let mut directory = None;
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--snapshot") if snapshot.is_none() => {
                    snapshot = Some(PathBuf::from(
                        args.next()
                            .filter(|v| !v.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| {
                                Failure::usage("--snapshot requires a saved P1 JSON path")
                            })?,
                    ))
                }
                Some("--baseline") if name != "query-info" && baseline.is_none() => {
                    baseline = Some(PathBuf::from(
                        args.next()
                            .filter(|v| !v.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| {
                                Failure::usage("--baseline needs a successful saved info session")
                            })?,
                    ));
                }
                Some("--layout-session")
                    if matches!(
                        name,
                        "query-headers"
                            | "query-sensitivity-body"
                            | "query-sensitivity-block"
                            | "query-sensitivity-memory02"
                    ) && layout_session.is_none() =>
                {
                    layout_session = Some(PathBuf::from(
                        args.next()
                            .filter(|v| !v.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| {
                                Failure::usage(
                                    "--layout-session requires a successful saved layout session",
                                )
                            })?,
                    ));
                }
                Some("--headers-session")
                    if matches!(
                        name,
                        "query-sensitivity-body"
                            | "query-sensitivity-block"
                            | "query-sensitivity-memory02"
                    ) && headers_session.is_none() =>
                {
                    headers_session = Some(PathBuf::from(
                        args.next()
                            .filter(|v| !v.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| {
                                Failure::usage(
                                    "--headers-session requires a successful saved header session",
                                )
                            })?,
                    ));
                }
                Some("--output") if directory.is_none() => {
                    directory = Some(PathBuf::from(
                        args.next()
                            .filter(|v| !v.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| Failure::usage("--output requires a new directory"))?,
                    ))
                }
                _ => {
                    return Err(Failure::usage(
                        "queries require saved baselines appropriate to their mode and a new --output; no raw device/command/address/count options",
                    ));
                }
            }
        }
        if matches!(
            name,
            "query-sensitivity-body" | "query-sensitivity-block" | "query-sensitivity-memory02"
        ) {
            return Ok(Command::QueryBody {
                snapshot: snapshot
                    .ok_or_else(|| Failure::usage(format!("{name} requires --snapshot")))?,
                baseline: baseline
                    .ok_or_else(|| Failure::usage(format!("{name} requires --baseline")))?,
                layout_session: layout_session
                    .ok_or_else(|| Failure::usage(format!("{name} requires --layout-session")))?,
                headers_session: headers_session
                    .ok_or_else(|| Failure::usage(format!("{name} requires --headers-session")))?,
                block: name == "query-sensitivity-block",
                memory02: name == "query-sensitivity-memory02",
                output: directory
                    .ok_or_else(|| Failure::usage(format!("{name} requires --output")))?,
            });
        }
        if name == "query-headers" {
            return Ok(Command::QueryHeaders {
                snapshot: snapshot
                    .ok_or_else(|| Failure::usage("query-headers requires --snapshot"))?,
                baseline: baseline
                    .ok_or_else(|| Failure::usage("query-headers requires --baseline"))?,
                layout_session: layout_session
                    .ok_or_else(|| Failure::usage("query-headers requires --layout-session"))?,
                output: directory
                    .ok_or_else(|| Failure::usage("query-headers requires --output"))?,
            });
        }
        if name == "query-layout" {
            return Ok(Command::QueryLayout {
                snapshot: snapshot
                    .ok_or_else(|| Failure::usage("query-layout requires --snapshot"))?,
                baseline: baseline
                    .ok_or_else(|| Failure::usage("query-layout requires --baseline"))?,
                output: directory
                    .ok_or_else(|| Failure::usage("query-layout requires --output"))?,
            });
        }
        return Ok(Command::QueryInfo {
            snapshot: snapshot.ok_or_else(|| Failure::usage("query-info requires --snapshot"))?,
            output: directory.ok_or_else(|| Failure::usage("query-info requires --output"))?,
        });
    }
    if name == "discover-passive" {
        let mut root = None;
        let mut output = None;
        let mut json = false;
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--json") if !json => json = true,
                Some("--sysfs-root") if root.is_none() => {
                    root = Some(PathBuf::from(
                        args.next()
                            .filter(|value| !value.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| Failure::usage("--sysfs-root needs a directory"))?,
                    ));
                }
                Some("--output") if output.is_none() => {
                    output = Some(PathBuf::from(
                        args.next()
                            .filter(|value| !value.to_string_lossy().starts_with("--"))
                            .ok_or_else(|| {
                                Failure::usage(
                                    "--output needs a new directory; its parent must exist",
                                )
                            })?,
                    ));
                }
                _ => {
                    return Err(Failure::usage(
                        "unknown/repeated discover-passive option; no raw-device option is supported",
                    ));
                }
            }
        }
        return Ok(Command::Passive {
            root: root.unwrap_or_else(|| PathBuf::from("/sys")),
            output,
            json,
        });
    }
    if name == "query-audit" {
        let mut json = false;
        for arg in args {
            match arg.to_str() {
                Some("--help" | "-h") => return Ok(Command::Help),
                Some("--json") if !json => json = true,
                _ => {
                    return Err(Failure::usage(
                        "query-audit accepts only --json or --help; it performs no device I/O",
                    ));
                }
            }
        }
        return Ok(Command::QueryAudit { json });
    }
    if !matches!(name, "inspect" | "tui" | "plan" | "simulate" | "preview") {
        return Err(Failure::usage(format!(
            "unknown command {name:?}; use --help"
        )));
    }
    let mut options = Options {
        assets: None,
        core: None,
        project: None,
        workflow_model: false,
        workflow_session: None,
        json: false,
        simulation: SimulationConfig::nominal(),
    };
    let mut scenario = None;
    let mut record_index = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--assets") if !matches!(name, "preview" | "tui") && options.assets.is_none() => {
                let path = args
                    .next()
                    .filter(|value| !value.to_string_lossy().starts_with("--"))
                    .ok_or_else(|| Failure::usage("--assets needs an application directory"))?;
                options.assets = Some(PathBuf::from(path));
            }
            Some("--core") if name != "preview" && options.core.is_none() => {
                let value = args
                    .next()
                    .ok_or_else(|| Failure::usage("--core needs 1, 2, 3 or 4"))?;
                options.core = Some(
                    value
                        .to_str()
                        .ok_or_else(|| Failure::usage("invalid Core"))?
                        .parse()
                        .map_err(Failure::usage_from_display)?,
                );
            }
            Some("--project") if matches!(name, "preview" | "tui") && options.project.is_none() => {
                options.project = Some(PathBuf::from(
                    args.next()
                        .filter(|value| !value.to_string_lossy().starts_with("--"))
                        .ok_or_else(|| Failure::usage("--project needs a local JSON file"))?,
                ));
            }
            Some("--restore-session") if name == "tui" => {
                if options.workflow_session.is_some() {
                    return Err(Failure::usage("repeated workflow path"));
                }
                options.workflow_session = Some(PathBuf::from(
                    args.next()
                        .filter(|v| !v.to_string_lossy().starts_with("--"))
                        .ok_or_else(|| Failure::usage("workflow option needs a path"))?,
                ));
            }
            Some("--workflow-model") if name == "tui" && !options.workflow_model => {
                options.workflow_model = true
            }
            Some("--json") if name != "tui" && !options.json => options.json = true,
            Some("--scenario") if name == "simulate" && scenario.is_none() => {
                let value = args
                    .next()
                    .ok_or_else(|| Failure::usage("--scenario needs a name"))?;
                scenario = Some(
                    value
                        .to_str()
                        .ok_or_else(|| Failure::usage("invalid scenario"))?
                        .parse::<Scenario>()
                        .map_err(Failure::usage)?,
                );
            }
            Some("--record-index") if name == "simulate" && record_index.is_none() => {
                let value = args
                    .next()
                    .ok_or_else(|| Failure::usage("--record-index needs an integer"))?;
                record_index = Some(
                    value
                        .to_str()
                        .and_then(|text| text.parse::<usize>().ok())
                        .ok_or_else(|| {
                            Failure::usage("--record-index needs a nonnegative integer")
                        })?,
                );
            }
            _ => {
                return Err(Failure::usage(format!(
                    "unknown or repeated option {:?}; use --help",
                    arg
                )));
            }
        }
    }
    if matches!(name, "plan" | "simulate") && options.core.is_none() {
        return Err(Failure::usage("plan/simulate requires --core 1, 2, 3 or 4"));
    }
    if name == "simulate" {
        options.simulation =
            SimulationConfig::new(scenario.unwrap_or(Scenario::Nominal), record_index)
                .map_err(Failure::usage)?;
    }
    Ok(match name {
        "inspect" => Command::Inspect(options),
        "tui" => Command::Tui(options),
        "plan" => Command::Plan(options),
        "simulate" => Command::Simulate(options),
        "preview" => Command::Preview {
            project: options
                .project
                .ok_or_else(|| Failure::usage("preview requires --project FILE"))?,
            json: options.json,
        },
        _ => unreachable!("validated command"),
    })
}

impl Failure {
    fn usage_from_display(error: impl std::fmt::Display) -> Self {
        Self::usage(error.to_string())
    }
}

#[derive(Serialize)]
struct InspectionReport<'a> {
    schema_version: u32,
    mode: &'static str,
    asset_root: String,
    provenance: &'a str,
    scope: &'a str,
    images: Vec<Inspection>,
    limitations: [&'static str; 3],
}

fn run() -> Result<(), Failure> {
    let command = parse(env::args_os().skip(1))?;
    let (options, tui) = match command {
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
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return Ok(());
        }
        Command::LightingStatus { model } => {
            let input = ratmax::workflow::Workspace::resolve_default().map_err(Failure::operation)?;
            let workspace =
                ratmax::workflow::Workspace::load(&input).map_err(Failure::operation)?;
            let status =
                ratmax::lighting::read_status(&workspace, model).map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&status).map_err(Failure::operation)? + "\n"))?;
            return Ok(());
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
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return Ok(());
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
                _ => {
                    ratmax::workflow::prepare(&input, &directory, operation == "workflow-simulate")
                }
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if operation == "workflow-plan" || report["complete"] == true {
                Ok(())
            } else {
                Err(Failure::operation(
                    "workflow incomplete; restoration status is in cycle.json",
                ))
            };
        }

        Command::PresetWorker(path) => {
            return boot_roundtrip::pipeline::worker(&path).map_err(Failure::operation);
        }
        Command::PresetCycle {
            input,
            output: directory,
            operation,
        } => {
            let physical = matches!(
                operation.as_str(),
                "preset-cycle-run" | "preset-cycle-restore"
            );
            let report = match operation.as_str() {
                "preset-cycle-run" => boot_roundtrip::pipeline::run(&input, &directory),
                "preset-cycle-restore" => boot_roundtrip::pipeline::restore(&input, &directory),
                _ => boot_roundtrip::pipeline::prepare(
                    &input,
                    &directory,
                    operation == "preset-cycle-simulate",
                ),
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if !physical || report["complete"] == true {
                Ok(())
            } else {
                Err(Failure::operation(
                    "preset cycle incomplete; original restoration status is in the saved result",
                ))
            };
        }
        Command::GateClose {
            baseline,
            output: directory,
        } => {
            let report = boot_roundtrip::run_gate_close(&baseline, &directory)
                .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if report["result"]["complete"] == true {
                Ok(())
            } else {
                Err(Failure::operation("gate-close incomplete"))
            };
        }
        Command::GateCloseWorker(reference) => {
            return boot_roundtrip::worker_gate_close(&reference).map_err(Failure::operation);
        }
        Command::BackupWorker(reference) => {
            return boot_roundtrip::worker_backup(&reference).map_err(Failure::operation);
        }
        Command::FirmwareBackup {
            baseline,
            output: directory,
            operation,
        } => {
            let report = if operation == "firmware-backup-run" {
                boot_roundtrip::run_backup(&baseline, &directory)
            } else {
                boot_roundtrip::prepare_backup(
                    &baseline,
                    &directory,
                    operation == "firmware-backup-simulate",
                )
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if operation == "firmware-backup-run" && report["result"]["complete"] != true {
                Err(Failure::operation(
                    "normal firmware backup incomplete; inspect session state",
                ))
            } else {
                Ok(())
            };
        }
        Command::TargetReturnWorker {
            baseline,
            backup,
            proof,
            entry,
            boot,
        } => {
            return boot_roundtrip::target_return::worker(
                &baseline,
                &backup,
                &proof,
                entry.as_deref(),
                boot,
            )
            .map_err(Failure::operation);
        }
        Command::TargetReturn {
            baseline,
            backup,
            prepared,
            core,
            output: directory,
            operation,
        } => {
            let report = if operation == "firmware-return-run" {
                boot_roundtrip::target_return::run(
                    &baseline,
                    &backup,
                    prepared.as_deref().ok_or_else(|| {
                        Failure::usage("native target return requires forward session")
                    })?,
                    &directory,
                )
            } else {
                boot_roundtrip::target_return::prepare(
                    &baseline,
                    &backup,
                    prepared.as_deref(),
                    core,
                    &directory,
                    operation == "firmware-return-simulate",
                )
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if operation == "firmware-return-run" && report["complete"] != true {
                Err(Failure::operation(
                    "prepared-target backup return incomplete; inspect entry, cleanup and restore reports",
                ))
            } else {
                Ok(())
            };
        }
        Command::BootReadbackWorker { baseline, backup } => {
            return boot_roundtrip::readback::worker(&baseline, &backup)
                .map_err(Failure::operation);
        }
        Command::BootReadback {
            baseline,
            backup,
            output: directory,
            operation,
        } => {
            let report = if operation == "boot-readback-run" {
                boot_roundtrip::readback::run(&baseline, &backup, &directory)
            } else {
                boot_roundtrip::readback::prepare(
                    &baseline,
                    &backup,
                    &directory,
                    operation == "boot-readback-simulate",
                )
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if operation == "boot-readback-run" && report["complete"] != true {
                Err(Failure::operation(
                    "boot readback incomplete; inspect capture and entry-return reports",
                ))
            } else {
                Ok(())
            };
        }
        Command::EntryReturnWorker {
            baseline,
            proof,
            mode,
        } => {
            return boot_roundtrip::worker_entry_return(&baseline, &proof, mode)
                .map_err(Failure::operation);
        }
        Command::RestoreWorker {
            baseline,
            backup,
            from_normal,
        } => {
            return boot_roundtrip::worker_restore(&baseline, &backup, from_normal)
                .map_err(Failure::operation);
        }
        Command::FirmwareRestore {
            baseline,
            backup,
            output: directory,
            operation,
            attempts,
            failures,
            from_normal,
        } => {
            let report = if operation == "firmware-restore-run" {
                boot_roundtrip::run_restore(&baseline, &backup, &directory, attempts, from_normal)
            } else {
                boot_roundtrip::prepare_restore(
                    &baseline,
                    &backup,
                    &directory,
                    operation == "firmware-restore-simulate",
                    failures,
                    attempts,
                    from_normal,
                )
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if operation == "firmware-restore-run" && report["complete"] != true {
                Err(Failure::operation(
                    "backup restoration incomplete; inspect attempts and retained lock",
                ))
            } else {
                Ok(())
            };
        }
        Command::FirmwareWorker {
            baseline,
            assets,
            core,
        } => {
            return boot_roundtrip::worker_firmware(&baseline, &assets, core)
                .map_err(Failure::operation);
        }
        Command::FirmwareJob {
            baseline,
            assets,
            core,
            output: directory,
            operation,
        } => {
            let report = if operation == "firmware-job-run" {
                boot_roundtrip::run_firmware(&baseline, &directory, &assets, core)
            } else {
                boot_roundtrip::prepare_firmware(
                    &baseline,
                    &directory,
                    &assets,
                    core,
                    operation == "firmware-job-simulate",
                )
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if operation == "firmware-job-run" && report["result"]["complete"] != true {
                Err(Failure::operation(
                    "firmware job incomplete; inspect retained state and lock",
                ))
            } else {
                Ok(())
            };
        }
        Command::Prepared {
            core,
            assets: root,
            simulate,
        } => {
            let root = root
                .or_else(assets::default_asset_root)
                .ok_or_else(|| Failure::operation("stock assets not found; use --assets"))?;
            let image = Manifest::embedded()
                .map_err(Failure::operation)?
                .inspect_file(&root, core)
                .map_err(Failure::operation)?;
            let plan = ratmax::prepared::Plan::new(image).map_err(Failure::operation)?;
            let report = if simulate {
                serde_json::json!({
                    "plan": plan.summary(),
                    "simulations":ratmax::prepared::Scenario::ALL.map(|scenario| plan.simulate(scenario)),
                })
            } else {
                serde_json::to_value(plan.summary()).map_err(Failure::operation)?
            };
            return output(
                &(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"),
            );
        }
        Command::AccessWorker => return access_session::worker_main().map_err(Failure::operation),
        Command::BootWorker(baseline) => {
            return boot_roundtrip::worker(&baseline).map_err(Failure::operation);
        }
        Command::BootRoundtrip {
            baseline,
            output: directory,
            operation,
        } => {
            let report = match operation {
                BootOperation::Plan => boot_roundtrip::prepare(&baseline, &directory, None),
                BootOperation::Simulate(scenario) => {
                    boot_roundtrip::prepare(&baseline, &directory, Some(scenario))
                }
                BootOperation::Run => boot_roundtrip::run(&baseline, &directory),
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            if matches!(operation, BootOperation::Run) && report["result"]["complete"] != true {
                return Err(Failure::operation(
                    "boot round trip incomplete; inspect marker, mode and lock state",
                ));
            }
            return Ok(());
        }
        Command::W1 {
            project,
            output: directory,
            worker,
        } => {
            if worker {
                return w1::worker(&project, &directory).map_err(Failure::operation);
            }
            let report = w1::run(&project, &directory).map_err(Failure::operation)?;
            let json = serde_json::to_string_pretty(&report).map_err(Failure::operation)?;
            output(&(json + "\n"))?;
            return if report["complete"] == true {
                Ok(())
            } else {
                Err(Failure::operation(
                    "W1 incomplete; inspect the measured session and lock state",
                ))
            };
        }
        Command::SettingsRecoveryReplay(project) => {
            let report = recovery::load(&project).map_err(Failure::operation)?;
            let json = serde_json::to_string_pretty(&report).map_err(Failure::operation)?;
            return output(&(json + "\n"));
        }
        Command::SettingsCycleSimulate(project) => {
            let report = settings_cycle::load(&project).map_err(Failure::operation)?;
            let json = serde_json::to_string_pretty(&report).map_err(Failure::operation)?;
            return output(&(json + "\n"));
        }
        Command::ButtonPlan(project) => {
            let report = ratmax::button_plan::load(&project).map_err(Failure::operation)?;
            let json = serde_json::to_string_pretty(&report).map_err(Failure::operation)?;
            return output(&(json + "\n"));
        }
        Command::ButtonCycle {
            project,
            baseline,
            output: directory,
            fault,
            physical,
            read_only,
            observe_seconds,
        } => {
            let report = if physical {
                ratmax::button_cycle::run_observed(
                    &project,
                    &baseline,
                    &directory,
                    if read_only { 0 } else { observe_seconds },
                    read_only,
                )
            } else {
                ratmax::button_cycle::simulate(&project, &baseline, &directory, &fault)
            }
            .map_err(Failure::operation)?;
            let json = serde_json::to_string_pretty(&report).map_err(Failure::operation)?;
            output(&(json + "\n"))?;
            return if !physical || report["complete"] == true {
                Ok(())
            } else {
                Err(Failure::operation(
                    "button cycle incomplete; inspect saved state and retained lease",
                ))
            };
        }
        Command::ButtonCycleWorker { source, proof } => {
            return ratmax::button_cycle::worker(&source, proof.as_deref())
                .map_err(Failure::operation);
        }
        Command::ButtonRestore {
            session,
            output: directory,
        } => {
            let report =
                ratmax::button_cycle::restore(&session, &directory).map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if report["complete"] == true {
                Ok(())
            } else {
                Err(Failure::operation(
                    "restoration incomplete; retain the session and retry the whole original-page restore",
                ))
            };
        }
        Command::Access {
            snapshot,
            baseline,
            layout,
            headers,
            output: directory,
            operation,
        } => {
            let value = match operation {
                AccessOperation::Run(scope) => {
                    access_session::run(&snapshot, &baseline, &layout, &headers, &directory, scope)
                }
                _ => query_session::load_access_baseline(&snapshot, &baseline, &layout, &headers)
                    .and_then(|b| {
                        access_session::prepare(
                            b,
                            &directory,
                            match operation {
                                AccessOperation::Simulate(s) => Some(s),
                                _ => None,
                            },
                        )
                    }),
            }
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&value).map_err(Failure::operation)? + "\n"))?;
            if matches!(operation, AccessOperation::Run(_)) && value["result"]["complete"] != true {
                return Err(Failure::operation(
                    "access job incomplete; inspect cleanup/uncertainty evidence",
                ));
            }
            return Ok(());
        }
        Command::Help => {
            let scenarios = Scenario::ALL.map(Scenario::name).join("\n  ");
            return output(&format!("{HELP}\nSimulation scenarios:\n  {scenarios}\n"));
        }
        Command::Readback {
            layout,
            sensitivity,
            main,
            json,
        } => {
            let layout = read_offline_reply(&layout)?;
            let sensitivity = sensitivity.as_deref().map(read_offline_reply).transpose()?;
            let main = main.as_deref().map(read_offline_reply).transpose()?;
            let inspection =
                readback::OfflineInspection::new(&layout, sensitivity.as_deref(), main.as_deref())
                    .map_err(Failure::operation)?;
            return output(&if json {
                serde_json::to_string_pretty(&inspection).map_err(Failure::operation)? + "\n"
            } else {
                inspection.text()
            });
        }
        Command::QueryWorker => return query_session::worker_main().map_err(Failure::operation),
        Command::QueryBody {
            snapshot,
            baseline,
            layout_session,
            headers_session,
            block,
            memory02,
            output: directory,
        } => {
            let execute = if memory02 {
                query_session::query_sensitivity_memory02
            } else if block {
                query_session::query_sensitivity_block
            } else {
                query_session::query_sensitivity_body
            };
            let report = execute(
                &snapshot,
                &baseline,
                &layout_session,
                &headers_session,
                &directory,
            )
            .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if report.complete {
                Ok(())
            } else {
                Err(Failure::operation(
                    report
                        .failure
                        .as_deref()
                        .unwrap_or("sensitivity body session incomplete"),
                ))
            };
        }
        Command::QueryHeaders {
            snapshot,
            baseline,
            layout_session,
            output: directory,
        } => {
            let report =
                query_session::query_headers(&snapshot, &baseline, &layout_session, &directory)
                    .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if report.complete {
                Ok(())
            } else {
                Err(Failure::operation(
                    report
                        .failure
                        .as_deref()
                        .unwrap_or("header session incomplete"),
                ))
            };
        }
        Command::QueryLayout {
            snapshot,
            baseline,
            output: directory,
        } => {
            let report = query_session::query_layout(&snapshot, &baseline, &directory)
                .map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if report.complete {
                Ok(())
            } else {
                Err(Failure::operation(
                    report
                        .failure
                        .as_deref()
                        .unwrap_or("descriptor session incomplete"),
                ))
            };
        }
        Command::QueryInfo {
            snapshot,
            output: directory,
        } => {
            let report =
                query_session::query_info(&snapshot, &directory).map_err(Failure::operation)?;
            output(&(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"))?;
            return if report.complete {
                Ok(())
            } else {
                Err(Failure::operation(
                    report
                        .failure
                        .as_deref()
                        .unwrap_or("query session incomplete"),
                ))
            };
        }
        Command::Inspect(options) => (options, false),
        Command::Tui(options) => (options, true),
        Command::Preview { project, json } => {
            let report = preview::load(&project).map_err(Failure::operation)?;
            return output(&if json {
                serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"
            } else {
                report.text()
            });
        }
        Command::Plan(options) => return run_plan(options, false),
        Command::Simulate(options) => return run_plan(options, true),
        Command::QueryAudit { json } => {
            let audit = queries::audit();
            return output(&if json {
                serde_json::to_string_pretty(&audit).map_err(Failure::operation)? + "\n"
            } else {
                audit.text()
            });
        }
        Command::Passive {
            root,
            output: directory,
            json,
        } => {
            let report = discovery::collect(&root).map_err(Failure::operation)?;
            if let Some(directory) = directory {
                report.save(&directory).map_err(Failure::operation)?;
            }
            output(&if json {
                serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"
            } else {
                report.text()
            })?;
            return if report.complete() {
                Ok(())
            } else {
                Err(Failure::operation(
                    "passive report is incomplete; see retained collection/descriptor errors",
                ))
            };
        }
    };
    if tui {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(Failure::usage(
                "tui requires an interactive terminal; use inspect --json for noninteractive output",
            ));
        }
        let workspace_path = ratmax::workflow::Workspace::default_path();
        if (options.workflow_model || options.workflow_session.is_some())
            && workspace_path.is_none()
        {
            return Err(Failure::usage(
                "workflow options require RATMAX_WORKSPACE or ~/.config/ratmax/workspace.json",
            ));
        }
        return ratmax::tui::run(
            options.core.unwrap_or(if workspace_path.is_some() {
                Core::Three
            } else {
                Core::One
            }),
            options.project,
            workspace_path.map(|workspace| ratmax::tui::WorkflowOptions {
                workspace,
                model: options.workflow_model,
                session: options.workflow_session,
            }),
        )
        .map_err(Failure::operation);
    }
    let root = options
        .assets
        .or_else(assets::default_asset_root)
        .ok_or_else(|| {
            Failure::usage(
                "application directory not found; use --assets PATH (directory containing FW/)",
            )
        })?;
    let manifest = Manifest::embedded().map_err(Failure::operation)?;
    let cores = options
        .core
        .map_or_else(|| Core::ALL.to_vec(), |core| vec![core]);
    let images = cores
        .into_iter()
        .map(|core| {
            manifest
                .inspect_file(&root, core)
                .map(|image| image.inspection().clone())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Failure::operation)?;
    let report = InspectionReport {
        schema_version: 1,
        mode: "offline",
        asset_root: root.to_string_lossy().into_owned(),
        provenance: manifest.provenance(),
        scope: manifest.scope(),
        images,
        limitations: [
            "No device accessed; model/Core describe assets, not the connected mouse.",
            "64-byte local buffers are reconstructed; actual device report length is unknown.",
            "Encoded payloads are unchanged; preflight, responses, finalization and reset are absent.",
        ],
    };
    if options.json {
        return output(
            &(serde_json::to_string_pretty(&report).map_err(Failure::operation)? + "\n"),
        );
    }
    let mut text = format!(
        "ratmax | OFFLINE | {}\nAssets: {}\n",
        manifest.model(),
        root.display()
    );
    for info in report.images {
        text.push_str(&format!(
            "\n{} -> firmware index {}: verified local asset\n  {}\n  {} bytes | {} encoded records\n  Source SHA-256: {}\n  Local buffers: {} x {} = {} bytes\n  Buffer SHA-256: {}\n  Encoded ranges: [0x0000,0x5460), [0x7FE0,0xFF00)\n",
            info.core, info.firmware_index.get(), info.source, info.source_bytes, info.record_count,
            info.source_sha256, info.record_count, info.local_buffer_length,
            info.scratch_buffer_bytes, info.scratch_buffer_sha256,
        ));
    }
    text.push_str("\nDevice report length: UNKNOWN. No device accessed.\nBuffers are offline reconstructions; payloads remain encoded.\n");
    output(&text)
}

/// Bounded local-artifact input, separate from every HID/sysfs entry point.
fn read_offline_reply(path: &std::path::Path) -> Result<Vec<u8>, Failure> {
    let canonical = path.canonicalize().map_err(Failure::operation)?;
    if ["/sys", "/dev", "/proc"]
        .iter()
        .any(|p| canonical.starts_with(p))
    {
        return Err(Failure::operation(
            "readback input must be a local artifact outside /sys, /dev and /proc",
        ));
    }
    if !std::fs::symlink_metadata(path)
        .map_err(Failure::operation)?
        .is_file()
    {
        return Err(Failure::operation(
            "readback input must be a regular local file, not a symlink/directory/device",
        ));
    }
    let file = std::fs::File::open(&canonical).map_err(Failure::operation)?;
    if !file.metadata().map_err(Failure::operation)?.is_file() {
        return Err(Failure::operation(
            "opened readback artifact is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take((readback::FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(Failure::operation)?;
    if bytes.len() != readback::FRAME_BYTES {
        return Err(Failure::operation(
            "readback reply artifact must contain exactly 64 bytes",
        ));
    }
    Ok(bytes)
}

fn run_plan(options: Options, simulate: bool) -> Result<(), Failure> {
    let root = options
        .assets
        .or_else(assets::default_asset_root)
        .ok_or_else(|| Failure::usage("application directory not found; use --assets PATH"))?;
    let manifest = Manifest::embedded().map_err(Failure::operation)?;
    let image = manifest
        .inspect_file(
            &root,
            options.core.expect("explicit Core required by parser"),
        )
        .map_err(Failure::operation)?;
    let plan = FirmwarePlan::new(image);
    if simulate {
        let result = simulation::simulate(&plan, options.simulation);
        return output(&if options.json {
            serde_json::to_string_pretty(&result).map_err(Failure::operation)? + "\n"
        } else {
            result.text()
        });
    }
    output(&if options.json {
        plan.json().map_err(Failure::operation)? + "\n"
    } else {
        plan.text()
    })
}

fn output(text: &str) -> Result<(), Failure> {
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(Failure::operation)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(io::stderr().lock(), "ratmax: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}
