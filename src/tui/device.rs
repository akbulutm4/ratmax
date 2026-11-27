//! Simplified Mouse tab + shared review/progress modal for all TUI tabs.
use crate::{
    boot_roundtrip::{self, Mode},
    macros::Target,
    model::Core,
    workflow::{
        self, Button, CurrentConfiguration, CurrentControl, ExtraControl, Operation, Settings,
        Workspace,
    },
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct WorkflowOptions {
    pub workspace: PathBuf,
    pub model: bool,
    pub session: Option<PathBuf>,
}

struct Review {
    project: Option<PathBuf>,
    output: PathBuf,
    restore: Option<PathBuf>,
    model: bool,
    title: String,
    lines: Vec<String>,
    clear_pending_on_success: bool,
}

struct Active {
    child: Child,
    output: PathBuf,
    stop_root: PathBuf,
    previous_last: Option<PathBuf>,
    model: bool,
    cancel_requested: bool,
    inspection: bool,
    clear_pending_on_success: bool,
}

struct InitPrompt {
    detected: crate::init::DetectedMouse,
    assets: Result<PathBuf, String>,
    data_dir: PathBuf,
    reason: String,
}

struct InitActive {
    child: Child,
    progress_file: PathBuf,
    stdout_file: PathBuf,
    stderr_file: PathBuf,
}

enum State {
    Ready,
    InitPrompt(Box<InitPrompt>),
    Initializing(InitActive),
    Review(Review),
    Running(Active),
}

const TOTAL_ROWS: usize = 15; // 0..=4 DPI, 5 Rate, 6 Core, 7 Shooting, 8..=14 Buttons

pub(super) struct Panel {
    options: WorkflowOptions,
    workspace: Result<Workspace, String>,
    detected_uninitialized: Option<crate::init::DetectedMouse>,
    init_assets: Option<Result<PathBuf, String>>,
    core: Core,
    entry: Option<Mode>,
    settings: Settings,
    row: usize,
    cpi_edit: Option<String>,
    state: State,
    message: Option<(String, bool)>,
    last: Option<PathBuf>,
    native_budget: Option<PathBuf>,
    model_budget: Option<PathBuf>,
    current: Option<CurrentConfiguration>,
}

impl Panel {
    pub(super) fn new(options: WorkflowOptions, core: Core) -> Self {
        let workspace = Workspace::load(&options.workspace);
        let settings = empty_settings();
        let last = options.session.clone();
        let mut p = Self {
            options,
            workspace,
            detected_uninitialized: None,
            init_assets: None,
            core,
            entry: None,
            settings,
            row: 0,
            cpi_edit: None,
            state: State::Ready,
            message: None,
            last,
            native_budget: None,
            model_budget: None,
            current: None,
        };
        p.refresh();
        if p.workspace.is_err() && !p.options.model {
            p.probe_uninitialized(true);
        }
        if p.last.is_none()
            && let Ok(w) = &p.workspace
        {
            let name = if p.options.model {
                "last-model-session.json"
            } else {
                "last-native-session.json"
            };
            if let Ok(value) = read_json(&w.sessions.join(name)) {
                p.last = value["session"].as_str().map(PathBuf::from);
            }
        }
        if let (Some(last), Ok(workspace)) = (&p.last, &p.workspace)
            && let Ok(report) = read_json(&last.join("cycle.json"))
                .or_else(|_| read_json(&last.join("run-intent.json")))
            && let Some(root) = report["budget_root"].as_str()
            && let Ok(reference) = boot_roundtrip::load(&workspace.baseline)
            && let Ok(backup_plan) = crate::backup_restore::Plan::load(&workspace.backup)
            && workflow::validate_budget(
                Path::new(root),
                &reference.baseline.fingerprint(),
                backup_plan.sha256(),
                !p.options.model,
            )
            .is_ok()
        {
            if p.options.model {
                if report["desired_configuration_kept"] == true {
                    p.entry = serde_json::from_value(report["result"]["mode"].clone()).ok();
                }
                p.model_budget = Some(root.into());
            } else {
                p.native_budget = Some(root.into());
            }
        }
        p.sync_core_to_installed();
        p
    }

    pub(super) fn installed_mode(&self) -> Option<Mode> {
        self.entry
    }

    pub(super) fn installed_core(&self) -> Option<Core> {
        match self.entry {
            Some(Mode::Normal) => Some(Core::One),
            Some(Mode::Target(c)) => Some(c),
            _ => None,
        }
    }

    fn effective_mode(&self) -> Mode {
        if self.will_flash() {
            Mode::Target(self.core)
        } else {
            self.entry.unwrap_or(Mode::Target(self.core))
        }
    }

    fn sanitize_for_mode(&mut self) -> bool {
        let mode = self.effective_mode();
        let mut cleared = false;
        if !workflow::shooting_supported(mode) && self.settings.shooting_slot.is_some() {
            self.settings.shooting_slot = None;
            cleared = true;
        }
        for slot in self
            .settings
            .side_buttons
            .iter_mut()
            .chain(self.settings.extra_buttons.iter_mut())
        {
            if !slot.supported(mode) {
                *slot = Button::Preserve;
                cleared = true;
            }
        }
        cleared
    }

    pub(super) fn installed_lighting(&self) -> Option<&crate::lighting::PersistentLighting> {
        self.current.as_ref()?.custom_lighting.as_ref()
    }

    pub(super) fn installed_macro_buttons(&self) -> Vec<Target> {
        let Some(cur) = &self.current else {
            return vec![];
        };
        if !cur.button_macros.is_empty() {
            cur.button_macros.iter().map(|m| m.button).collect()
        } else if let Some(m) = &cur.button_macro {
            vec![m.button]
        } else {
            vec![]
        }
    }

    pub(super) fn header_status(&self) -> (&'static str, String, Color) {
        if matches!(self.state, State::Initializing(_)) {
            return ("●", "Initializing…".into(), Color::Yellow);
        }
        if self.running() {
            return ("●", "Working…".into(), Color::Yellow);
        }
        if self.options.model {
            let core_str = self
                .installed_core()
                .map_or("Core ?".into(), |c| format!("Core {}", c.number()));
            return ("●", format!("Model · W95 Max ({core_str})"), Color::Yellow);
        }
        if self.workspace.is_err() {
            if let Some(det) = &self.detected_uninitialized {
                return (
                    "●",
                    format!("W95 Max · {} (Needs Init)", det.mode_label()),
                    Color::Yellow,
                );
            }
            return ("○", "Needs initialization".into(), Color::Yellow);
        }
        match self.entry {
            Some(Mode::Normal) => ("●", "W95 Max · Original Core 1".into(), Color::Green),
            Some(Mode::Target(c)) => (
                "●",
                format!("W95 Max · Core {}", c.number()),
                Color::Green,
            ),
            _ => ("○", "Mouse not detected".into(), Color::Red),
        }
    }

    pub(super) fn modal_active(&self) -> bool {
        !matches!(self.state, State::Ready) || self.cpi_edit.is_some()
    }

    pub(super) fn running(&self) -> bool {
        matches!(self.state, State::Running(_) | State::Initializing(_))
    }

    pub(super) fn startup_read(&mut self) {
        if self.workspace.is_err() || matches!(self.state, State::InitPrompt(_)) {
            return;
        }
        if let Err(error) = self.read_current() {
            self.message = Some((error, true));
        }
    }

    pub(super) fn trigger_refresh(&mut self) {
        if self.workspace.is_err() {
            self.workspace = Workspace::load(&self.options.workspace);
            if self.workspace.is_err() {
                if !self.options.model {
                    self.probe_uninitialized(true);
                }
                return;
            }
            self.detected_uninitialized = None;
            self.init_assets = None;
        }
        self.refresh();
        if let Err(e) = self.read_current() {
            self.message = Some((e, true));
        }
    }

    fn probe_uninitialized(&mut self, open_prompt: bool) {
        let assets = crate::init::resolve_assets(None, Some(&self.options.workspace));
        self.init_assets = Some(assets.clone());
        match crate::init::detect_mouse() {
            Ok(Some(detected)) => {
                self.detected_uninitialized = Some(detected.clone());
                if open_prompt {
                    let reason = self
                        .workspace
                        .as_ref()
                        .err()
                        .cloned()
                        .unwrap_or_else(|| "No baseline/backup workspace configured.".into());
                    self.state = State::InitPrompt(Box::new(InitPrompt {
                        detected,
                        assets,
                        data_dir: Workspace::preferred_data_dir(),
                        reason,
                    }));
                }
            }
            Ok(None) => {
                self.detected_uninitialized = None;
                self.message = Some((
                    "No Bloody W95 Max mouse detected on USB. Plug it in and press r to re-scan."
                        .into(),
                    true,
                ));
            }
            Err(e) => {
                self.detected_uninitialized = None;
                self.message = Some((format!("Mouse detection failed: {e}"), true));
            }
        }
    }

    fn start_init(&mut self) -> Result<(), String> {
        let State::InitPrompt(prompt) = std::mem::replace(&mut self.state, State::Ready) else {
            return Ok(());
        };
        let prompt = *prompt;
        let assets = match prompt.assets {
            Ok(path) => path,
            Err(err) => {
                self.state = State::InitPrompt(Box::new(InitPrompt {
                    assets: Err(err.clone()),
                    ..prompt
                }));
                return Err(err);
            }
        };
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let pid = std::process::id();
        let tmp_dir = std::env::temp_dir();
        let progress_file = tmp_dir.join(format!("ratmax-init-progress-{pid}-{stamp}.txt"));
        let stdout_file = tmp_dir.join(format!("ratmax-init-stdout-{pid}-{stamp}.json"));
        let stderr_file = tmp_dir.join(format!("ratmax-init-stderr-{pid}-{stamp}.txt"));
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stdout_file)
            .map_err(|e| e.to_string())?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stderr_file)
            .map_err(|e| e.to_string())?;
        let mut cmd = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
        cmd.arg("init")
            .arg("--assets")
            .arg(&assets)
            .arg("--dir")
            .arg(&prompt.data_dir)
            .arg("--workspace")
            .arg(&self.options.workspace)
            .arg("--progress-file")
            .arg(&progress_file)
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        let child = cmd.spawn().map_err(|e| e.to_string())?;
        self.message = None;
        self.state = State::Initializing(InitActive {
            child,
            progress_file,
            stdout_file,
            stderr_file,
        });
        Ok(())
    }

    fn sync_core_to_installed(&mut self) {
        if let Some(c) = self.installed_core() {
            self.core = c;
        }
        self.settings.operation = Operation::Configure;
    }

    fn will_flash(&self) -> bool {
        match self.entry {
            Some(Mode::Normal) => self.core != Core::One,
            Some(Mode::Target(installed)) => self.core != installed,
            _ => false,
        }
    }

    fn has_pending_edits(&self) -> bool {
        self.will_flash()
            || self.settings.cpi.iter().any(Option::is_some)
            || self.settings.cpi_xy.iter().any(Option::is_some)
            || self.settings.report_rate_hz.is_some()
            || self.settings.shooting_slot.is_some()
            || self
                .settings
                .side_buttons
                .iter()
                .chain(&self.settings.extra_buttons)
                .any(|b| *b != Button::Preserve)
    }

    fn clear_pending_edits(&mut self) {
        self.settings.cpi = [None; 5];
        self.settings.cpi_xy = [None; 5];
        self.settings.report_rate_hz = None;
        self.settings.shooting_slot = None;
        self.settings.side_buttons = [Button::Preserve; 2];
        self.settings.extra_buttons = [Button::Preserve; 5];
        self.sync_core_to_installed();
    }

    fn refresh(&mut self) {
        if self.running() {
            return;
        }
        if self.options.model {
            self.entry.get_or_insert(Mode::Normal);
            return;
        }
        match self
            .workspace
            .as_ref()
            .map_err(Clone::clone)
            .and_then(Workspace::inspect)
        {
            Ok(report) => {
                let list = report["candidates"].as_array().expect("candidates");
                self.entry = if list.len() == 1 {
                    serde_json::from_value(list[0]["mode"].clone()).ok()
                } else {
                    None
                };
            }
            Err(e) => {
                self.entry = None;
                self.message = Some((e, true));
            }
        }
        if self
            .current
            .as_ref()
            .is_some_and(|c| Some(c.mode) != self.entry)
        {
            self.current = None;
        }
        if !self.will_flash() {
            self.sync_core_to_installed();
        }
    }

    fn read_current(&mut self) -> Result<(), String> {
        if self.running() {
            return Ok(());
        }
        if !self.options.model && !workflow::available() {
            return Err("Live hardware access is disabled in this build.".into());
        }
        self.current = None;
        let saved = self.settings.clone();
        let saved_core = self.core;
        self.settings = empty_settings();
        self.settings.operation = Operation::Inspect;
        if let Some(c) = self.installed_core() {
            self.core = c;
        }
        let result = self
            .prepare_review(
                false,
                self.options.model,
                "Reading settings".into(),
                vec![],
                false,
            )
            .and_then(|()| self.start());
        self.settings = saved;
        self.core = saved_core;
        result
    }

    fn next_path(&self, label: &str) -> Result<PathBuf, String> {
        let w = self.workspace.as_ref().map_err(Clone::clone)?;
        std::fs::create_dir_all(&w.sessions).map_err(|e| e.to_string())?;
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        Ok(w.sessions.join(format!("{label}-{id}")))
    }

    fn budget(&mut self, model: bool) -> Result<PathBuf, String> {
        let slot = if model {
            &mut self.model_budget
        } else {
            &mut self.native_budget
        };
        if let Some(root) = slot {
            return Ok(root.clone());
        }
        let root = self
            .workspace
            .as_ref()
            .map_err(Clone::clone)?
            .create_budget(model)?;
        *slot = Some(root.clone());
        Ok(root)
    }

    fn prepare_review(
        &mut self,
        restore: bool,
        model: bool,
        title: String,
        lines: Vec<String>,
        clear_pending_on_success: bool,
    ) -> Result<(), String> {
        let budget = self.budget(model)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let output = budget.join(format!("job-{stamp}"));
        if restore {
            let source = self
                .last
                .clone()
                .ok_or("No previous session found to restore from.")?;
            let report = read_json(&source.join("cycle.json"))
                .or_else(|_| read_json(&source.join("run-intent.json")))?;
            if report["native"] != !model {
                return Err("Model and hardware restore sessions cannot be mixed.".into());
            }
            if report["original_restored"] == true {
                return Err("Factory backup was already restored in that session.".into());
            }
            self.state = State::Review(Review {
                project: None,
                output,
                restore: Some(source),
                model,
                title: "Restore Factory Backup".into(),
                lines: vec![
                    "Reflash original factory Core 1 firmware & settings.".into(),
                    "Your current Core, DPI, buttons, and lighting will be replaced.".into(),
                ],
                clear_pending_on_success: true,
            });
            return Ok(());
        }
        let mode = self
            .entry
            .ok_or("Mouse not detected. Connect W95 Max and press r to refresh.")?;
        let mut settings = self.settings.clone();
        settings.entry = mode;
        settings.budget = Some(budget);
        if model
            && self.options.model
            && let Some(last) = &self.last
            && let Ok(report) = read_json(&last.join("cycle.json"))
            && report["native"] == false
            && report["desired_configuration_kept"] == true
        {
            settings.model_entry = Some(last.clone());
        }

        let workspace = self.workspace.as_ref().map_err(Clone::clone)?;
        let request = workspace.request(self.core, settings);
        let path = output.with_extension("project.json");
        boot_roundtrip::save_artifact(
            &path,
            &serde_json::to_vec_pretty(&request).map_err(|e| e.to_string())?,
        )?;
        let _plan = crate::boot_roundtrip::pipeline::Plan::load(&path)?;
        self.state = State::Review(Review {
            project: Some(path),
            output,
            restore: None,
            model,
            title,
            lines,
            clear_pending_on_success,
        });
        Ok(())
    }

    fn review_mouse_changes(&mut self, model: bool) -> Result<(), String> {
        let mut summary: Vec<String> = Vec::new();
        let is_flash = self.will_flash();
        self.settings.operation = if is_flash {
            Operation::Flash
        } else {
            Operation::Configure
        };
        if is_flash {
            summary.push(format!(
                "Flash firmware: switch to Core {}",
                self.core.number()
            ));
        }
        for i in 0..5 {
            if let Some([x, y]) = self.settings.cpi_xy[i] {
                summary.push(format!("DPI {}: {x} × {y}", i + 1));
            } else if let Some(v) = self.settings.cpi[i] {
                summary.push(format!("DPI {}: {v}", i + 1));
            }
        }
        if let Some(hz) = self.settings.report_rate_hz {
            summary.push(format!("Polling Rate: {hz} Hz"));
        }
        if let Some(slot) = self.settings.shooting_slot {
            summary.push(format!(
                "Shooting Mode: {}",
                ["Normal", "Double", "Triple"][slot as usize]
            ));
        }
        for (label, b) in [
            ("Back", self.settings.side_buttons[0]),
            ("Forward", self.settings.side_buttons[1]),
        ] {
            if b != Button::Preserve {
                summary.push(format!("{label}: {}", b.name()));
            }
        }
        for (ctrl, b) in ExtraControl::ALL
            .into_iter()
            .zip(self.settings.extra_buttons)
        {
            if b != Button::Preserve {
                summary.push(format!("{}: {}", short_extra_name(ctrl), b.name()));
            }
        }
        if summary.is_empty() {
            summary.push("No pending edits — re-verify and save current configuration.".into());
        }
        let title = if model {
            "Test Changes (Model)".into()
        } else if is_flash {
            format!("Flash Core {} & Apply", self.core.number())
        } else {
            "Apply Settings to Mouse".into()
        };
        self.prepare_review(false, model, title, summary, true)
    }

    pub(super) fn review_macro_removal(&mut self) -> Result<(), String> {
        let Some(Mode::Target(c @ (Core::Three | Core::Four))) = self.entry else {
            return Err("Macros require Core 3 or Core 4.".into());
        };
        if self.installed_macro_buttons().is_empty() {
            return Err("No custom macros are currently installed on the mouse.".into());
        }
        self.review_macro(c, crate::macros::storage::Edit::Remove)
    }

    pub(super) fn review_macro(
        &mut self,
        core: Core,
        edit: crate::macros::storage::Edit,
    ) -> Result<(), String> {
        if self.modal_active() {
            return Err("Finish the current action first.".into());
        }
        if self.entry != Some(Mode::Target(core)) {
            return Err(format!(
                "Mouse is not on Core {}. Switch Active Core on the Mouse tab first.",
                core.number()
            ));
        }
        if self.has_pending_edits() {
            return Err("Apply or revert pending Mouse tab edits before saving macros.".into());
        }
        let (title, lines) = match &edit {
            crate::macros::storage::Edit::Install { button, program } => {
                let mut ls = vec![format!("Button: {}", button.name())];
                if !program.press.is_empty() {
                    ls.push(format!("On press: {} step(s)", program.press.len()));
                }
                if !program.release.is_empty() {
                    ls.push(format!("On release: {} step(s)", program.release.len()));
                }
                if program.repeat > 1 {
                    ls.push(format!("Repeat: {}x", program.repeat));
                }
                ("Save Macro to Mouse".into(), ls)
            }
            crate::macros::storage::Edit::InstallAll { bindings } => {
                let mut ls = vec![format!("Save {} button macros to mouse:", bindings.len())];
                for b in bindings {
                    ls.push(format!(
                        "  {} ({} press / {} release steps)",
                        b.button.name(),
                        b.program.press.len(),
                        b.program.release.len()
                    ));
                }
                ("Save Macros to Mouse".into(), ls)
            }
            crate::macros::storage::Edit::Remove => (
                "Clear Macros from Mouse".into(),
                vec!["Remove all custom button macros and restore original button actions.".into()],
            ),
        };
        let prev = self.settings.clone();
        let prev_core = self.core;
        self.settings = empty_settings();
        self.settings.operation = Operation::Configure;
        self.settings.entry = Mode::Target(core);
        self.settings.button_macro = Some(edit);
        self.core = core;
        let res = self.prepare_review(false, self.options.model, title, lines, false);
        self.settings = prev;
        self.core = prev_core;
        res
    }

    pub(super) fn review_lighting(
        &mut self,
        edit: crate::lighting::PersistentEdit,
    ) -> Result<(), String> {
        if self.modal_active() {
            return Err("Finish the current action first.".into());
        }
        let Some(Mode::Target(core)) = self.entry else {
            return Err(
                "Permanent custom RGB requires Core 1–4 firmware (switch Active Core on the Mouse tab)."
                    .into(),
            );
        };
        if self.has_pending_edits() {
            return Err("Apply or revert pending Mouse tab edits before saving lighting.".into());
        }
        let (title, lines) = match &edit {
            crate::lighting::PersistentEdit::Install {
                leds,
                breathing,
                brightness,
            } => {
                let effect_str = if leds.iter().all(|c| *c == leds[0]) {
                    format!("Solid {}", leds[0].hex())
                } else {
                    format!("Custom 15-LED ({} → {})", leds[0].hex(), leds[14].hex())
                };
                let b_str = brightness.map_or("Unchanged", |b| b.label());
                (
                    "Save Permanent RGB to Mouse".into(),
                    vec![
                        format!("Effect:     {effect_str}"),
                        format!("Breathing:  {}", breathing.label()),
                        format!("Brightness: {b_str}"),
                        "Survives unplug/reboot and activates immediately.".into(),
                    ],
                )
            }
            crate::lighting::PersistentEdit::Remove => (
                "Restore Stock Lighting".into(),
                vec!["Remove custom permanent RGB and restore stock built-in lighting.".into()],
            ),
        };
        let prev = self.settings.clone();
        let prev_core = self.core;
        self.settings = empty_settings();
        self.settings.operation = Operation::Configure;
        self.settings.entry = Mode::Target(core);
        self.settings.custom_lighting = Some(edit);
        self.core = core;
        let res = self.prepare_review(false, self.options.model, title, lines, false);
        self.settings = prev;
        self.core = prev_core;
        res
    }

    fn start(&mut self) -> Result<(), String> {
        let State::Review(review) = std::mem::replace(&mut self.state, State::Ready) else {
            return Ok(());
        };
        if !review.model && !workflow::available() {
            return Err("Live hardware access is disabled in this build.".into());
        }
        let command = match (review.model, review.restore.is_some()) {
            (true, false) => "workflow-simulate",
            (true, true) => "workflow-restore-simulate",
            (false, false) => "workflow-run",
            (false, true) => "workflow-restore",
        };
        let input = review
            .restore
            .as_ref()
            .or(review.project.as_ref())
            .expect("review input");
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(review.output.with_extension("stdout.json"))
            .map_err(|e| e.to_string())?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(review.output.with_extension("stderr.txt"))
            .map_err(|e| e.to_string())?;
        let mut cmd = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
        cmd.arg(command)
            .arg(if review.restore.is_some() {
                "--session"
            } else {
                "--project"
            })
            .arg(input)
            .arg("--output")
            .arg(&review.output)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let inspection = review.restore.is_none() && review.title == "Reading settings";
        let previous_last = self.last.clone();
        let track = review.model == self.options.model && !inspection;
        if track {
            self.last = Some(review.output.clone());
            self.save_pointer(&review.output, review.model)?;
        }
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                self.last = previous_last;
                return Err(e.to_string());
            }
        };
        self.message = None;
        self.state = State::Running(Active {
            child,
            stop_root: review.output.clone(),
            output: review.output,
            previous_last,
            model: review.model,
            cancel_requested: false,
            inspection,
            clear_pending_on_success: review.clear_pending_on_success,
        });
        Ok(())
    }

    fn cancel(&mut self) {
        if let State::Running(job) = &mut self.state {
            job.cancel_requested = true;
            if job.stop_root.exists() {
                let _ = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(job.stop_root.join("STOP"));
            }
        }
    }

    pub(super) fn poll(&mut self) {
        if let State::Initializing(job) = &mut self.state {
            match job.child.try_wait() {
                Ok(Some(status)) => {
                    let stderr_text = std::fs::read_to_string(&job.stderr_file).unwrap_or_default();
                    let _ = std::fs::remove_file(&job.progress_file);
                    let _ = std::fs::remove_file(&job.stdout_file);
                    let _ = std::fs::remove_file(&job.stderr_file);
                    self.state = State::Ready;
                    if status.success() {
                        self.workspace = Workspace::load(&self.options.workspace);
                        if self.workspace.is_ok() {
                            self.detected_uninitialized = None;
                            self.init_assets = None;
                            self.refresh();
                            self.sync_core_to_installed();
                            if let Err(e) = self.read_current() {
                                self.message = Some((
                                    format!("Workspace initialized, but live read failed: {e}"),
                                    true,
                                ));
                            } else {
                                self.message = Some((
                                    "Workspace initialized and verified from mouse.".into(),
                                    false,
                                ));
                            }
                        } else if let Err(e) = &self.workspace {
                            self.message = Some((format!("Initialized, but reload failed: {e}"), true));
                        }
                    } else {
                        let detail = stderr_text
                            .trim()
                            .strip_prefix("ratmax: ")
                            .unwrap_or(stderr_text.trim());
                        let msg = if detail.is_empty() {
                            "Initialization failed.".into()
                        } else {
                            format!("Init failed: {detail}")
                        };
                        self.message = Some((msg, true));
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    self.message = Some((e.to_string(), true));
                }
            }
            return;
        }
        if let State::Running(job) = &self.state
            && job.cancel_requested
            && job.stop_root.exists()
        {
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(job.stop_root.join("STOP"));
        }
        let finished = match &mut self.state {
            State::Running(job) => match job.child.try_wait() {
                Ok(Some(status)) => Some((
                    status.success(),
                    job.output.clone(),
                    job.model,
                    job.previous_last.clone(),
                    job.clear_pending_on_success,
                )),
                Ok(None) => None,
                Err(e) => {
                    self.message = Some((e.to_string(), true));
                    None
                }
            },
            _ => None,
        };
        if let Some((success, path, model, previous_last, clear_pending)) = finished {
            self.state = State::Ready;
            match read_json(&path.join("cycle.json")) {
                Ok(report) => {
                    if !success
                        && report["device_unchanged_no_test_writes"] == true
                        && model == self.options.model
                    {
                        self.last = previous_last;
                        if let Some(prior) = &self.last {
                            let _ = self.save_pointer(prior, model);
                        }
                    }
                    let kept = report["desired_configuration_kept"] == true;
                    let restored = report["original_restored"] == true;
                    let inspected = report["inspected"] == true;
                    if success && (kept || restored || inspected) {
                        let expected = if model {
                            report["result"]["mode"].clone()
                        } else {
                            report["attempts"]
                                .as_array()
                                .and_then(|a| a.last())
                                .map_or(serde_json::Value::Null, |a| a["result"]["mode"].clone())
                        };
                        match load_current(&path, model, &expected) {
                            Ok(current) => self.current = Some(current),
                            Err(e) => {
                                self.current = None;
                                self.message = Some((format!("Readback error: {e}"), true));
                            }
                        }
                    }
                    if (kept
                        || restored
                        || (!success && report["device_unchanged_no_test_writes"] != true))
                        && model == self.options.model
                    {
                        self.last = Some(path.clone());
                        let _ = self.save_pointer(&path, model);
                    }
                    if model && self.options.model {
                        if restored {
                            self.entry = Some(Mode::Normal);
                        } else if kept {
                            self.entry =
                                serde_json::from_value(report["result"]["mode"].clone()).ok();
                        }
                    } else if !model {
                        self.refresh();
                    }
                    if success && clear_pending && (kept || restored) {
                        self.clear_pending_edits();
                    } else if success && inspected {
                        self.sync_core_to_installed();
                    }
                    self.message = Some(if !success {
                        (
                            format!("Operation failed — see {}", path.display()),
                            true,
                        )
                    } else if kept {
                        ("Saved to mouse.".into(), false)
                    } else if restored {
                        ("Factory backup restored.".into(), false)
                    } else if inspected {
                        ("Settings synced from mouse.".into(), false)
                    } else {
                        ("Operation stopped.".into(), true)
                    });
                }
                Err(e) => {
                    self.last = Some(path.clone());
                    let _ = self.save_pointer(&path, model);
                    self.message = Some((format!("Worker stopped unexpectedly: {e}"), true));
                }
            }
        }
    }

    fn save_pointer(&self, path: &Path, model: bool) -> Result<(), String> {
        let root = &self.workspace.as_ref().map_err(Clone::clone)?.sessions;
        let name = if model {
            "last-model-session.json"
        } else {
            "last-native-session.json"
        };
        let target = root.join(name);
        let temporary = self.next_path("last-session")?;
        boot_roundtrip::save_artifact(
            &temporary,
            &serde_json::to_vec(&serde_json::json!({"session": path}))
                .map_err(|e| e.to_string())?,
        )?;
        std::fs::rename(temporary, target).map_err(|e| e.to_string())
    }

    fn current_cpi_pair(&self, idx: usize) -> [u16; 2] {
        if let Some(xy) = self.settings.cpi_xy[idx] {
            return xy;
        }
        if let Some(v) = self.settings.cpi[idx] {
            return [v, v];
        }
        if let Some(cur) = &self.current {
            if let Some([x, y]) = cur.cpi_xy_approx[idx] {
                return [
                    x.clamp(22, u32::from(crate::settings::MAX_CPI)) as u16,
                    y.clamp(22, u32::from(crate::settings::MAX_CPI)) as u16,
                ];
            }
            if let Some(v) = cur.cpi_approx[idx] {
                let c = v.clamp(22, u32::from(crate::settings::MAX_CPI)) as u16;
                return [c, c];
            }
        }
        [800, 800]
    }

    fn step_cpi(value: u16, delta: i32) -> u16 {
        let step = if value >= 6200 { 100 } else { 44 };
        value
            .saturating_add_signed((delta * step) as i16)
            .clamp(22, crate::settings::MAX_CPI)
    }

    fn adjust_cpi_axis(&mut self, idx: usize, delta: i32, y_only: bool) {
        let [x, y] = self.current_cpi_pair(idx);
        let (nx, ny) = if y_only {
            (x, Self::step_cpi(y, delta))
        } else if x != y {
            (Self::step_cpi(x, delta), y)
        } else {
            let next = Self::step_cpi(x, delta);
            (next, next)
        };
        if nx == ny {
            self.settings.cpi_xy[idx] = None;
            self.settings.cpi[idx] = Some(nx);
        } else {
            self.settings.cpi[idx] = None;
            self.settings.cpi_xy[idx] = Some([nx, ny]);
        }
    }

    fn adjust(&mut self, delta: i32) {
        match self.row {
            0..=4 => self.adjust_cpi_axis(self.row, delta, false),
            5 => {
                let all = [
                    None,
                    Some(125),
                    Some(250),
                    Some(500),
                    Some(1000),
                    Some(2000),
                ];
                let at = all
                    .iter()
                    .position(|v| *v == self.settings.report_rate_hz)
                    .unwrap_or(0);
                self.settings.report_rate_hz = all[(at as i32 + delta).rem_euclid(6) as usize];
            }
            6 => {
                self.core =
                    Core::ALL[(i32::from(self.core.number()) - 1 + delta).rem_euclid(4) as usize];
                if self.sanitize_for_mode() {
                    self.message = Some((
                        format!(
                            "Cleared pending options not supported on Core {}.",
                            self.core.number()
                        ),
                        false,
                    ));
                }
            }
            7 => {
                let mode = self.effective_mode();
                if !workflow::shooting_supported(mode) {
                    self.message = Some((
                        format!(
                            "Shooting Mode is disabled on {} (Core 2 / 3 only).",
                            mode_label(mode)
                        ),
                        true,
                    ));
                    return;
                }
                let all = [None, Some(0), Some(1), Some(2)];
                let at = all
                    .iter()
                    .position(|v| *v == self.settings.shooting_slot)
                    .unwrap_or(0);
                self.settings.shooting_slot = all[(at as i32 + delta).rem_euclid(4) as usize];
            }
            8 | 9 => {
                let mode = self.effective_mode();
                let allowed: Vec<Button> = Button::ALL
                    .into_iter()
                    .filter(|b| b.supported(mode))
                    .collect();
                let slot = &mut self.settings.side_buttons[self.row - 8];
                let at = allowed.iter().position(|v| v == slot).unwrap_or(0);
                *slot = allowed[(at as i32 + delta).rem_euclid(allowed.len() as i32) as usize];
            }
            10..=14 => {
                let mode = self.effective_mode();
                let allowed: Vec<Button> = Button::ALL
                    .into_iter()
                    .filter(|b| b.supported(mode))
                    .collect();
                let slot = &mut self.settings.extra_buttons[self.row - 10];
                let at = allowed.iter().position(|v| v == slot).unwrap_or(0);
                *slot = allowed[(at as i32 + delta).rem_euclid(allowed.len() as i32) as usize];
            }
            _ => {}
        }
    }

    /// Handles keys while a review/running/init/CPI-input modal is active. Returns `true` to stay open.
    pub(super) fn handle_modal(&mut self, key: KeyEvent) -> bool {
        if matches!(self.state, State::Initializing(_)) {
            return true;
        }
        if matches!(self.state, State::InitPrompt(_)) {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    if let Err(e) = self.start_init() {
                        self.message = Some((e, true));
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.state = State::Ready;
                }
                _ => {}
            }
            return true;
        }
        if self.running() {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('x'))
                || (key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL))
            {
                self.cancel();
            }
            return true;
        }
        if matches!(self.state, State::Review(_)) {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Err(e) = self.start() {
                        self.message = Some((e, true));
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.state = State::Ready;
                }
                _ => {}
            }
            return true;
        }
        if let Some(edit) = &mut self.cpi_edit {
            if key.code == KeyCode::Char('u') && key.modifiers.contains(KeyModifiers::CONTROL) {
                edit.clear();
                return true;
            }
            match key.code {
                KeyCode::Char(c)
                    if c.is_ascii_digit() || matches!(c, 'x' | 'X' | '/' | ',') =>
                {
                    if edit.len() < 12 {
                        edit.push(c);
                    }
                }
                KeyCode::Backspace => {
                    edit.pop();
                }
                KeyCode::Esc => {
                    self.cpi_edit = None;
                    self.message = None;
                }
                KeyCode::Enter => match crate::settings::parse_cpi_input(edit) {
                    Ok((eq, xy)) => {
                        self.settings.cpi[self.row] = eq;
                        self.settings.cpi_xy[self.row] = xy;
                        self.cpi_edit = None;
                        self.message = None;
                    }
                    Err(e) => self.message = Some((e, true)),
                },
                _ => {}
            }
            return true;
        }
        true
    }

    pub(super) fn handle(&mut self, key: KeyEvent) -> bool {
        if self.workspace.is_err() {
            return match key.code {
                KeyCode::Char('i') | KeyCode::Char('I') => {
                    self.probe_uninitialized(true);
                    true
                }
                KeyCode::Char('r') => {
                    self.trigger_refresh();
                    true
                }
                _ => false,
            };
        }
        let result: Result<(), String> = match key.code {
            KeyCode::Up => {
                self.row = (self.row + TOTAL_ROWS - 1) % TOTAL_ROWS;
                Ok(())
            }
            KeyCode::Down => {
                self.row = (self.row + 1) % TOTAL_ROWS;
                Ok(())
            }
            KeyCode::Left => {
                if self.row <= 4 && key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.adjust_cpi_axis(self.row, -1, true);
                } else {
                    self.adjust(-1);
                }
                Ok(())
            }
            KeyCode::Right => {
                if self.row <= 4 && key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.adjust_cpi_axis(self.row, 1, true);
                } else {
                    self.adjust(1);
                }
                Ok(())
            }
            KeyCode::Char('[') if self.row <= 4 => {
                self.adjust_cpi_axis(self.row, -1, true);
                Ok(())
            }
            KeyCode::Char(']') if self.row <= 4 => {
                self.adjust_cpi_axis(self.row, 1, true);
                Ok(())
            }
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char(' ') if self.row <= 4 => {
                let [x, y] = self.current_cpi_pair(self.row);
                self.cpi_edit = Some(if x == y {
                    x.to_string()
                } else {
                    format!("{x}x{y}")
                });
                Ok(())
            }
            KeyCode::Char('x') | KeyCode::Char('X') if self.row <= 4 => {
                let [x, _] = self.current_cpi_pair(self.row);
                self.cpi_edit = Some(format!("{x}x"));
                Ok(())
            }
            KeyCode::Delete | KeyCode::Backspace => {
                match self.row {
                    0..=4 => {
                        self.settings.cpi[self.row] = None;
                        self.settings.cpi_xy[self.row] = None;
                    }
                    5 => self.settings.report_rate_hz = None,
                    6 => {
                        self.sync_core_to_installed();
                        self.sanitize_for_mode();
                    }
                    7 => self.settings.shooting_slot = None,
                    8 | 9 => self.settings.side_buttons[self.row - 8] = Button::Preserve,
                    10..=14 => self.settings.extra_buttons[self.row - 10] = Button::Preserve,
                    _ => {}
                }
                Ok(())
            }
            KeyCode::Char('s') | KeyCode::Char('S') => self.review_mouse_changes(self.options.model),
            KeyCode::Char('m') | KeyCode::Char('M') => self.review_mouse_changes(true),
            KeyCode::Char('R') => self.prepare_review(true, self.options.model, String::new(), vec![], true),
            KeyCode::Char('r') => {
                self.refresh();
                self.read_current()
            }
            KeyCode::Char('B') | KeyCode::Char('b') => {
                self.next_path("original-backup").and_then(|p| {
                    self.workspace
                        .as_ref()
                        .map_err(Clone::clone)?
                        .export_backup(&p)
                        .map(|_| {
                            self.message =
                                Some((format!("Backup exported to {}", p.display()), false));
                        })
                })
            }
            _ => return false,
        };
        if let Err(e) = result {
            self.message = Some((e, true));
        }
        true
    }

    pub(super) fn draw(&self, frame: &mut Frame<'_>, area: Rect) {
        if let Err(e) = &self.workspace {
            let mut lines = vec![
                Line::raw(""),
                Line::styled(
                    "  Workspace is not initialized yet (no verified baseline/backup).",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::styled(format!("  Details: {e}"), Style::default().fg(Color::Gray)),
                Line::raw(""),
            ];
            if let Some(det) = &self.detected_uninitialized {
                lines.push(Line::from(vec![
                    Span::styled("  Detected mouse: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!(
                            "Bloody W95 Max · {} on {}",
                            det.mode_label(),
                            det.binding.device_path()
                        ),
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                match &self.init_assets {
                    Some(Ok(path)) => lines.push(Line::from(vec![
                        Span::styled("  Stock assets:   ", Style::default().fg(Color::Gray)),
                        Span::styled(path.display().to_string(), Style::default().fg(Color::White)),
                    ])),
                    Some(Err(err)) => lines.push(Line::styled(
                        format!("  Stock assets:   {err}"),
                        Style::default().fg(Color::Red),
                    )),
                    None => {}
                }
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        " [i] Initialize workspace from detected mouse ",
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "   [r] Re-scan   [q] Quit",
                        Style::default().fg(Color::Gray),
                    ),
                ]));
            } else {
                lines.push(Line::styled(
                    "  No Bloody W95 Max mouse detected on USB. Connect your mouse and press [r] to re-scan.",
                    Style::default().fg(Color::Red),
                ));
            }
            if let Some((msg, is_err)) = &self.message {
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    format!("  {msg}"),
                    Style::default().fg(if *is_err { Color::Red } else { Color::Green }),
                ));
            }
            let p = Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Mouse — Setup Required "));
            frame.render_widget(p, area);
            return;
        }

        let main_and_status = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(10), Constraint::Length(3)])
            .split(area);

        let cols = if area.width >= 78 {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(main_and_status[0])
        } else {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(11), Constraint::Min(9)])
                .split(main_and_status[0])
        };

        // Left pane: DPI 1-5, Polling Rate, Active Core, Shooting Mode
        let mut left_lines: Vec<Line<'_>> = Vec::new();
        for i in 0..5 {
            let (val, dirty) = format_dpi_value(
                self.settings.cpi[i],
                self.settings.cpi_xy[i],
                self.current.as_ref().map(|s| s.cpi_approx[i]),
                self.current.as_ref().map(|s| s.cpi_xy_approx[i]),
                self.current
                    .as_ref()
                    .is_some_and(|s| s.sensitivity_uses_stock_default),
            );
            left_lines.push(setting_row(
                self.row == i,
                &format!("DPI {}", i + 1),
                &val,
                dirty,
            ));
        }
        left_lines.push(Line::raw(""));
        let (rate_val, rate_dirty) = match self.settings.report_rate_hz {
            Some(hz) => (format!("{hz} Hz"), true),
            None => match self.current.as_ref().and_then(|c| c.report_rate_hz) {
                Some(hz) => (format!("{hz} Hz"), false),
                None => ("Default".into(), false),
            },
        };
        left_lines.push(setting_row(self.row == 5, "Polling Rate", &rate_val, rate_dirty));

        let core_val = if self.will_flash() {
            format!("Core {} (will flash)", self.core.number())
        } else if self.installed_core().is_some() {
            format!("Core {}", self.core.number())
        } else {
            "—".into()
        };
        left_lines.push(setting_row(
            self.row == 6,
            "Active Core",
            &core_val,
            self.will_flash(),
        ));

        let mode = self.effective_mode();
        let shooting_ok = workflow::shooting_supported(mode);
        let (shoot_val, shoot_dirty) = if !shooting_ok {
            (
                if mode == Mode::Target(Core::Four) {
                    "Disabled on Core 4 (Core 2/3 only)".into()
                } else {
                    "Disabled (Core 2/3 only)".into()
                },
                false,
            )
        } else if let Some(slot) = self.settings.shooting_slot {
            (["Normal", "Double", "Triple"][slot as usize].into(), true)
        } else if let Some(slot) = self.current.as_ref().and_then(|c| c.shooting_slot) {
            (shooting_name(slot), false)
        } else {
            ("Default".into(), false)
        };
        left_lines.push(if shooting_ok {
            setting_row(self.row == 7, "Shooting Mode", &shoot_val, shoot_dirty)
        } else {
            disabled_setting_row(self.row == 7, "Shooting Mode", &shoot_val)
        });

        left_lines.push(Line::raw(""));
        left_lines.push(Line::styled(
            format!("  {}", core_capabilities_summary(mode)),
            Style::default().fg(Color::DarkGray),
        ));
        if self.row <= 4 {
            left_lines.push(Line::styled(
                "  DPI: ←→ X (or both) · Shift+←→ Y only · Enter edit · x type XxY",
                Style::default().fg(Color::DarkGray),
            ));
        }

        let left = Paragraph::new(left_lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    " Sensitivity & Core ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )),
        );
        frame.render_widget(left, cols[0]);

        // Right pane: 7 Buttons
        let installed_macros = self.installed_macro_buttons();
        let mut right_lines: Vec<Line<'_>> = Vec::new();
        let side_labels = [("Back", Target::Back, 0), ("Forward", Target::Forward, 1)];
        for (i, (label, target, sidx)) in side_labels.iter().enumerate() {
            let choice = self.settings.side_buttons[*sidx];
            let (val, dirty, is_macro) = format_button_value(
                choice,
                self.current.as_ref().map(|c| &c.side_buttons[*sidx]),
                installed_macros.contains(target),
            );
            right_lines.push(button_row(self.row == 8 + i, label, &val, dirty, is_macro));
        }
        right_lines.push(Line::raw(""));
        let extra_targets = [
            Target::ExtraClick,
            Target::Precision,
            Target::AuxClick,
            Target::AuxFront,
            Target::AuxRear,
        ];
        for (i, (ctrl, target)) in ExtraControl::ALL.into_iter().zip(extra_targets).enumerate() {
            let choice = self.settings.extra_buttons[i];
            let (val, dirty, is_macro) = format_button_value(
                choice,
                self.current.as_ref().map(|c| &c.extra_buttons[i]),
                installed_macros.contains(&target),
            );
            right_lines.push(button_row(
                self.row == 10 + i,
                short_extra_name(ctrl),
                &val,
                dirty,
                is_macro,
            ));
        }
        right_lines.push(Line::raw(""));
        right_lines.push(Line::styled(
            if workflow::macros_supported(mode) {
                "  Tip: Use tab 2 (Macros) to assign custom key combos to buttons."
            } else {
                "  Macros disabled on this Core (switch to Core 3 or 4)."
            },
            Style::default().fg(Color::DarkGray),
        ));

        let right = Paragraph::new(right_lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    " Buttons ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )),
        );
        frame.render_widget(right, cols[1]);

        // Status strip
        let status_line = if let Some((msg, is_err)) = &self.message {
            Line::styled(
                format!("  {msg}"),
                Style::default().fg(if *is_err { Color::Red } else { Color::Green }),
            )
        } else if self.has_pending_edits() {
            Line::styled(
                "  Pending changes marked with * — press s to apply to mouse.",
                Style::default().fg(Color::Yellow),
            )
        } else {
            Line::styled(
                "  Ready · [s] Apply  [r] Refresh  [B] Export Backup  [R] Factory Restore",
                Style::default().fg(Color::DarkGray),
            )
        };
        let status = Paragraph::new(status_line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(status, main_and_status[1]);
    }

    /// Renders any active confirmation, progress, or CPI-input modal on top of the whole screen.
    pub(super) fn draw_modal(&self, frame: &mut Frame<'_>, area: Rect) {
        if let Some(edit) = &self.cpi_edit {
            let mut lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::raw("  DPI (e.g. 1600, 10000, or 1600x800): "),
                    Span::styled(
                        format!("{edit}_"),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::raw(""),
                Line::styled(
                    "  [Enter] Accept    [Ctrl+U] Clear    [Esc] Cancel",
                    Style::default().fg(Color::DarkGray),
                ),
            ];
            if let Some((msg, true)) = &self.message {
                lines.push(Line::styled(
                    format!("  {msg}"),
                    Style::default().fg(Color::Red),
                ));
            }
            super::draw_popup_box(
                frame,
                area,
                &format!("EDIT DPI {}", self.row + 1),
                Color::Cyan,
                lines,
            );
            return;
        }
        match &self.state {
            State::InitPrompt(prompt) => {
                let mut lines: Vec<Line<'_>> = vec![
                    Line::raw(""),
                    Line::styled(
                        "  No verified baseline/backup workspace was found.",
                        Style::default().fg(Color::White),
                    ),
                    Line::styled(
                        format!("  ({})", prompt.reason),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Line::raw(""),
                    Line::from(vec![
                        Span::styled("  Detected:   ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("Bloody W95 Max · {}", prompt.detected.mode_label()),
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("  Interface:  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{} (09DA:712F)", prompt.detected.binding.device_path()),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("  Save to:    ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            prompt.data_dir.display().to_string(),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                ];
                match &prompt.assets {
                    Ok(assets) => {
                        lines.push(Line::from(vec![
                            Span::styled("  Assets:     ", Style::default().fg(Color::Gray)),
                            Span::styled(
                                assets.display().to_string(),
                                Style::default().fg(Color::White),
                            ),
                        ]));
                        lines.push(Line::raw(""));
                        lines.push(Line::styled(
                            "  Reads your mouse's flash & boot bank twice (read-only, zero writes,",
                            Style::default().fg(Color::Gray),
                        ));
                        lines.push(Line::styled(
                            "  ~10 seconds) to create your verified backup and baseline.",
                            Style::default().fg(Color::Gray),
                        ));
                        lines.push(Line::raw(""));
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(
                                " [y / Enter] Initialize from Mouse ",
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("    "),
                            Span::styled("[Esc] Cancel", Style::default().fg(Color::Gray)),
                        ]));
                    }
                    Err(err) => {
                        lines.push(Line::from(vec![
                            Span::styled("  Assets:     ", Style::default().fg(Color::Gray)),
                            Span::styled(err.clone(), Style::default().fg(Color::Red)),
                        ]));
                        lines.push(Line::raw(""));
                        lines.push(Line::styled(
                            "  Extract stock W95 Max assets with `7z` (see `ratmax --help`), then press [r].",
                            Style::default().fg(Color::Yellow),
                        ));
                        lines.push(Line::raw(""));
                        lines.push(Line::styled("  [Esc] Close", Style::default().fg(Color::Gray)));
                    }
                }
                super::draw_popup_box(
                    frame,
                    area,
                    "INITIALIZE WORKSPACE FROM MOUSE",
                    Color::Yellow,
                    lines,
                );
            }
            State::Initializing(job) => {
                let step = std::fs::read_to_string(&job.progress_file)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "Connecting to mouse…".into());
                let lines = vec![
                    Line::raw(""),
                    Line::styled(
                        format!("  {step}"),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::styled(
                        "  Read-only 2-pass backup & baseline verification (zero writes).",
                        Style::default().fg(Color::Gray),
                    ),
                    Line::styled(
                        "  Please wait and do not unplug the mouse…",
                        Style::default().fg(Color::DarkGray),
                    ),
                ];
                super::draw_popup_box(frame, area, "INITIALIZING MOUSE", Color::Cyan, lines);
            }
            State::Review(review) => {
                let mut lines: Vec<Line<'_>> = vec![Line::raw("")];
                for l in &review.lines {
                    lines.push(Line::styled(format!("  {l}"), Style::default().fg(Color::White)));
                }
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        " [y] Confirm & Apply ",
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("    "),
                    Span::styled("[Esc] Cancel", Style::default().fg(Color::Gray)),
                ]));
                super::draw_popup_box(frame, area, &review.title, Color::Yellow, lines);
            }
            State::Running(job) => {
                let title = if job.inspection {
                    "READING MOUSE"
                } else {
                    "UPDATING MOUSE"
                };
                let step = progress(&job.output);
                let lines = vec![
                    Line::raw(""),
                    Line::styled(
                        format!("  {step}"),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::styled(
                        if job.cancel_requested {
                            "  Stopping cleanly…"
                        } else if job.inspection {
                            "  Please wait…"
                        } else {
                            "  Do not unplug mouse · [Esc] Cancel"
                        },
                        Style::default().fg(Color::DarkGray),
                    ),
                ];
                super::draw_popup_box(frame, area, title, Color::Cyan, lines);
            }
            State::Ready => {}
        }
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        if self.running() {
            self.cancel();
        }
    }
}

fn empty_settings() -> Settings {
    Settings {
        operation: Operation::Configure,
        entry: Mode::Normal,
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

fn setting_row(selected: bool, label: &str, value: &str, dirty: bool) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            if selected { " ▶ " } else { "   " },
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{label:<15}"),
            if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
        Span::styled(
            value.to_string(),
            if dirty {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            },
        ),
    ];
    if dirty {
        spans.push(Span::styled(" *", Style::default().fg(Color::Yellow)));
    }
    Line::from(spans)
}

fn disabled_setting_row(selected: bool, label: &str, reason: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            if selected { " ▶ " } else { "   " },
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{label:<15}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(reason.to_string(), Style::default().fg(Color::DarkGray)),
    ])
}

fn mode_label(mode: Mode) -> String {
    match mode {
        Mode::Normal => "Original Core 1".into(),
        Mode::Target(c) => format!("Core {}", c.number()),
        Mode::Boot => "Boot mode".into(),
    }
}

fn core_capabilities_summary(mode: Mode) -> &'static str {
    match mode {
        Mode::Normal => "Stock Core 1: DPI & basic buttons (flash Core 1–4 for RGB/extras)",
        Mode::Target(Core::One) => "Core 1: DPI, buttons, RGB (no Shooting, GunA, or Macros)",
        Mode::Target(Core::Two) => "Core 2: DPI, buttons, Shooting, RGB (no GunA or Macros)",
        Mode::Target(Core::Three) => "Core 3: DPI, buttons, Shooting, Macros, RGB",
        Mode::Target(Core::Four) => "Core 4: Full-Key Macros, DPI, buttons, RGB (no Shooting/GunA)",
        Mode::Boot => "Bootloader mode",
    }
}

fn button_row(
    selected: bool,
    label: &str,
    value: &str,
    dirty: bool,
    is_macro: bool,
) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            if selected { " ▶ " } else { "   " },
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{label:<16}"),
            if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
    ];
    if is_macro && !dirty {
        spans.push(Span::styled("● ", Style::default().fg(Color::Green)));
    }
    spans.push(Span::styled(
        value.to_string(),
        if dirty {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if is_macro {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else if selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        },
    ));
    if dirty {
        spans.push(Span::styled(" *", Style::default().fg(Color::Yellow)));
    }
    Line::from(spans)
}

fn short_extra_name(ctrl: ExtraControl) -> &'static str {
    match ctrl {
        ExtraControl::ExtraClick => "Extra Click",
        ExtraControl::Precision => "Precision",
        ExtraControl::Aux1 => "Aux Click",
        ExtraControl::AuxN => "Aux Front",
        ExtraControl::Aux3 => "Aux Rear",
    }
}

fn shooting_name(slot: u8) -> String {
    match slot {
        0 => "Normal".into(),
        1 => "Double".into(),
        2 => "Triple".into(),
        _ => format!("Slot {slot}"),
    }
}

fn format_button_value(
    choice: Button,
    current: Option<&CurrentControl>,
    is_macro: bool,
) -> (String, bool, bool) {
    if choice != Button::Preserve {
        return (choice.name().into(), true, false);
    }
    if is_macro {
        return ("Custom Macro".into(), false, true);
    }
    (
        current.map_or("—".into(), |c| c.description.clone()),
        false,
        false,
    )
}

fn format_dpi_value(
    choice: Option<u16>,
    choice_xy: Option<[u16; 2]>,
    current: Option<Option<u32>>,
    current_xy: Option<Option<[u32; 2]>>,
    firmware_default: bool,
) -> (String, bool) {
    if let Some([x, y]) = choice_xy {
        return (format!("{x} × {y}"), true);
    }
    if let Some(v) = choice {
        return (v.to_string(), true);
    }
    let val = match (current_xy, current) {
        (Some(Some([x, y])), _) if x != y => format!("{x} × {y}"),
        (Some(Some([x, _])), _) => format!("{x}"),
        (_, Some(Some(v))) => format!("{v}"),
        (Some(None), _) | (_, Some(None)) if firmware_default => "Default".into(),
        (Some(None), _) | (_, Some(None)) => "Custom".into(),
        _ => "—".into(),
    };
    (val, false)
}

fn load_current(
    path: &Path,
    model: bool,
    expected: &serde_json::Value,
) -> Result<CurrentConfiguration, String> {
    let actor = if model {
        path.to_owned()
    } else {
        let mut actors = std::fs::read_dir(path)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("attempt-"))
            })
            .collect::<Vec<_>>();
        actors.sort();
        actors.pop().ok_or("worker output missing")?
    };
    let current: CurrentConfiguration =
        serde_json::from_value(read_json(&actor.join("workflow-current.json"))?)
            .map_err(|e| e.to_string())?;
    if current.schema != 1
        || serde_json::to_value(current.mode).map_err(|e| e.to_string())? != *expected
    {
        return Err("readback belongs to a different mode".into());
    }
    Ok(current)
}

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&crate::preview::read_file(path, 1_048_576)?)
        .map_err(|e| e.to_string())
}

fn progress(output: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(output) else {
        return "Preparing…".into();
    };
    let mut actors = entries
        .filter_map(Result::ok)
        .map(|p| p.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("attempt-"))
        })
        .collect::<Vec<_>>();
    actors.sort();
    let Some(actor) = actors.last() else {
        return "Starting…".into();
    };
    let path = actor.join("journal.jsonl");
    let Ok(mut file) = std::fs::File::open(path) else {
        return "Connecting to mouse…".into();
    };
    let Ok(size) = file.metadata().map(|m| m.len()) else {
        return "Working…".into();
    };
    let _ = file.seek(SeekFrom::Start(size.saturating_sub(8192)));
    let mut data = Vec::new();
    let _ = file.read_to_end(&mut data);
    let text = String::from_utf8_lossy(&data);
    for line in text.lines().rev() {
        if let Ok(row) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(action) = row["value"].get("action")
        {
            let phase = action["phase"].as_str().unwrap_or("reconnecting");
            return match phase {
                p if p.contains("preflight") || p.contains("inspect") => "Reading mouse…".into(),
                p if p.contains("forward-records") => "Flashing firmware…".into(),
                p if p.contains("restore-records") => "Restoring backup…".into(),
                p if p.contains("config") => "Writing settings…".into(),
                p if p.contains("lighting") => "Updating lighting…".into(),
                _ => "Verifying…".into(),
            };
        }
    }
    "Working…".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (PathBuf, Panel) {
        let root = std::env::temp_dir().join(format!(
            "ratmax-tui-workflow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let panel = Panel {
            options: WorkflowOptions {
                workspace: root.join("workspace.json"),
                model: true,
                session: None,
            },
            workspace: Ok(Workspace {
                schema: 1,
                baseline: root.join("baseline"),
                backup: root.join("backup"),
                assets: root.join("assets"),
                sessions: root.join("jobs"),
            }),
            detected_uninitialized: None,
            init_assets: None,
            core: Core::One,
            entry: Some(Mode::Normal),
            settings: empty_settings(),
            row: 0,
            cpi_edit: None,
            state: State::Ready,
            message: None,
            last: None,
            native_budget: None,
            model_budget: None,
            current: None,
        };
        (root, panel)
    }

    #[test]
    fn core_change_automatically_selects_flash_and_asymmetric_cpi_edits_revert_cleanly() {
        let (root, mut panel) = fixture();
        assert!(!panel.will_flash());

        // Changing Active Core (row 6) to Core 3 automatically sets will_flash() -> Flash!
        panel.row = 6;
        panel.adjust(2);
        assert_eq!(panel.core, Core::Three);
        assert!(panel.will_flash());
        // Pressing Delete on row 6 reverts back to installed Core 1!
        panel.handle(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(panel.core, Core::One);
        assert!(!panel.will_flash());

        // Asymmetric CPI editing via ']' splits Y independently
        panel.row = 0;
        panel.handle(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE));
        assert_eq!(panel.settings.cpi_xy[0], Some([800, 844]));
        panel.handle(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(panel.settings.cpi_xy[0], None);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn core4_is_enabled_and_disables_shooting_and_gun_a_while_sanitizing_pending_edits() {
        let (root, mut panel) = fixture();

        // Original Core 1: Precision, DoubleClick, TripleClick, and Select* are filtered out.
        panel.row = 8;
        let mut seen_normal = Vec::new();
        for _ in 0..20 {
            panel.adjust(1);
            seen_normal.push(panel.settings.side_buttons[0]);
        }
        assert!(!seen_normal.contains(&Button::Precision));
        assert!(!seen_normal.contains(&Button::DoubleClick));
        assert!(!seen_normal.contains(&Button::SelectNormal));

        // Switch to Core 3: Shooting Mode + Select* selectors become available.
        panel.row = 6;
        panel.adjust(2);
        assert_eq!(panel.core, Core::Three);
        panel.row = 7;
        panel.adjust(1);
        assert_eq!(panel.settings.shooting_slot, Some(0));
        panel.settings.side_buttons[0] = Button::SelectDouble;
        panel.settings.side_buttons[1] = Button::Precision;

        // Switch from Core 3 -> Core 4: Shooting Mode & SelectDouble are automatically cleared,
        // while Core-4-supported Precision is preserved!
        panel.row = 6;
        panel.adjust(1);
        assert_eq!(panel.core, Core::Four);
        assert!(panel.will_flash());
        assert_eq!(panel.settings.shooting_slot, None);
        assert_eq!(panel.settings.side_buttons[0], Button::Preserve);
        assert_eq!(panel.settings.side_buttons[1], Button::Precision);

        // On Core 4: Shooting Mode stays disabled, GunA is unsupported, Macros + Permanent RGB are supported.
        assert!(!workflow::shooting_supported(Mode::Target(Core::Four)));
        assert!(!workflow::gun_a_supported(Mode::Target(Core::Four)));
        assert!(workflow::macros_supported(Mode::Target(Core::Four)));
        assert!(workflow::permanent_lighting_supported(Mode::Target(Core::Four)));
        panel.row = 7;
        panel.adjust(1);
        assert_eq!(panel.settings.shooting_slot, None);

        // Cycling buttons on Core 4 admits Precision/DoubleClick/TripleClick, excludes Select* selectors.
        panel.row = 8;
        let mut seen_c4 = Vec::new();
        for _ in 0..20 {
            panel.adjust(1);
            seen_c4.push(panel.settings.side_buttons[0]);
        }
        assert!(seen_c4.contains(&Button::Precision));
        assert!(seen_c4.contains(&Button::DoubleClick));
        assert!(!seen_c4.contains(&Button::SelectNormal));
        assert!(!seen_c4.contains(&Button::SelectDouble));
        assert!(!seen_c4.contains(&Button::SelectTriple));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exit_keys_during_job_request_cancel_and_keep_ui_open() {
        let (root, mut panel) = fixture();
        let child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        panel.state = State::Running(Active {
            child,
            output: root.clone(),
            stop_root: root.clone(),
            previous_last: None,
            model: true,
            cancel_requested: false,
            inspection: false,
            clear_pending_on_success: false,
        });
        for key in [
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        ] {
            assert!(panel.handle_modal(key));
            assert!(panel.running());
            assert!(root.join("STOP").is_file());
        }
        if let State::Running(job) = &mut panel.state {
            job.child.kill().unwrap();
            job.child.wait().unwrap();
        }
        panel.state = State::Ready;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uninitialized_workspace_shows_init_prompt_and_dismisses_cleanly() {
        let (root, mut panel) = fixture();
        panel.options.model = false;
        panel.workspace = Err("workspace baseline path missing".into());
        let detected = crate::init::DetectedMouse {
            mode: Mode::Target(Core::Three),
            binding: crate::query_session::Binding {
                node: "hidraw3".into(),
                hid_sysfs_path: "/sys/devices/pci0000:00/usb1/1-5/1-5:1.2/0003:09DA:712F.0004"
                    .into(),
                usb_parent: "/sys/devices/pci0000:00/usb1/1-5".into(),
                usb_interface_path: "/sys/devices/pci0000:00/usb1/1-5/1-5:1.2".into(),
                usb_bus_number: 1,
                usb_device_number: 3,
                usb_interface_number: 2,
                usb_release_bcd: 0x34,
                vendor_id: 0x09da,
                product_id: 0x712f,
                manufacturer: "A4TECH".into(),
                product: "Bloody W95 Max".into(),
                serial: None,
                hid_phys: Some("usb-1-5/input2".into()),
                hid_unique: Some(String::new()),
                major_minor: "243:3".into(),
                feature_07_total_bytes: 64,
                descriptor_bytes: 180,
                descriptor_sha256:
                    "a4fc70e1648716690a8989efb837f907447bc0ced5e68e906a53615fb7890d24".into(),
            },
        };
        panel.detected_uninitialized = Some(detected.clone());
        panel.state = State::InitPrompt(Box::new(InitPrompt {
            detected,
            assets: Ok(root.join("BloodyWorkShop8")),
            data_dir: root.join("data"),
            reason: "workspace baseline path missing".into(),
        }));
        assert!(panel.modal_active());
        let (_, status, _) = panel.header_status();
        assert!(status.contains("Needs Init"), "got: {status}");
        assert!(panel.handle_modal(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(!panel.modal_active());
        std::fs::remove_dir_all(root).unwrap();
    }
}
