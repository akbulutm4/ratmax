//! The W95 Max apply/keep/restore workflow shared by the TUI and CLI.
use crate::{
    boot_roundtrip::{
        self, Mode,
        pipeline::{self, Plan, Request},
    },
    model::Core,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const PHYSICAL_WORKFLOW_RELEASED: bool = true;

/// The v0034 Left-shooting dispatcher explicitly admits runtime Cores 2 and 3.
/// Core 1 and Core 4 do not support Left-click shooting modes or shooting selectors.
pub fn shooting_supported(mode: Mode) -> bool {
    matches!(mode, Mode::Target(Core::Two | Core::Three))
}

/// Custom GunA Left-click programs are restricted to prepared Core 3.
/// Core 4 (Full Key Programming) does not allow GunA.
pub fn gun_a_supported(mode: Mode) -> bool {
    mode == Mode::Target(Core::Three)
}

/// Ordinary custom button macros are supported on prepared Core 3 and Core 4.
pub fn macros_supported(mode: Mode) -> bool {
    matches!(mode, Mode::Target(Core::Three | Core::Four))
}

/// Permanent internal-flash RGB lighting is supported on prepared v0034 firmware (Cores 1–4).
pub fn permanent_lighting_supported(mode: Mode) -> bool {
    matches!(mode, Mode::Target(_))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Inspect,
    Configure,
    Flash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Button {
    Preserve,
    Default,
    LeftClick,
    RightClick,
    MiddleClick,
    CpiNext,
    CpiPrevious,
    SelectNormal,
    SelectTriple,
    Back,
    Forward,
    Disabled,
    Precision,
    DoubleClick,
    TripleClick,
    SelectDouble,
}
impl Button {
    pub const ALL: [Self; 16] = [
        Self::Preserve,
        Self::Default,
        Self::Back,
        Self::Forward,
        Self::MiddleClick,
        Self::LeftClick,
        Self::RightClick,
        Self::Disabled,
        Self::Precision,
        Self::DoubleClick,
        Self::TripleClick,
        Self::CpiNext,
        Self::CpiPrevious,
        Self::SelectNormal,
        Self::SelectDouble,
        Self::SelectTriple,
    ];
    pub fn supported(self, mode: Mode) -> bool {
        match self {
            Self::Preserve
            | Self::Default
            | Self::LeftClick
            | Self::RightClick
            | Self::MiddleClick
            | Self::Back
            | Self::Forward
            | Self::Disabled
            | Self::CpiNext
            | Self::CpiPrevious => true,
            Self::Precision | Self::DoubleClick | Self::TripleClick => {
                matches!(mode, Mode::Target(_))
            }
            Self::SelectNormal | Self::SelectDouble | Self::SelectTriple => {
                shooting_supported(mode)
            }
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::Default => "stock default",
            Self::LeftClick => "Left click",
            Self::RightClick => "Right click",
            Self::MiddleClick => "Middle click",
            Self::CpiNext => "Next CPI preset",
            Self::CpiPrevious => "Previous CPI preset",
            Self::SelectNormal => "Select normal-click mode",
            Self::SelectTriple => "Select triple-click mode",
            Self::Back => "Back",
            Self::Forward => "Forward",
            Self::Disabled => "Disabled",
            Self::Precision => "Precision hold",
            Self::DoubleClick => "Double click",
            Self::TripleClick => "Triple click",
            Self::SelectDouble => "Select double-click mode",
        }
    }
    pub(crate) fn words(self, mode: Mode, image: &[u8]) -> Result<[u16; 2], String> {
        Ok(match self {
            Self::LeftClick => [0x2501, 0x2401],
            Self::RightClick => [0x2502, 0x2402],
            Self::MiddleClick => [0x2504, 0x2404],
            Self::CpiNext => [0x2626, 0x262e],
            Self::CpiPrevious => [0x2624, 0x262e],
            Self::Back => [0x2508, 0x2408],
            Self::Forward => [0x2510, 0x2410],
            Self::Disabled => [0x262e; 2],
            Self::Precision if matches!(mode, Mode::Target(_)) => [0x2628, 0x2629],
            Self::SelectNormal if shooting_supported(mode) => [0x2610, 0x262e],
            Self::SelectDouble if shooting_supported(mode) => [0x2611, 0x262e],
            Self::SelectTriple if shooting_supported(mode) => [0x2612, 0x262e],
            Self::DoubleClick | Self::TripleClick if matches!(mode, Mode::Target(_)) => {
                let slot = if self == Self::DoubleClick { 1 } else { 2 };
                // Direct stock clicks keep their verified list even when the
                // shooting-slot table points at a custom program.
                let value = if slot == 1 { 0xc1f0 } else { 0xc1ec };
                let clicks = if self == Self::DoubleClick { 2 } else { 3 };
                let mut expected = Vec::new();
                for i in 0..clicks {
                    expected.extend([
                        0x2501_u16,
                        0x2819,
                        0x2401,
                        if i + 1 == clicks { 0x262f } else { 0x2855 },
                    ]);
                }
                let start = 0xe200 + 2 * usize::from(value & 0x3fff);
                if expected
                    .iter()
                    .enumerate()
                    .any(|(i, v)| word(image, start + 2 * i) != *v)
                {
                    return Err("stock click program instructions differ".into());
                }
                [value, 0x262e]
            }
            _ => return Err("button action is unavailable for this firmware".into()),
        })
    }
}
/// Extra assignments use GUI/profile ordinals. Aux direction/click association
/// is established by the physical mapping test, not inferred from KeyCodeIndex.
#[derive(Clone, Copy, Debug)]
pub enum ExtraControl {
    ExtraClick,
    Precision,
    Aux1,
    AuxN,
    Aux3,
}
impl ExtraControl {
    pub const ALL: [Self; 5] = [
        Self::ExtraClick,
        Self::Precision,
        Self::Aux1,
        Self::AuxN,
        Self::Aux3,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::ExtraClick => "Extra click button",
            Self::Precision => "Precision button",
            Self::Aux1 => "Aux wheel click",
            Self::AuxN => "Aux wheel toward front",
            Self::Aux3 => "Aux wheel toward rear",
        }
    }
    pub(crate) fn trigger(self) -> usize {
        match self {
            Self::ExtraClick => 7,
            Self::Precision => 14,
            Self::Aux1 => 9,
            Self::AuxN => 10,
            Self::Aux3 => 11,
        }
    }
}
fn preserve_extras() -> [Button; 5] {
    [Button::Preserve; 5]
}

fn cpi_xy_empty(values: &[Option<[u16; 2]>; 5]) -> bool {
    values.iter().all(Option::is_none)
}
fn cpi_xy_approx_empty(values: &[Option<[u32; 2]>; 5]) -> bool {
    values.iter().all(Option::is_none)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub operation: Operation,
    pub entry: Mode,
    #[serde(default)]
    pub cpi: [Option<u16>; 5],
    #[serde(default, skip_serializing_if = "cpi_xy_empty")]
    pub cpi_xy: [Option<[u16; 2]>; 5],
    pub report_rate_hz: Option<u16>,
    #[serde(default)]
    pub shooting_slot: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_shooting: Option<crate::program::internal::Edit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button_macro: Option<crate::macros::storage::Edit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_lighting: Option<crate::lighting::PersistentEdit>,
    pub side_buttons: [Button; 2],
    #[serde(default = "preserve_extras")]
    pub extra_buttons: [Button; 5],
    #[serde(default)]
    pub restore_after: bool,
    #[serde(default)]
    pub budget: Option<PathBuf>,
    #[serde(default)]
    pub model_entry: Option<PathBuf>,
}
impl Settings {
    pub fn validate(&self, core: Core) -> Result<(), String> {
        if let Some(edit) = &self.button_macro {
            if self.operation != Operation::Configure || self.custom_shooting.is_some() {
                return Err(
                    "button macro edits require Configure and no shooting-program edit".into(),
                );
            }
            crate::macros::storage::validate_edit(edit, self.entry)?;
            let check_preserve = |button: crate::macros::Target| -> Result<(), String> {
                if self
                    .side_buttons
                    .iter()
                    .chain(&self.extra_buttons)
                    .nth(button.index())
                    != Some(&Button::Preserve)
                {
                    Err("preserve the macro destination's ordinary assignment in this edit".into())
                } else {
                    Ok(())
                }
            };
            match edit {
                crate::macros::storage::Edit::Install { button, .. } => check_preserve(*button)?,
                crate::macros::storage::Edit::InstallAll { bindings } => {
                    for b in bindings {
                        check_preserve(b.button)?;
                    }
                }
                crate::macros::storage::Edit::Remove => {}
            }
        }
        if let Some(edit) = &self.custom_shooting {
            if self.operation != Operation::Configure {
                return Err("custom-program edits require Configure".into());
            }
            crate::program::internal::validate_edit(edit, self.entry)?;
        }
        if self.custom_lighting.is_some()
            && (self.operation != Operation::Configure || !matches!(self.entry, Mode::Target(_)))
        {
            return Err(
                "permanent internal lighting edits require Configure on prepared v0034 firmware"
                    .into(),
            );
        }
        if self.entry == Mode::Boot {
            return Err("boot mode requires original-backup restoration".into());
        }
        if self.operation == Operation::Configure
            && self.entry != Mode::Normal
            && self.entry != Mode::Target(core)
        {
            return Err("configuration cannot change the installed Core; choose Flash".into());
        }
        if self.operation == Operation::Configure && self.entry == Mode::Normal && core != Core::One
        {
            return Err("original firmware is Core 1; choose Flash to change Core".into());
        }
        let destination = if self.operation == Operation::Flash {
            Mode::Target(core)
        } else {
            self.entry
        };
        if self.operation != Operation::Inspect {
            for button in self.side_buttons.iter().chain(self.extra_buttons.iter()) {
                if !button.supported(destination) {
                    return Err(
                        "Ratmax has not qualified this action on the destination Core".into(),
                    );
                }
            }
            if self.shooting_slot.is_some_and(|slot| slot > 2)
                || (self.shooting_slot.is_some() && !shooting_supported(destination))
            {
                return Err(
                    "shooting-mode edits require prepared Core 2 or 3 and a slot from 0 to 2"
                        .into(),
                );
            }
        }
        for slot in 0..5 {
            if self.cpi[slot].is_some() && self.cpi_xy[slot].is_some() {
                return Err("specify either cpi or cpi_xy for a given slot, not both".into());
            }
            if let Some(value) = self.cpi[slot] {
                crate::settings::encode_cpi(value)?;
            }
            if let Some([x, y]) = self.cpi_xy[slot] {
                crate::settings::encode_cpi_xy(x, y)?;
            }
        }
        if let Some(rate) = self.report_rate_hz {
            crate::settings::encode_report_rate(rate)?;
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub schema: u8,
    pub baseline: PathBuf,
    pub backup: PathBuf,
    pub assets: PathBuf,
    pub sessions: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Budget {
    schema: u8,
    native: bool,
    baseline_sha256: String,
    backup_sha256: String,
}
pub(crate) fn validate_budget(
    root: &Path,
    baseline: &str,
    backup_sha256: &str,
    native: bool,
) -> Result<(), String> {
    let value: Budget = serde_json::from_slice(&crate::preview::read_file(
        &root.join("read-budget.json"),
        65536,
    )?)
    .map_err(|e| e.to_string())?;
    if value.schema != 1
        || value.native != native
        || value.baseline_sha256 != baseline
        || value.backup_sha256 != backup_sha256
    {
        return Err("read budget belongs to another unit or execution mode".into());
    }
    Ok(())
}
impl Workspace {
    /// Resolve workspace from `RATMAX_WORKSPACE` (empty disables lookup),
    /// `$XDG_CONFIG_HOME/ratmax/workspace.json`, `$HOME/.config/ratmax/workspace.json`,
    /// or `$SUDO_USER`'s `~/.config/ratmax/workspace.json`.
    pub fn default_path() -> Option<PathBuf> {
        if let Some(value) = std::env::var_os("RATMAX_WORKSPACE") {
            return (!value.is_empty()).then(|| PathBuf::from(value));
        }
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
            && !xdg.is_empty()
        {
            let candidate = PathBuf::from(xdg).join("ratmax").join("workspace.json");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        if let Some(home) = std::env::var_os("HOME")
            && !home.is_empty()
        {
            let candidate = PathBuf::from(home)
                .join(".config")
                .join("ratmax")
                .join("workspace.json");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        if let Ok(user) = std::env::var("SUDO_USER")
            && !user.is_empty()
            && user != "root"
            && let Ok(passwd) = std::fs::read_to_string("/etc/passwd")
            && let Some(home) = passwd_home(&passwd, &user)
        {
            let candidate = home.join(".config").join("ratmax").join("workspace.json");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    pub fn resolve_default() -> Result<PathBuf, String> {
        Self::default_path().ok_or_else(|| {
            "workspace not found; set RATMAX_WORKSPACE or create ~/.config/ratmax/workspace.json"
                .into()
        })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let mut value: Self = serde_json::from_slice(&crate::preview::read_file(path, 65536)?)
            .map_err(|e| e.to_string())?;
        if value.schema != 1 {
            return Err("unsupported workspace schema".into());
        }
        let root = path.parent().unwrap_or(Path::new("."));
        for p in [&mut value.baseline, &mut value.backup, &mut value.assets] {
            *p = std::fs::canonicalize(root.join(&*p)).map_err(|e| e.to_string())?;
        }
        value.sessions = root.join(value.sessions);
        if !value.sessions.is_absolute() {
            value.sessions = std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(value.sessions);
        }
        crate::backup_restore::Plan::load(&value.backup)?;
        boot_roundtrip::load(&value.baseline)?;
        Ok(value)
    }
    pub fn create_budget(&self, model: bool) -> Result<PathBuf, String> {
        std::fs::create_dir_all(&self.sessions).map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let root = crate::access_session::create_output(&self.sessions.join(format!(
            "{}-{stamp}",
            if model { "model" } else { "device" }
        )))?;
        let reference = boot_roundtrip::load(&self.baseline)?;
        let backup_plan = crate::backup_restore::Plan::load(&self.backup)?;
        let budget = Budget {
            schema: 1,
            native: !model,
            baseline_sha256: reference.baseline.fingerprint(),
            backup_sha256: backup_plan.sha256().into(),
        };
        boot_roundtrip::save_artifact(
            &root.join("read-budget.json"),
            &serde_json::to_vec_pretty(&budget).map_err(|e| e.to_string())?,
        )?;
        Ok(root)
    }
    pub fn request(&self, core: Core, settings: Settings) -> Request {
        Request {
            schema: 1,
            baseline: self.baseline.clone(),
            backup: self.backup.clone(),
            assets: self.assets.clone(),
            core,
            observation_seconds: 0,
            shooting_comparison: false,
            workflow: Some(settings),
        }
    }
    /// Cached USB metadata only. No device handle or report is used here.
    pub fn inspect(&self) -> Result<serde_json::Value, String> {
        let reference = boot_roundtrip::load(&self.baseline)?;
        let backup_plan = crate::backup_restore::Plan::load(&self.backup)?;
        let report = crate::discovery::collect(Path::new("/sys"))?;
        let found = boot_roundtrip::select_normal_mode(&report, reference.baseline.binding())?
            .map(|(mode, binding)| vec![serde_json::json!({"mode":mode,"binding":binding})])
            .unwrap_or_default();
        Ok(
            serde_json::json!({"candidates":found,"backup_sha256":backup_plan.sha256(),"physical_execution_available":available(),"device_reports":0}),
        )
    }
    pub fn export_backup(&self, output: &Path) -> Result<serde_json::Value, String> {
        let backup_plan = crate::backup_restore::Plan::load(&self.backup)?;
        let output = crate::access_session::create_output(output)?;
        for name in [
            "session.json",
            "normal-image.pass0.bin",
            "normal-image.pass1.bin",
        ] {
            boot_roundtrip::save_artifact(
                &output.join(name),
                &crate::preview::read_file(&self.backup.join(name), 1_048_576)?,
            )?;
        }
        let result = serde_json::json!({"verified":true,"bytes":65536,"sha256":backup_plan.sha256(),"device_operations":0,"source":self.backup});
        boot_roundtrip::save_artifact(
            &output.join("export.json"),
            &serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?,
        )?;
        Ok(result)
    }
}
pub fn available() -> bool {
    PHYSICAL_WORKFLOW_RELEASED && boot_roundtrip::workflow_transport_available()
}
pub fn prepare(project: &Path, output: &Path, simulate: bool) -> Result<serde_json::Value, String> {
    let p = Plan::load(project)?;
    if p.request.workflow.is_none() {
        return Err("workflow settings are required".into());
    }
    if simulate {
        boot_roundtrip::simulate_workflow(project, output, false)
    } else {
        pipeline::prepare(project, output, false)
    }
}
pub fn simulate_restore(session: &Path, output: &Path) -> Result<serde_json::Value, String> {
    boot_roundtrip::simulate_workflow(session, output, true)
}
pub fn run(project: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical workflow is disabled in this build".into());
    }
    let p = Plan::load(project)?;
    if p.request.workflow.is_none() {
        return Err("workflow settings are required".into());
    }
    if p.request
        .workflow
        .as_ref()
        .is_some_and(|w| w.model_entry.is_some())
    {
        return Err("model state cannot authorize physical execution".into());
    }
    boot_roundtrip::run_workflow(project, output, false)
}
pub fn restore(session: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical workflow restoration is disabled in this build".into());
    }
    if !session.join("cycle.json").is_file() {
        return Err("workflow session directory is missing cycle.json".into());
    }
    boot_roundtrip::run_workflow(session, output, true)
}
fn word(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(image[at..at + 2].try_into().unwrap())
}
fn put(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// Accept only the original unit's settings or settings produced by this editor.
fn validate_sensitivity(image: &[u8], original: &[u8]) -> Result<(), String> {
    let block = &image[0xe000..0xe100];
    let gold = &original[0xe000..0xe100];
    if block[..4] != [0xa4; 4]
        || crate::sensitivity_block::checksums(block)? != (word(image, 0xe004), word(image, 0xe006))
    {
        return Err("current sensitivity block checksum or marker differs".into());
    }
    for i in 0..256 {
        if (4..8).contains(&i) || (12..42).contains(&i) || (60..62).contains(&i) {
            continue;
        }
        if block[i] != gold[i] {
            return Err(format!("unowned sensitivity byte {i:02X}"));
        }
    }
    for slot in 0..5 {
        let at = 12 + 6 * slot;
        let words = [
            word(image, 0xe000 + at),
            word(image, 0xe002 + at),
            word(image, 0xe004 + at),
        ];
        if block[at..at + 6] != gold[at..at + 6] && !crate::settings::valid_cpi_words(words) {
            return Err("unsupported current CPI encoding".into());
        }
    }
    if ![1, 2, 4, 8, 17].contains(&word(image, 0xe03c)) {
        return Err("unsupported current report rate".into());
    }
    Ok(())
}
pub(crate) fn side_address(mode: Mode) -> usize {
    if mode == Mode::Normal { 0xe274 } else { 0xe2bc }
}
pub(crate) fn extra_address(mode: Mode, control: ExtraControl) -> usize {
    let table = if mode == Mode::Normal { 0xe268 } else { 0xe2b0 };
    table + 4 * (control.trigger() - 1)
}
fn control_addresses(mode: Mode) -> [usize; 7] {
    let side = side_address(mode);
    [
        side,
        side + 4,
        extra_address(mode, ExtraControl::ExtraClick),
        extra_address(mode, ExtraControl::Precision),
        extra_address(mode, ExtraControl::Aux1),
        extra_address(mode, ExtraControl::AuxN),
        extra_address(mode, ExtraControl::Aux3),
    ]
}
fn apply_pair(image: &mut [u8], start: usize, pair: [u16; 2]) {
    for (part, value) in pair.into_iter().enumerate() {
        let at = start + 2 * part;
        let delta = value.wrapping_sub(word(image, at));
        let sum = word(image, 0xe204).wrapping_add(delta);
        let weighted =
            word(image, 0xe206).wrapping_add((((at - 0xe200) / 2) as u16).wrapping_mul(delta));
        put(image, 0xe204, sum);
        put(image, 0xe206, weighted);
        put(image, at, value);
    }
}
fn update_buttons(
    image: &mut [u8],
    canonical: &[u8],
    mode: Mode,
    settings: &Settings,
) -> Result<(), String> {
    let buttons = settings
        .side_buttons
        .into_iter()
        .chain(settings.extra_buttons);
    for (at, button) in control_addresses(mode).into_iter().zip(buttons) {
        let pair = match button {
            Button::Preserve => continue,
            Button::Default => [word(canonical, at), word(canonical, at + 2)],
            _ => button.words(mode, canonical)?,
        };
        apply_pair(image, at, pair);
    }
    Ok(())
}
/// Program only the original main prefix through the last changed 32-byte block.
/// Later aliases/opaque bytes are fresh-captured and must match unchanged.
pub(crate) fn original_main_bytes(before: &[u8], after: &[u8]) -> usize {
    let end = before[0xe200..0xe700]
        .iter()
        .zip(&after[0xe200..0xe700])
        .rposition(|(a, b)| a != b)
        .map_or(0, |i| i + 1);
    end.div_ceil(32) * 32
}
pub(crate) fn extended_profile_pages(image: &[u8]) -> Result<usize, String> {
    let mg = crate::macros::storage::extended_pages(image)?
        .max(crate::program::internal::extended_pages(image)?);
    let lg = crate::lighting::extended_pages(image)?;
    Ok(mg.max(lg))
}

pub(crate) fn configured_main_bytes(before: &[u8], goal: &[u8]) -> usize {
    let before_pages = extended_profile_pages(before).unwrap_or(0);
    let goal_pages = extended_profile_pages(goal).unwrap_or(0);
    0x500 + 64 * before_pages.max(goal_pages)
}

pub(crate) fn validate_owned(
    image: &[u8],
    canonical: &[u8],
    original: &[u8],
    mode: Mode,
) -> Result<(), String> {
    validate_sensitivity(image, original)?;
    let mut expected = canonical.to_vec();
    let priors = crate::macros::storage::priors(image, canonical, mode)?;
    for at in control_addresses(mode) {
        let pair = priors
            .iter()
            .find(|(target, _)| target.address() == at)
            .map_or_else(|| [word(image, at), word(image, at + 2)], |(_, pair)| *pair);
        let stock = [word(canonical, at), word(canonical, at + 2)];
        if pair != stock
            && !Button::ALL
                .into_iter()
                .any(|b| b.words(mode, canonical).ok() == Some(pair))
        {
            return Err("current control assignment is outside the supported set".into());
        }
        apply_pair(&mut expected, at, pair);
    }
    if !priors.is_empty() {
        crate::macros::storage::admit(image, &mut expected, canonical, mode)?;
    } else {
        crate::program::internal::admit(image, &mut expected, canonical, mode)?;
    }
    let mg_pages = crate::macros::storage::extended_pages(&expected)?
        .max(crate::program::internal::extended_pages(&expected)?);
    if let Some(light) = crate::lighting::decode_persistent(image, mode)? {
        crate::lighting::install_persistent(&mut expected, canonical, mode, &light, mg_pages)?;
    }
    let owned_end = 0xe700 + 64 * extended_profile_pages(image)?;
    if image[0xe200..owned_end] != expected[0xe200..owned_end] {
        return Err("profile is not stock/Ratmax-owned; refusing to overwrite it".into());
    }
    Ok(())
}
pub(crate) fn configure(
    mut image: Vec<u8>,
    canonical: &[u8],
    mode: Mode,
    settings: &Settings,
) -> Result<Vec<u8>, String> {
    for slot in 0..5 {
        let encoded = if let Some([x, y]) = settings.cpi_xy[slot] {
            Some(crate::settings::encode_cpi_xy(x, y)?)
        } else if let Some(cpi) = settings.cpi[slot] {
            Some(crate::settings::encode_cpi(cpi)?)
        } else {
            None
        };
        if let Some(words) = encoded {
            for (part, value) in words.into_iter().enumerate() {
                put(&mut image, 0xe00c + 6 * slot + 2 * part, value);
            }
        }
    }
    if let Some(rate) = settings.report_rate_hz {
        put(
            &mut image,
            0xe03c,
            crate::settings::encode_report_rate(rate)?,
        );
    }
    let (sum, weighted) = crate::sensitivity_block::checksums(&image[0xe000..0xe100])?;
    put(&mut image, 0xe004, sum);
    put(&mut image, 0xe006, weighted);
    // Strip any installed internal-flash lighting before macros/GunA modify the tail,
    // then re-pack either the preserved or newly requested lighting right after them.
    let existing_lighting = crate::lighting::strip_persistent(&mut image, mode)?;
    let installed_priors = crate::macros::storage::priors(&image, canonical, mode)?;
    if !installed_priors.is_empty() {
        if settings.custom_shooting.is_some() {
            return Err(
                "remove the ordinary button macro before editing a shooting program".into(),
            );
        }
        if settings.button_macro.is_some() {
            crate::macros::storage::apply(
                &mut image,
                canonical,
                mode,
                &crate::macros::storage::Edit::Remove,
            )?;
        } else {
            for (target, _) in installed_priors {
                let assignment = settings
                    .side_buttons
                    .iter()
                    .chain(&settings.extra_buttons)
                    .nth(target.index());
                if assignment != Some(&Button::Preserve) {
                    crate::macros::storage::remove_target(&mut image, canonical, mode, target)?;
                }
            }
        }
    }
    update_buttons(&mut image, canonical, mode, settings)?;
    if let Some(edit) = &settings.button_macro {
        crate::macros::storage::apply(&mut image, canonical, mode, edit)?;
    }
    if let Some(edit) = &settings.custom_shooting {
        crate::program::internal::apply(&mut image, canonical, mode, edit)?;
    }
    let target_lighting = match &settings.custom_lighting {
        Some(crate::lighting::PersistentEdit::Install {
            leds, breathing, ..
        }) => Some(crate::lighting::PersistentLighting {
            leds: *leds,
            breathing: *breathing,
        }),
        Some(crate::lighting::PersistentEdit::Remove) => None,
        None => existing_lighting,
    };
    if let Some(light) = target_lighting {
        let mg_pages = crate::macros::storage::extended_pages(&image)?
            .max(crate::program::internal::extended_pages(&image)?);
        crate::lighting::install_persistent(&mut image, canonical, mode, &light, mg_pages)?;
    }
    Ok(image)
}

/// Stored configuration decoded from the bounded, validated settings/profile
/// capture. Approximate CPI reflects the firmware's equal-axis quantization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentConfiguration {
    pub schema: u8,
    pub mode: Mode,
    pub cpi_approx: [Option<u32>; 5],
    #[serde(default, skip_serializing_if = "cpi_xy_approx_empty")]
    pub cpi_xy_approx: [Option<[u32; 2]>; 5],
    pub selected_cpi_slot: Option<u16>,
    pub report_rate_hz: Option<u16>,
    pub side_buttons: [CurrentControl; 2],
    pub extra_buttons: [CurrentControl; 5],
    pub shooting_slot: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_shooting: Option<crate::program::gun_a::GunA>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button_macro: Option<crate::macros::storage::Current>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub button_macros: Vec<crate::macros::storage::Current>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_lighting: Option<crate::lighting::PersistentLighting>,
    pub sensitivity_uses_stock_default: bool,
    pub profile_uses_stock_default: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentControl {
    pub description: String,
    pub action: Option<Button>,
}
pub(crate) fn current_configuration(
    image: &[u8],
    mode: Mode,
    shooting_slot: Option<u8>,
    sensitivity_uses_stock_default: bool,
    profile_uses_stock_default: bool,
) -> Result<CurrentConfiguration, String> {
    if image.len() != 65536 || mode == Mode::Boot {
        return Err("current configuration requires a validated normal-mode image".into());
    }
    let cpi_xy_approx = std::array::from_fn(|slot| {
        if sensitivity_uses_stock_default {
            return None;
        }
        let at = 0xe00c + 6 * slot;
        crate::settings::decode_cpi_xy([word(image, at), word(image, at + 2), word(image, at + 4)])
    });
    let cpi_approx = std::array::from_fn(|slot| {
        cpi_xy_approx[slot].and_then(|[x, y]| (x == y).then_some(x))
    });
    let macro_list = crate::macros::storage::summary_all(image)?;
    let macro_info = (macro_list.len() == 1).then(|| macro_list[0].clone());
    let decode = |at| {
        if macro_list.iter().any(|m| m.button.address() == at) {
            return CurrentControl {
                description: "Custom macro".into(),
                action: None,
            };
        }
        let pair = [word(image, at), word(image, at + 2)];
        if let Some(action) = Button::ALL
            .into_iter()
            .find(|b| b.words(mode, image).ok() == Some(pair))
        {
            return CurrentControl {
                description: action.name().into(),
                action: Some(action),
            };
        }
        let description = match pair {
            [0x262a, 0x262e] => "CPI cycle (stock)",
            [0x2627, 0x262e] => "CPI increase (stock)",
            [0x2625, 0x262e] => "CPI decrease (stock)",
            _ => "Existing stock assignment",
        };
        CurrentControl {
            description: description.into(),
            action: None,
        }
    };
    let side = side_address(mode);
    Ok(CurrentConfiguration {
        schema: 1,
        mode,
        cpi_approx,
        cpi_xy_approx,
        selected_cpi_slot: (!sensitivity_uses_stock_default).then(|| word(image, 0xe00a)),
        report_rate_hz: match if sensitivity_uses_stock_default {
            0
        } else {
            word(image, 0xe03c)
        } {
            1 => Some(1000),
            2 => Some(500),
            4 => Some(250),
            8 => Some(125),
            17 => Some(2000),
            _ => None,
        },
        side_buttons: [decode(side), decode(side + 4)],
        extra_buttons: ExtraControl::ALL.map(|c| decode(extra_address(mode, c))),
        shooting_slot,
        custom_shooting: crate::program::internal::current(image, mode)?,
        button_macro: macro_info,
        button_macros: macro_list,
        custom_lighting: if profile_uses_stock_default {
            None
        } else {
            crate::lighting::decode_persistent(image, mode)?
        },
        sensitivity_uses_stock_default,
        profile_uses_stock_default,
    })
}

fn passwd_home(contents: &str, user: &str) -> Option<PathBuf> {
    contents.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        if name != user {
            return None;
        }
        let home = fields.nth(4)?;
        (!home.is_empty()).then(|| PathBuf::from(home))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_home_extracts_matching_user_directory() {
        let sample = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n";
        assert_eq!(passwd_home(sample, "alice"), Some(PathBuf::from("/home/alice")));
        assert_eq!(passwd_home(sample, "missing"), None);
    }
}
