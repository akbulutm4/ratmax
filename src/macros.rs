//! Structured button macros, shared by the editor, preview and device workflow.
pub mod storage;
use crate::{model::Core, program::ProgramWords};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    Back,
    Forward,
    ExtraClick,
    Precision,
    AuxClick,
    AuxFront,
    AuxRear,
}
impl Target {
    pub const ALL: [Self; 7] = [
        Self::Back,
        Self::Forward,
        Self::ExtraClick,
        Self::Precision,
        Self::AuxClick,
        Self::AuxFront,
        Self::AuxRear,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Back => "Back",
            Self::Forward => "Forward",
            Self::ExtraClick => "Extra click button",
            Self::Precision => "Precision button",
            Self::AuxClick => "Aux wheel click",
            Self::AuxFront => "Aux wheel toward front",
            Self::AuxRear => "Aux wheel toward rear",
        }
    }
    pub(crate) fn address(self) -> usize {
        [0xe2bc, 0xe2c0, 0xe2c8, 0xe2e4, 0xe2d0, 0xe2d4, 0xe2d8][self.index()]
    }
    pub(crate) fn index(self) -> usize {
        Self::ALL.iter().position(|v| *v == self).unwrap()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mouse {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}
impl Mouse {
    pub(crate) fn mask(self) -> u16 {
        match self {
            Self::Left => 1,
            Self::Right => 2,
            Self::Middle => 4,
            Self::Back => 8,
            Self::Forward => 16,
        }
    }
    pub(crate) fn from_mask(mask: u16) -> Option<Self> {
        [
            Self::Left,
            Self::Right,
            Self::Middle,
            Self::Back,
            Self::Forward,
        ]
        .into_iter()
        .find(|v| v.mask() == mask)
    }
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "left" => Ok(Self::Left),
            "right" => Ok(Self::Right),
            "middle" => Ok(Self::Middle),
            "back" => Ok(Self::Back),
            "forward" => Ok(Self::Forward),
            _ => Err("mouse button: left/right/middle/back/forward".into()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Step {
    Tap { key: String, hold_ms: u16 },
    KeyDown { key: String },
    KeyUp { key: String },
    Click { button: Mouse, hold_ms: u16 },
    MouseDown { button: Mouse },
    MouseUp { button: Mouse },
    Delay { ms: u16 },
    Move { x: i16, y: i16 },
}
impl Step {
    pub fn parse(line: &str) -> Result<Self, String> {
        let s = line.to_ascii_lowercase();
        let p: Vec<_> = s.split_whitespace().collect();
        let number = |s: &str| {
            s.parse::<u16>()
                .map_err(|_| "expected a positive millisecond value".to_string())
        };
        match p.as_slice() {
            ["tap", key] => Ok(Self::Tap {
                key: key.to_string(),
                hold_ms: 20,
            }),
            ["tap", key, ms] => Ok(Self::Tap {
                key: key.to_string(),
                hold_ms: number(ms)?,
            }),
            ["down", key] => Ok(Self::KeyDown {
                key: key.to_string(),
            }),
            ["up", key] => Ok(Self::KeyUp {
                key: key.to_string(),
            }),
            ["click", button] => Ok(Self::Click {
                button: Mouse::parse(button)?,
                hold_ms: 20,
            }),
            ["click", button, ms] => Ok(Self::Click {
                button: Mouse::parse(button)?,
                hold_ms: number(ms)?,
            }),
            ["mouse-down", button] => Ok(Self::MouseDown {
                button: Mouse::parse(button)?,
            }),
            ["mouse-up", button] => Ok(Self::MouseUp {
                button: Mouse::parse(button)?,
            }),
            ["delay", ms] => Ok(Self::Delay { ms: number(ms)? }),
            ["move", x, y] => Ok(Self::Move {
                x: x.parse().map_err(|_| "invalid X movement")?,
                y: y.parse().map_err(|_| "invalid Y movement")?,
            }),
            _ => Err("Use tap ctrl+c, down a, up a, click left, delay 100, or move 0 -12".into()),
        }
    }
}
impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tap { key, hold_ms } => write!(f, "tap {key} {hold_ms}"),
            Self::KeyDown { key } => write!(f, "down {key}"),
            Self::KeyUp { key } => write!(f, "up {key}"),
            Self::Click { button, hold_ms } => write!(
                f,
                "click {} {hold_ms}",
                format!("{button:?}").to_lowercase()
            ),
            Self::MouseDown { button } => {
                write!(f, "mouse-down {}", format!("{button:?}").to_lowercase())
            }
            Self::MouseUp { button } => {
                write!(f, "mouse-up {}", format!("{button:?}").to_lowercase())
            }
            Self::Delay { ms } => write!(f, "delay {ms}"),
            Self::Move { x, y } => write!(f, "move {x} {y}"),
        }
    }
}
fn one() -> u8 {
    1
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sequence {
    #[serde(default)]
    pub press: Vec<Step>,
    #[serde(default)]
    pub release: Vec<Step>,
    #[serde(default = "one")]
    pub repeat: u8,
}
impl Default for Sequence {
    fn default() -> Self {
        Self {
            press: vec![],
            release: vec![],
            repeat: 1,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub button: Target,
    pub name: String,
    pub program: Sequence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub core: Core,
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema_version: u8,
    pub model: crate::model::Model,
    pub macros: Project,
}
impl Document {
    pub fn empty(core: Core) -> Self {
        Self {
            schema_version: 1,
            model: crate::model::Model::W95Max,
            macros: Project {
                core,
                bindings: Target::ALL
                    .into_iter()
                    .map(|button| Binding {
                        button,
                        name: button.name().into(),
                        program: Sequence::default(),
                    })
                    .collect(),
            },
        }
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let d: Self = serde_json::from_slice(&crate::preview::read_file(path, 65536)?)
            .map_err(|e| e.to_string())?;
        d.validate()?;
        Ok(d)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !matches!(self.macros.core, Core::Three | Core::Four)
            || self.macros.bindings.len() > 7
        {
            return Err(
                "macro project requires schema 1, Core 3/4, and at most seven buttons".into(),
            );
        }
        let mut targets = BTreeSet::new();
        for b in &self.macros.bindings {
            if !targets.insert(b.button)
                || b.name.chars().count() > 64
                || b.name.chars().any(char::is_control)
                || b.program.press.len() > 128
                || b.program.release.len() > 128
                || !(1..=16).contains(&b.program.repeat)
            {
                return Err(
                    "duplicate button, invalid name, too many steps, or repeat outside 1..16"
                        .into(),
                );
            }
        }
        Ok(())
    }
    /// Incomplete drafts may be saved; compilation/application still validates them.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        self.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = parent.canonicalize().map_err(|e| e.to_string())?;
        if ["/dev", "/sys", "/proc"]
            .iter()
            .any(|p| directory.starts_with(p))
        {
            return Err("save projects in a regular local directory".into());
        }
        if path.exists() {
            crate::preview::read_file(path, 65536)?;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let tmp = parent.join(format!(".ratmax-macros-{}-{stamp}.tmp", std::process::id()));
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        if bytes.len() + 1 > 65536 {
            return Err("project exceeds 64 KiB".into());
        }
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, path).map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(tmp);
        }
        result
    }
}

/// USB Keyboard/Keypad page usages; names represent physical keys, not text.
pub fn key_usage(name: &str) -> Result<u8, String> {
    let key = name.to_ascii_lowercase();
    if key.len() == 1 {
        let c = key.as_bytes()[0];
        if c.is_ascii_lowercase() {
            return Ok(c - b'a' + 4);
        }
        if c.is_ascii_digit() {
            return Ok(if c == b'0' { 0x27 } else { c - b'1' + 0x1e });
        }
    }
    if let Some(n) = key.strip_prefix('f').and_then(|s| s.parse::<u8>().ok()) {
        if (1..=12).contains(&n) {
            return Ok(0x39 + n);
        }
        if (13..=24).contains(&n) {
            return Ok(0x68 + n - 13);
        }
    }
    let value = match key.as_str() {
        "enter" | "return" => 0x28,
        "esc" | "escape" => 0x29,
        "backspace" => 0x2a,
        "tab" => 0x2b,
        "space" => 0x2c,
        "minus" => 0x2d,
        "equal" => 0x2e,
        "left-bracket" => 0x2f,
        "right-bracket" => 0x30,
        "backslash" => 0x31,
        "semicolon" => 0x33,
        "quote" => 0x34,
        "grave" => 0x35,
        "comma" => 0x36,
        "period" => 0x37,
        "slash" => 0x38,
        "capslock" => 0x39,
        "printscreen" => 0x46,
        "scrolllock" => 0x47,
        "pause" => 0x48,
        "insert" => 0x49,
        "home" => 0x4a,
        "pageup" => 0x4b,
        "delete" => 0x4c,
        "end" => 0x4d,
        "pagedown" => 0x4e,
        "right" => 0x4f,
        "left" => 0x50,
        "down" => 0x51,
        "up" => 0x52,
        "ctrl" | "lctrl" => 0xe0,
        "shift" | "lshift" => 0xe1,
        "alt" | "lalt" => 0xe2,
        "super" | "gui" | "win" | "lsuper" => 0xe3,
        "rctrl" => 0xe4,
        "rshift" => 0xe5,
        "ralt" => 0xe6,
        "rsuper" => 0xe7,
        _ => {
            if let Some(raw) = key.strip_prefix("hid:") {
                let n = raw
                    .strip_prefix("0x")
                    .map_or_else(|| raw.parse::<u8>(), |s| u8::from_str_radix(s, 16))
                    .map_err(|_| "invalid HID usage")?;
                if (4..=0x97).contains(&n) || (0xe0..=0xe7).contains(&n) {
                    return Ok(n);
                }
                return Err("HID usage must be 4..97 or modifier E0..E7".into());
            } else {
                return Err(format!("unknown key {name}; use a key name or hid:0xNN"));
            }
        }
    };
    Ok(value)
}
fn key_word(usage: u8, down: bool) -> u16 {
    if usage >= 0xe0 {
        (if down { 0x2300 } else { 0x2200 }) | (1 << (usage - 0xe0))
    } else {
        (if down { 0x2100 } else { 0x2000 }) | u16::from(usage)
    }
}
#[derive(Default)]
struct Builder {
    words: Vec<u16>,
    held: BTreeSet<u8>,
    mouse: u16,
    ms: u32,
}
impl Builder {
    fn key(&mut self, key: u8, down: bool) -> Result<(), String> {
        if if down {
            !self.held.insert(key)
        } else {
            !self.held.remove(&key)
        } {
            return Err("duplicate key down or key up without matching down".into());
        }
        if self.held.iter().filter(|k| **k < 0xe0).count() > 6 {
            return Err("at most six ordinary keys may be held together".into());
        }
        self.words.push(key_word(key, down));
        Ok(())
    }
    fn mouse(&mut self, b: Mouse, down: bool) -> Result<(), String> {
        let mask = b.mask();
        if (self.mouse & mask != 0) == down {
            return Err("duplicate mouse down or mouse up without matching down".into());
        }
        if down {
            self.mouse |= mask;
        } else {
            self.mouse &= !mask;
        }
        self.words.push((if down { 0x2500 } else { 0x2400 }) | mask);
        Ok(())
    }
    fn delay(&mut self, ms: u16) -> Result<(), String> {
        if ms == 0 {
            return Err("delay must be at least 1 ms".into());
        }
        self.ms += u32::from(ms);
        let mut remaining = ms;
        while remaining > 0 {
            let part = remaining.min(999);
            self.words.push(0x2800 + part);
            remaining -= part;
        }
        Ok(())
    }
    fn step(&mut self, s: &Step) -> Result<(), String> {
        match s {
            Step::KeyDown { key } => self.key(key_usage(key)?, true)?,
            Step::KeyUp { key } => self.key(key_usage(key)?, false)?,
            Step::Tap { key, hold_ms } => {
                let keys: Vec<_> = key.split('+').map(key_usage).collect::<Result<_, _>>()?;
                let Some((&last, mods)) = keys.split_last() else {
                    return Err("empty shortcut".into());
                };
                if last >= 0xe0
                    || mods.iter().any(|m| *m < 0xe0)
                    || keys.iter().copied().collect::<BTreeSet<_>>().len() != keys.len()
                {
                    return Err(
                        "shortcut needs distinct modifiers followed by one ordinary key".into(),
                    );
                }
                let added: Vec<_> = mods
                    .iter()
                    .copied()
                    .filter(|m| !self.held.contains(m))
                    .collect();
                for m in &added {
                    self.key(*m, true)?;
                }
                self.key(last, true)?;
                self.delay(*hold_ms)?;
                self.key(last, false)?;
                for m in added.into_iter().rev() {
                    self.key(m, false)?;
                }
            }
            Step::Click { button, hold_ms } => {
                self.mouse(*button, true)?;
                self.delay(*hold_ms)?;
                self.mouse(*button, false)?;
            }
            Step::MouseDown { button } => self.mouse(*button, true)?,
            Step::MouseUp { button } => self.mouse(*button, false)?,
            Step::Delay { ms } => self.delay(*ms)?,
            Step::Move { x, y } => {
                if !(-64..=63).contains(x) || !(-64..=63).contains(y) {
                    return Err("relative movement must be -64..63 per axis".into());
                }
                self.words
                    .push(0x4000 + (((*x as u16) & 127) << 7) + ((*y as u16) & 127));
            }
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Compiled {
    pub words: ProgramWords,
    pub duration_ms: u32,
    pub repeat: u8,
    pub compact_tail_bytes: usize,
    pub extended_pages: usize,
    pub internal_bytes: usize,
    pub internal_installable: bool,
}
pub fn compile(program: &Sequence) -> Result<Compiled, String> {
    if !(1..=16).contains(&program.repeat)
        || program.press.len() > 128
        || program.release.len() > 128
    {
        return Err("repeat must be 1..16 and each event is limited to 128 steps".into());
    }
    if program.press.is_empty() && program.release.is_empty() {
        return Err("add at least one macro step".into());
    }
    let mut press_builder = Builder::default();
    for _ in 0..program.repeat {
        for (i, step) in program.press.iter().enumerate() {
            press_builder
                .step(step)
                .map_err(|e| format!("press step {}: {e}", i + 1))?;
        }
        if program.repeat > 1 && (!press_builder.held.is_empty() || press_builder.mouse != 0) {
            return Err(
                "press leaves a key/button held; add its matching up step (or set repeat to 1 to release it in On Release)"
                    .into(),
            );
        }
        if press_builder.words.len() > 4095 {
            return Err("compiled event exceeds 4096 words".into());
        }
    }
    let mut duration_ms = press_builder.ms;
    if !program.press.is_empty() {
        press_builder.words.push(0x262f);
    }

    let mut release_builder = Builder {
        words: Vec::new(),
        held: press_builder.held,
        mouse: press_builder.mouse,
        ms: 0,
    };
    for _ in 0..program.repeat {
        for (i, step) in program.release.iter().enumerate() {
            release_builder
                .step(step)
                .map_err(|e| format!("release step {}: {e}", i + 1))?;
        }
        if program.repeat > 1 && (!release_builder.held.is_empty() || release_builder.mouse != 0) {
            return Err("release leaves a key/button held; add its matching up step".into());
        }
        if release_builder.words.len() > 4095 {
            return Err("compiled event exceeds 4096 words".into());
        }
    }
    if !release_builder.held.is_empty() || release_builder.mouse != 0 {
        return Err(
            "macro leaves a key/button held after release; add its matching up step in On Press or On Release"
                .into(),
        );
    }
    duration_ms += release_builder.ms;
    if !program.release.is_empty() {
        release_builder.words.push(0x262f);
    }
    if duration_ms > 60_000 {
        return Err("total programmed delay exceeds 60 seconds".into());
    }
    let press = press_builder.words;
    let release = release_builder.words;
    let compact_tail_bytes = storage::compact_bytes(press.len(), release.len());
    let (internal_bytes, extended_pages, internal_installable) =
        storage::single_storage(press.len(), release.len());
    Ok(Compiled {
        words: ProgramWords {
            press,
            release: Some(release),
        },
        duration_ms,
        repeat: program.repeat,
        compact_tail_bytes,
        extended_pages,
        internal_bytes,
        internal_installable,
    })
}
#[derive(Serialize)]
pub struct BindingPreview {
    pub button: Target,
    pub name: String,
    pub compiled: Compiled,
}
#[derive(Serialize)]
pub struct ProjectPreview {
    pub core: Core,
    pub bindings: Vec<BindingPreview>,
    pub simultaneous_device_programs: usize,
    pub combined_internal_bytes: usize,
    pub combined_extended_pages: usize,
    pub combined_internal_installable: bool,
    pub write_ready: bool,
}
pub fn preview(p: &Project) -> Result<ProjectPreview, String> {
    let doc = Document {
        schema_version: 1,
        model: crate::model::Model::W95Max,
        macros: p.clone(),
    };
    doc.validate()?;
    let bindings: Vec<_> = p
        .bindings
        .iter()
        .filter(|b| !b.program.press.is_empty() || !b.program.release.is_empty())
        .map(|b| {
            Ok(BindingPreview {
                button: b.button,
                name: b.name.clone(),
                compiled: compile(&b.program)?,
            })
        })
        .collect::<Result<_, String>>()?;
    if bindings.is_empty() {
        return Err("add at least one macro step".into());
    }
    let word_pairs: Vec<(usize, usize)> = bindings
        .iter()
        .map(|b| {
            (
                b.compiled.words.press.len(),
                b.compiled.words.release.as_deref().unwrap_or_default().len(),
            )
        })
        .collect();
    let (combined_internal_bytes, combined_extended_pages, combined_internal_installable) =
        storage::combined_storage(&word_pairs);
    Ok(ProjectPreview {
        core: p.core,
        bindings,
        simultaneous_device_programs: Target::ALL.len(),
        combined_internal_bytes,
        combined_extended_pages,
        combined_internal_installable,
        write_ready: false,
    })
}
