//! Audited W95 Max RGB lighting codecs and bounded runtime control.
//!
//! Covers two zero-NOR-write hardware paths audited on Core 3 and Core 4 v0034:
//! - `07 11`: read/set persistent brightness level (`0=Off`, `1=25%`, `2=50%`, `3=100%`).
//! - `07 03 06`: read lighting status (`05`), enable/disable live RAM preview (`00`),
//!   set breathing speed (`01`, `0..4`), and write all 15 LED RGB triplets in a single
//!   64-byte Feature report (`02`).
use crate::{
    boot_roundtrip::{self, Mode},
    discovery, query_session,
    workflow::Workspace,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const LED_COUNT: usize = 15;
const PROFILE_BASE: usize = 0xe200;
const EXT_BASE: usize = 0xe700;
const EXT_END: usize = 0xfe80;
const LIGHTING_MAGIC: u16 = 0xa801;
const BLOCK_HEADER_BYTES: usize = 24; // 2 magic + 1 breathing + 1 flags + 20 saved table
const STREAM_BYTES: usize = 68; // 34 words: [1, breathing], [3, 50], 27 RGB words, [4, 0], [0xA4A4]
const BLOCK_PAGES: usize = 2;
const BLOCK_BYTES: usize = BLOCK_PAGES * 64; // 128 bytes
const FRAME_TICKS: u16 = 50;
const MODE_SLOTS: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentLighting {
    pub leds: [Rgb; LED_COUNT],
    pub breathing: Breathing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PersistentEdit {
    Install {
        leds: [Rgb; LED_COUNT],
        breathing: Breathing,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brightness: Option<Brightness>,
    },
    Remove,
}

fn word(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn put_word_delta(image: &mut [u8], at: usize, value: u16) {
    let old = word(image, at);
    if old == value {
        return;
    }
    let delta = value.wrapping_sub(old);
    let idx = ((at - PROFILE_BASE) / 2) as u16;
    let sum = word(image, PROFILE_BASE + 4).wrapping_add(delta);
    let weighted = word(image, PROFILE_BASE + 6).wrapping_add(idx.wrapping_mul(delta));
    image[PROFILE_BASE + 4..PROFILE_BASE + 6].copy_from_slice(&sum.to_le_bytes());
    image[PROFILE_BASE + 6..PROFILE_BASE + 8].copy_from_slice(&weighted.to_le_bytes());
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn lighting_table_addr(image: &[u8]) -> Result<usize, String> {
    if image.len() != 65536 {
        return Err("lighting storage inspection requires a complete image".into());
    }
    let w13 = word(image, PROFILE_BASE + 0x1a);
    let t = usize::from(w13 & 0x3fff);
    if t == 0 || 2 * t + MODE_SLOTS * 4 > 0x04d8 {
        return Err("profile lighting table offset is outside owned stock region".into());
    }
    Ok(PROFILE_BASE + 2 * t)
}

/// Detect a Ratmax internal-flash lighting block via the 5 mode pointers at `0xE200 + 2*T`.
/// Returns `Some(block_addr)` when all 5 mode pointers point to a page-aligned block at `>= 0xE700`.
fn detect_block_addr(image: &[u8]) -> Result<Option<(usize, usize)>, String> {
    if image.len() != 65536 || image[PROFILE_BASE..PROFILE_BASE + 4] != [0xa4; 4] {
        return Ok(None);
    }
    let Ok(table_addr) = lighting_table_addr(image) else {
        return Ok(None);
    };
    let first_lo = word(image, table_addr);
    let first_hi = word(image, table_addr + 2);
    if first_hi != 0 || first_lo < ((EXT_BASE + BLOCK_HEADER_BYTES - PROFILE_BASE) / 2) as u16 {
        return Ok(None);
    }
    for m in 1..MODE_SLOTS {
        if word(image, table_addr + 4 * m) != first_lo
            || word(image, table_addr + 4 * m + 2) != 0
        {
            return Ok(None);
        }
    }
    let stream_addr = PROFILE_BASE + 2 * usize::from(first_lo);
    let Some(block_addr) = stream_addr.checked_sub(BLOCK_HEADER_BYTES) else {
        return Ok(None);
    };
    if block_addr < EXT_BASE
        || !(block_addr - EXT_BASE).is_multiple_of(64)
        || block_addr + BLOCK_BYTES > EXT_END
    {
        return Err("invalid internal lighting block alignment or range".into());
    }
    Ok(Some((table_addr, block_addr)))
}

pub(crate) fn block_start(image: &[u8]) -> Result<Option<usize>, String> {
    Ok(detect_block_addr(image)?.map(|(_, block_addr)| block_addr))
}

pub(crate) fn extended_pages(image: &[u8]) -> Result<usize, String> {
    let Some((_, block_addr)) = detect_block_addr(image)? else {
        return Ok(0);
    };
    Ok((block_addr + BLOCK_BYTES - EXT_BASE) / 64)
}

pub(crate) fn decode_persistent(
    image: &[u8],
    mode: Mode,
) -> Result<Option<PersistentLighting>, String> {
    let Some((_, block_addr)) = detect_block_addr(image)? else {
        return Ok(None);
    };
    if !matches!(mode, Mode::Target(_)) {
        return Err("permanent internal lighting requires prepared v0034 firmware".into());
    }
    if word(image, block_addr) != LIGHTING_MAGIC {
        return Err("corrupt internal lighting block magic".into());
    }
    let breathing = Breathing::from_speed(image[block_addr + 2])?;
    if image[block_addr + 3] != 0 {
        return Err("unsupported internal lighting block flags".into());
    }
    let stream = block_addr + BLOCK_HEADER_BYTES;
    if word(image, stream) != 1
        || word(image, stream + 2) != u16::from(breathing as u8)
        || word(image, stream + 4) != 3
        || word(image, stream + 6) != FRAME_TICKS
        || word(image, stream + 62) != 4
        || word(image, stream + 64) != 0
        || word(image, stream + 66) != 0xa4a4
    {
        return Err("corrupt internal lighting animation stream".into());
    }
    // 54-byte RGB payload: 15*3 = 45 active bytes + 9 trailing zero bytes.
    if image[stream + 8 + LED_COUNT * 3..stream + 8 + 54]
        .iter()
        .any(|&b| b != 0)
    {
        return Err("nonzero trailing bytes in internal lighting RGB frame".into());
    }
    if image[stream + STREAM_BYTES..block_addr + BLOCK_BYTES]
        .iter()
        .any(|&b| b != 0)
    {
        return Err("nonzero page padding after internal lighting stream".into());
    }
    let leds = std::array::from_fn(|i| {
        let base = stream + 8 + i * 3;
        Rgb::new(image[base], image[base + 1], image[base + 2])
    });
    Ok(Some(PersistentLighting { leds, breathing }))
}

pub(crate) fn strip_persistent(
    image: &mut [u8],
    mode: Mode,
) -> Result<Option<PersistentLighting>, String> {
    let Some(decoded) = decode_persistent(image, mode)? else {
        return Ok(None);
    };
    let (table_addr, block_addr) = detect_block_addr(image)?.expect("already verified");
    let mut saved_table = [0u8; MODE_SLOTS * 4];
    saved_table.copy_from_slice(&image[block_addr + 4..block_addr + 4 + MODE_SLOTS * 4]);
    for i in 0..(MODE_SLOTS * 2) {
        let w = u16::from_le_bytes(saved_table[2 * i..2 * i + 2].try_into().unwrap());
        put_word_delta(image, table_addr + 2 * i, w);
    }
    for off in (0..BLOCK_BYTES).step_by(2) {
        put_word_delta(image, block_addr + off, 0);
    }
    Ok(Some(decoded))
}

pub(crate) fn install_persistent(
    image: &mut [u8],
    canonical: &[u8],
    mode: Mode,
    cfg: &PersistentLighting,
    preceding_ext_pages: usize,
) -> Result<(), String> {
    if !matches!(mode, Mode::Target(_)) {
        return Err("permanent internal lighting requires prepared v0034 firmware".into());
    }
    let table_addr = lighting_table_addr(image)?;
    if lighting_table_addr(canonical)? != table_addr {
        return Err("canonical profile lighting table offset differs".into());
    }
    let block_addr = EXT_BASE + 64 * preceding_ext_pages;
    if block_addr + BLOCK_BYTES > EXT_END {
        return Err("not enough internal flash space for permanent lighting alongside macros".into());
    }
    if image[block_addr..block_addr + BLOCK_BYTES]
        .iter()
        .any(|&b| b != 0)
    {
        return Err("internal lighting destination pages are not empty".into());
    }
    let mut block = [0u8; BLOCK_BYTES];
    block[0..2].copy_from_slice(&LIGHTING_MAGIC.to_le_bytes());
    block[2] = cfg.breathing as u8;
    block[3] = 0;
    block[4..4 + MODE_SLOTS * 4]
        .copy_from_slice(&image[table_addr..table_addr + MODE_SLOTS * 4]);
    let s = BLOCK_HEADER_BYTES;
    block[s..s + 2].copy_from_slice(&1u16.to_le_bytes());
    block[s + 2..s + 4].copy_from_slice(&u16::from(cfg.breathing as u8).to_le_bytes());
    block[s + 4..s + 6].copy_from_slice(&3u16.to_le_bytes());
    block[s + 6..s + 8].copy_from_slice(&FRAME_TICKS.to_le_bytes());
    for (i, rgb) in cfg.leds.iter().enumerate() {
        let off = s + 8 + i * 3;
        block[off] = rgb.r;
        block[off + 1] = rgb.g;
        block[off + 2] = rgb.b;
    }
    block[s + 62..s + 64].copy_from_slice(&4u16.to_le_bytes());
    block[s + 64..s + 66].copy_from_slice(&0u16.to_le_bytes());
    block[s + 66..s + 68].copy_from_slice(&0xa4a4u16.to_le_bytes());

    for off in (0..BLOCK_BYTES).step_by(2) {
        let w = u16::from_le_bytes(block[off..off + 2].try_into().unwrap());
        put_word_delta(image, block_addr + off, w);
    }
    let stream_word = ((block_addr + BLOCK_HEADER_BYTES - PROFILE_BASE) / 2) as u16;
    for m in 0..MODE_SLOTS {
        put_word_delta(image, table_addr + 4 * m, stream_word);
        put_word_delta(image, table_addr + 4 * m + 2, 0);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    pub const PRESETS: [(&'static str, Self); 10] = [
        ("White", Self::new(0xff, 0xff, 0xff)),
        ("Red", Self::new(0xff, 0x00, 0x00)),
        ("Orange", Self::new(0xff, 0x55, 0x00)),
        ("Yellow", Self::new(0xff, 0xd0, 0x00)),
        ("Green", Self::new(0x00, 0xff, 0x00)),
        ("Cyan", Self::new(0x00, 0xff, 0xff)),
        ("Blue", Self::new(0x00, 0x44, 0xff)),
        ("Purple", Self::new(0x88, 0x00, 0xff)),
        ("Magenta", Self::new(0xff, 0x00, 0xaa)),
        ("Off", Self::new(0x00, 0x00, 0x00)),
    ];

    pub fn parse_hex(text: &str) -> Result<Self, String> {
        let clean = text.trim().strip_prefix('#').unwrap_or(text.trim());
        if clean.len() != 6 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("color must be 6 hex digits (e.g. ff3300 or #00ffcc)".into());
        }
        let r = u8::from_str_radix(&clean[0..2], 16).map_err(|e| e.to_string())?;
        let g = u8::from_str_radix(&clean[2..4], 16).map_err(|e| e.to_string())?;
        let b = u8::from_str_radix(&clean[4..6], 16).map_err(|e| e.to_string())?;
        Ok(Self { r, g, b })
    }

    pub fn hex(self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }

    pub fn preset_name(self) -> Option<&'static str> {
        Self::PRESETS
            .iter()
            .find(|(_, c)| *c == self)
            .map(|(name, _)| *name)
    }

    fn lerp(a: Self, b: Self, num: usize, den: usize) -> Self {
        let mix = |u: u8, v: u8| -> u8 {
            let f = f64::from(u) + (f64::from(v) - f64::from(u)) * (num as f64 / den as f64);
            f.round().clamp(0.0, 255.0) as u8
        };
        Self {
            r: mix(a.r, b.r),
            g: mix(a.g, b.g),
            b: mix(a.b, b.b),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Brightness {
    Off = 0,
    Low25 = 1,
    Medium50 = 2,
    High100 = 3,
}

impl Brightness {
    pub const ALL: [Self; 4] = [Self::Off, Self::Low25, Self::Medium50, Self::High100];

    pub fn from_level(level: u8) -> Result<Self, String> {
        match level {
            0 => Ok(Self::Off),
            1 => Ok(Self::Low25),
            2 => Ok(Self::Medium50),
            3 => Ok(Self::High100),
            _ => Err("brightness must be 0 (off), 1 (25%), 2 (50%), or 3 (100%)".into()),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off (0%)",
            Self::Low25 => "Low (25%)",
            Self::Medium50 => "Medium (50%)",
            Self::High100 => "High (100%)",
        }
    }

    pub fn pwm(self) -> u8 {
        match self {
            Self::Off => 0x00,
            Self::Low25 => 0x3f,
            Self::Medium50 => 0x7f,
            Self::High100 => 0xff,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Breathing {
    Off = 0,
    Slow = 1,
    Medium = 2,
    Fast = 3,
    Fastest = 4,
}

impl Breathing {
    pub const ALL: [Self; 5] = [
        Self::Off,
        Self::Slow,
        Self::Medium,
        Self::Fast,
        Self::Fastest,
    ];

    pub fn from_speed(speed: u8) -> Result<Self, String> {
        match speed {
            0 => Ok(Self::Off),
            1 => Ok(Self::Slow),
            2 => Ok(Self::Medium),
            3 => Ok(Self::Fast),
            4 => Ok(Self::Fastest),
            _ => Err("breathing speed must be 0 (off) through 4 (fastest)".into()),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Steady (off)",
            Self::Slow => "Slow",
            Self::Medium => "Medium",
            Self::Fast => "Fast",
            Self::Fastest => "Fastest",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum Effect {
    Normal,
    Solid { color: Rgb },
    Gradient { start: Rgb, end: Rgb },
    Rainbow,
    PerLed { leds: [Rgb; LED_COUNT] },
}

impl Effect {
    pub fn render_leds(&self) -> Option<[Rgb; LED_COUNT]> {
        match self {
            Self::Normal => None,
            Self::Solid { color } => Some([*color; LED_COUNT]),
            Self::Gradient { start, end } => Some(std::array::from_fn(|i| {
                Rgb::lerp(*start, *end, i, LED_COUNT - 1)
            })),
            Self::Rainbow => Some(std::array::from_fn(|i| {
                hsv_to_rgb((i as f64) * 360.0 / (LED_COUNT as f64))
            })),
            Self::PerLed { leds } => Some(*leds),
        }
    }
}

fn hsv_to_rgb(hue_deg: f64) -> Rgb {
    let h = (hue_deg.rem_euclid(360.0)) / 60.0;
    let x = (1.0 - (h % 2.0 - 1.0).abs()) * 255.0;
    let x = x.round().clamp(0.0, 255.0) as u8;
    match h as u8 {
        0 => Rgb::new(255, x, 0),
        1 => Rgb::new(x, 255, 0),
        2 => Rgb::new(0, 255, x),
        3 => Rgb::new(0, x, 255),
        4 => Rgb::new(x, 0, 255),
        _ => Rgb::new(255, 0, x),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightingStatus {
    pub brightness_level: u8,
    pub brightness_pwm: u8,
    pub mode_flags: u8,
    pub active_mode: u8,
    pub device_operations: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyReport {
    pub complete: bool,
    pub model: bool,
    pub device_operations: usize,
    pub feature_calls: usize,
    pub brightness: Option<u8>,
    pub live_preview: bool,
    pub breathing_speed: u8,
    pub status: Option<LightingStatus>,
}

pub fn brightness_get_frame() -> [u8; 64] {
    let mut frame = [0u8; 64];
    frame[0] = 0x07;
    frame[1] = 0x11;
    frame
}

pub fn brightness_set_frame(level: Brightness) -> [u8; 64] {
    let mut frame = [0u8; 64];
    frame[0] = 0x07;
    frame[1] = 0x11;
    frame[4] = 0x80;
    frame[8] = level as u8;
    frame
}

pub fn status_get_frame() -> [u8; 64] {
    let mut frame = [0u8; 64];
    frame[0] = 0x07;
    frame[1] = 0x03;
    frame[2] = 0x06;
    frame[3] = 0x05;
    frame
}

pub fn preview_enable_frame(enable: bool) -> [u8; 64] {
    let mut frame = [0u8; 64];
    frame[0] = 0x07;
    frame[1] = 0x03;
    frame[2] = 0x06;
    frame[3] = 0x00;
    frame[8] = u8::from(enable);
    frame
}

pub fn breathing_frame(speed: Breathing) -> [u8; 64] {
    let mut frame = [0u8; 64];
    frame[0] = 0x07;
    frame[1] = 0x03;
    frame[2] = 0x06;
    frame[3] = 0x01;
    frame[6] = u8::from(speed != Breathing::Off);
    frame[7] = speed as u8;
    frame
}

pub fn live_rgb_frame(leds: &[Rgb; LED_COUNT]) -> [u8; 64] {
    let mut frame = [0u8; 64];
    frame[0] = 0x07;
    frame[1] = 0x03;
    frame[2] = 0x06;
    frame[3] = 0x02;
    for (i, rgb) in leds.iter().enumerate() {
        let at = 8 + 3 * i;
        frame[at] = rgb.r;
        frame[at + 1] = rgb.g;
        frame[at + 2] = rgb.b;
    }
    frame
}

/// Strictly validates that a 64-byte frame belongs to the audited zero-NOR
/// lighting allowlist (`07 11` or `07 03 06 00/01/02/05`).
pub(crate) fn is_allowed_lighting_frame(frame: &[u8; 64]) -> bool {
    if frame[0] != 0x07 {
        return false;
    }
    match frame[1] {
        0x11 => (frame[4] == 0x00 || (frame[4] == 0x80 && frame[8] <= 3))
            && frame[2] == 0
            && frame[3] == 0
            && frame[5..8].iter().all(|&b| b == 0)
            && frame[9..].iter().all(|&b| b == 0),
        0x03 if frame[2] == 0x06 => match frame[3] {
            0x00 => frame[4..8].iter().all(|&b| b == 0) && frame[8] <= 1 && frame[9..].iter().all(|&b| b == 0),
            0x01 => frame[4..6].iter().all(|&b| b == 0) && frame[6] <= 1 && frame[7] <= 4 && frame[8..].iter().all(|&b| b == 0),
            0x02 => frame[4..8].iter().all(|&b| b == 0) && frame[8 + 3 * LED_COUNT..].iter().all(|&b| b == 0),
            0x05 => frame[4..].iter().all(|&b| b == 0),
            _ => false,
        },
        _ => false,
    }
}

pub fn build_apply_plan(
    brightness: Option<Brightness>,
    effect: Option<&Effect>,
    breathing: Breathing,
) -> Vec<([u8; 64], bool)> {
    let mut ops = Vec::new();
    if let Some(level) = brightness {
        ops.push((brightness_set_frame(level), true));
    }
    if let Some(effect) = effect {
        if let Some(leds) = effect.render_leds() {
            ops.push((preview_enable_frame(true), false));
            ops.push((breathing_frame(breathing), false));
            ops.push((live_rgb_frame(&leds), false));
        } else {
            ops.push((breathing_frame(Breathing::Off), false));
            ops.push((preview_enable_frame(false), false));
        }
    }
    ops
}

fn resolve_binding(workspace: &Workspace) -> Result<query_session::Binding, String> {
    let reference = boot_roundtrip::load(&workspace.baseline)?;
    let report = discovery::collect(Path::new("/sys"))?;
    let (_, binding) = boot_roundtrip::select_normal_mode(&report, reference.baseline.binding())?
        .ok_or_else(|| "supported W95 Max normal interface not found".to_string())?;
    Ok(binding)
}

pub fn read_status(workspace: &Workspace, model: bool) -> Result<LightingStatus, String> {
    if model {
        return Ok(LightingStatus {
            brightness_level: 3,
            brightness_pwm: 0xff,
            mode_flags: 0,
            active_mode: 0,
            device_operations: 0,
        });
    }
    if !crate::workflow::available() {
        return Err("physical lighting control is disabled in this build".into());
    }
    let binding = resolve_binding(workspace)?;
    let frames = [(brightness_get_frame(), true), (status_get_frame(), true)];
    let replies = query_session::lighting_exchange(&binding, &frames)?;
    let b_reply = replies[0].ok_or("missing 07 11 brightness reply")?;
    let s_reply = replies[1].ok_or("missing 07 03 06 05 status reply")?;
    Ok(LightingStatus {
        brightness_level: b_reply[8],
        brightness_pwm: s_reply[8],
        mode_flags: s_reply[9],
        active_mode: s_reply[10],
        device_operations: 4,
    })
}

pub fn apply(
    workspace: &Workspace,
    brightness: Option<Brightness>,
    effect: Option<&Effect>,
    breathing: Breathing,
    model: bool,
) -> Result<ApplyReport, String> {
    let ops = build_apply_plan(brightness, effect, breathing);
    if ops.is_empty() {
        return Err("nothing to apply; choose a brightness or lighting effect".into());
    }
    for (frame, _) in &ops {
        if !is_allowed_lighting_frame(frame) {
            return Err("internal lighting frame rejected by allowlist".into());
        }
    }
    let live_preview = effect.is_some_and(|e| !matches!(e, Effect::Normal));
    let feature_calls: usize = ops.iter().map(|(_, get)| if *get { 2 } else { 1 }).sum();
    if model {
        let level = brightness.map_or(3, |b| b as u8);
        return Ok(ApplyReport {
            complete: true,
            model: true,
            device_operations: 0,
            feature_calls,
            brightness: brightness.map(|b| b as u8),
            live_preview,
            breathing_speed: if live_preview { breathing as u8 } else { 0 },
            status: Some(LightingStatus {
                brightness_level: level,
                brightness_pwm: Brightness::from_level(level).map_or(0xff, Brightness::pwm),
                mode_flags: u8::from(live_preview),
                active_mode: 0,
                device_operations: 0,
            }),
        });
    }
    if !crate::workflow::available() {
        return Err("physical lighting control is disabled in this build".into());
    }
    let binding = resolve_binding(workspace)?;
    let mut full_ops = ops;
    full_ops.push((brightness_get_frame(), true));
    full_ops.push((status_get_frame(), true));
    let replies = query_session::lighting_exchange(&binding, &full_ops)?;
    let n = replies.len();
    let b_reply = replies[n - 2].ok_or("missing post-apply brightness reply")?;
    let s_reply = replies[n - 1].ok_or("missing post-apply status reply")?;
    if let Some(level) = brightness
        && b_reply[8] != level as u8
    {
        return Err(format!(
            "brightness verification mismatch: expected {}, got {}",
            level as u8, b_reply[8]
        ));
    }
    let total_calls: usize = full_ops.iter().map(|(_, g)| if *g { 2 } else { 1 }).sum();
    Ok(ApplyReport {
        complete: true,
        model: false,
        device_operations: total_calls,
        feature_calls: total_calls,
        brightness: Some(b_reply[8]),
        live_preview,
        breathing_speed: if live_preview { breathing as u8 } else { 0 },
        status: Some(LightingStatus {
            brightness_level: b_reply[8],
            brightness_pwm: s_reply[8],
            mode_flags: s_reply[9],
            active_mode: s_reply[10],
            device_operations: total_calls,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lighting_frames_match_audited_core3_and_core4_firmware_layouts() {
        let bg = brightness_get_frame();
        assert_eq!(&bg[..8], &[0x07, 0x11, 0, 0, 0, 0, 0, 0]);
        assert!(is_allowed_lighting_frame(&bg));

        let bs = brightness_set_frame(Brightness::Medium50);
        assert_eq!(&bs[..9], &[0x07, 0x11, 0, 0, 0x80, 0, 0, 0, 2]);
        assert!(is_allowed_lighting_frame(&bs));

        let st = status_get_frame();
        assert_eq!(&st[..8], &[0x07, 0x03, 0x06, 0x05, 0, 0, 0, 0]);
        assert!(is_allowed_lighting_frame(&st));

        let on = preview_enable_frame(true);
        assert_eq!(&on[..9], &[0x07, 0x03, 0x06, 0x00, 0, 0, 0, 0, 1]);
        assert!(is_allowed_lighting_frame(&on));

        let br = breathing_frame(Breathing::Fast);
        assert_eq!(&br[..8], &[0x07, 0x03, 0x06, 0x01, 0, 0, 1, 3]);
        assert!(is_allowed_lighting_frame(&br));

        let leds = Effect::Solid {
            color: Rgb::new(0x12, 0x34, 0x56),
        }
        .render_leds()
        .unwrap();
        let frame = live_rgb_frame(&leds);
        assert_eq!(&frame[..8], &[0x07, 0x03, 0x06, 0x02, 0, 0, 0, 0]);
        assert_eq!(&frame[8..11], &[0x12, 0x34, 0x56]);
        assert_eq!(&frame[8 + 3 * 14..8 + 3 * 15], &[0x12, 0x34, 0x56]);
        assert!(frame[8 + 3 * 15..].iter().all(|&b| b == 0));
        assert!(is_allowed_lighting_frame(&frame));

        // Reject non-lighting or out-of-range opcodes (including NOR 0x21 and flash 0x2F).
        let mut bad = [0u8; 64];
        bad[0] = 0x07;
        bad[1] = 0x21;
        assert!(!is_allowed_lighting_frame(&bad));
        bad[1] = 0x2f;
        assert!(!is_allowed_lighting_frame(&bad));
        let mut bad_bright = brightness_set_frame(Brightness::High100);
        bad_bright[8] = 4;
        assert!(!is_allowed_lighting_frame(&bad_bright));
    }

    #[test]
    fn hex_parsing_gradients_rainbow_and_model_apply_work_without_device_io() {
        assert_eq!(Rgb::parse_hex("#00ffcc").unwrap(), Rgb::new(0x00, 0xff, 0xcc));
        assert_eq!(Rgb::parse_hex("ff3300").unwrap().hex(), "#FF3300");
        assert!(Rgb::parse_hex("xyz").is_err());

        let grad = Effect::Gradient {
            start: Rgb::new(255, 0, 0),
            end: Rgb::new(0, 0, 255),
        }
        .render_leds()
        .unwrap();
        assert_eq!(grad[0], Rgb::new(255, 0, 0));
        assert_eq!(grad[LED_COUNT - 1], Rgb::new(0, 0, 255));
        assert_eq!(grad[7].r, 128);
        assert_eq!(grad[7].b, 128);

        let rainbow = Effect::Rainbow.render_leds().unwrap();
        assert_eq!(rainbow[0], Rgb::new(255, 0, 0));

        let ws = Workspace {
            schema: 1,
            baseline: std::path::PathBuf::from("unused-baseline"),
            backup: std::path::PathBuf::from("unused-backup"),
            assets: std::path::PathBuf::from("unused-assets"),
            sessions: std::path::PathBuf::from("unused-sessions"),
        };
        let st = read_status(&ws, true).unwrap();
        assert_eq!(st.device_operations, 0);
        let rep = apply(
            &ws,
            Some(Brightness::Medium50),
            Some(&Effect::Rainbow),
            Breathing::Slow,
            true,
        )
        .unwrap();
        assert!(rep.complete && rep.model && rep.device_operations == 0);
        assert_eq!(rep.brightness, Some(2));
        assert!(rep.live_preview);
    }

    #[test]
    fn persistent_internal_lighting_roundtrips_and_rejects_corruption() {
        let mut img = vec![0u8; 65536];
        img[PROFILE_BASE..PROFILE_BASE + 4].copy_from_slice(&[0xa4; 4]);
        // Stock Core 3/4 word 13 = 0x01D8 -> table at 0xE5B0
        img[PROFILE_BASE + 0x1a..PROFILE_BASE + 0x1c].copy_from_slice(&0x01d8u16.to_le_bytes());
        let canonical = img.clone();

        assert_eq!(extended_pages(&img).unwrap(), 0);
        assert_eq!(decode_persistent(&img, Mode::Target(crate::model::Core::Three)).unwrap(), None);

        let cfg = PersistentLighting {
            leds: Effect::Rainbow.render_leds().unwrap(),
            breathing: Breathing::Medium,
        };
        install_persistent(&mut img, &canonical, Mode::Target(crate::model::Core::Three), &cfg, 0)
            .unwrap();
        assert_eq!(extended_pages(&img).unwrap(), 2);
        // All 5 mode slots point to stream at 0xE718 -> word offset 0x028C, hi = 0x0000 (internal flash!)
        for m in 0..5 {
            assert_eq!(word(&img, 0xe5b0 + 4 * m), 0x028c);
            assert_eq!(word(&img, 0xe5b0 + 4 * m + 2), 0x0000);
        }
        assert_eq!(
            decode_persistent(&img, Mode::Target(crate::model::Core::Three)).unwrap(),
            Some(cfg.clone())
        );

        // Corrupting a structural byte must fail closed.
        let mut corrupt = img.clone();
        corrupt[0xe718] ^= 1;
        assert!(decode_persistent(&corrupt, Mode::Target(crate::model::Core::Three)).is_err());

        // Stripping must restore every single byte (including checksums) identically.
        let stripped = strip_persistent(&mut img, Mode::Target(crate::model::Core::Three)).unwrap();
        assert_eq!(stripped, Some(cfg));
        assert_eq!(img, canonical);
    }
}
