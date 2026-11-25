//! Word lowering for the built-in click lists and the traced packaged presets.
use crate::model::Core;
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod gun_a;
pub mod internal;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Program {
    DoubleClick,
    TripleClick,
    TripleFire,
    GunaDoubleHit,
    GunaTripleHit,
    GunaFourHit,
    PrecisionHold,
    ShootSelect(u8),
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DoubleClick => "Double Click",
            Self::TripleClick => "Triple Click",
            Self::TripleFire => "Triple Fire",
            Self::GunaDoubleHit => "GunA Double Hit",
            Self::GunaTripleHit => "GunA Triple Hit",
            Self::GunaFourHit => "GunA Four Hit",
            Self::PrecisionHold => "Precision Hold",
            Self::ShootSelect(slot) => return write!(f, "Select Shooting Slot {slot}"),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ProgramWords {
    pub press: Vec<u16>,
    /// None means the source evidence covers only the press list.
    pub release: Option<Vec<u16>>,
}

const LEFT_DOWN: u16 = 0x2501;
const LEFT_UP: u16 = 0x2401;
const END: u16 = 0x262F;

const fn delay(ms: u8) -> u16 {
    0x2800 + ms as u16
}

const fn movement(x: i8, y: i8) -> u16 {
    0x4000 + (((x as u16) & 0x7F) << 7) + ((y as u16) & 0x7F)
}

fn click_list(count: u8) -> Vec<u16> {
    let mut words = Vec::new();
    for index in 0..count {
        if index > 0 {
            words.push(delay(64));
        }
        words.extend([LEFT_DOWN, delay(64), LEFT_UP]);
    }
    words.push(END);
    words
}

fn triple_fire() -> Vec<u16> {
    let mut words = Vec::new();
    for x in [Some(1), Some(-1), None] {
        words.extend([LEFT_DOWN, delay(20), LEFT_UP, delay(80)]);
        if let Some(x) = x {
            words.extend([movement(x, 15), delay(2)]);
        }
    }
    words.push(END);
    words
}

fn gun_a(count: u8) -> Vec<u16> {
    let mut words = Vec::new();
    for index in 0..count {
        words.extend([LEFT_DOWN, 0x2608, delay(20), LEFT_UP]);
        if index + 1 < count {
            words.extend([0x2608, delay(80), 0x2609, movement(0, 0)]);
        }
    }
    words.push(END);
    words
}

pub fn compile(program: Program, core: Core) -> Result<ProgramWords, String> {
    use Program::*;
    let press = match (program, core) {
        (DoubleClick, Core::Three | Core::Four) => click_list(2),
        (TripleClick, Core::Three | Core::Four) => click_list(3),
        (TripleFire, Core::Three | Core::Four) => triple_fire(),
        (GunaDoubleHit, Core::Three) => gun_a(2),
        (GunaTripleHit, Core::Three) => gun_a(3),
        (GunaFourHit, Core::Three) => gun_a(4),
        (PrecisionHold, Core::Three) => {
            return Ok(ProgramWords {
                press: vec![0x2628],
                release: Some(vec![0x2629]),
            });
        }
        (ShootSelect(slot @ 1..=7), Core::Two | Core::Three) => vec![0x260F + u16::from(slot)],
        _ => {
            return Err(format!(
                "{program} preview is unsupported for Core {}",
                core.number()
            ));
        }
    };
    let release = match program {
        GunaDoubleHit | GunaTripleHit | GunaFourHit | ShootSelect(_) => None,
        _ => Some(Vec::new()),
    };
    Ok(ProgramWords { press, release })
}
