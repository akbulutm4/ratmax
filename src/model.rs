use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Internal model ID, not a USB product ID. Other models require separate evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub enum Model {
    W95Max,
}

impl TryFrom<u16> for Model {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x578 => Ok(Self::W95Max),
            _ => Err(Error::UnsupportedModel(value)),
        }
    }
}

impl From<Model> for u16 {
    fn from(_: Model) -> Self {
        0x578
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("W95 Max (0x578)")
    }
}

/// User-visible Core number. Core 4's encoded index is zero, not four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum Core {
    One,
    Two,
    Three,
    Four,
}

impl Core {
    pub const ALL: [Self; 4] = [Self::One, Self::Two, Self::Three, Self::Four];

    pub const fn number(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    pub const fn firmware_index(self) -> FirmwareIndex {
        FirmwareIndex(match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 0,
        })
    }
}

impl TryFrom<u8> for Core {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            _ => Err(Error::InvalidCore(value.to_string())),
        }
    }
}

impl From<Core> for u8 {
    fn from(value: Core) -> Self {
        value.number()
    }
}

impl FromStr for Core {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1" => Ok(Self::One),
            "2" => Ok(Self::Two),
            "3" => Ok(Self::Three),
            "4" => Ok(Self::Four),
            _ => Err(Error::InvalidCore(value.to_owned())),
        }
    }
}

impl fmt::Display for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Core {}", self.number())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct FirmwareIndex(u8);

impl FirmwareIndex {
    pub const fn get(self) -> u8 {
        self.0
    }
}
