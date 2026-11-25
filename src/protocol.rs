//! Pure local-buffer codecs from analysis checkpoint 15. These are not measured
//! HID report sizes, a read-only hardware API, or permission to issue commands.

use std::fmt;

use serde::Serialize;

use crate::firmware::LOCAL_BUFFER_LEN;

pub const GENERIC_LOCAL_LEN: usize = 72;
pub const GENERIC_HEADER_LEN: usize = 8;
pub const FINAL_BLOCK_LEN: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtocolError {
    Length {
        expected: usize,
        actual: usize,
    },
    Header {
        offset: usize,
        expected: u8,
        actual: u8,
    },
    RecordRejected {
        ack: u8,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "local reply: expected {expected} bytes, found {actual}")
            }
            Self::Header {
                offset,
                expected,
                actual,
            } => write!(
                f,
                "reply byte {offset}: expected {expected:02X}, found {actual:02X}"
            ),
            Self::RecordRejected { ack } => {
                write!(f, "record acknowledgment {ack:02X}; expected 01")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    DeviceValue,
    FinalBlock,
}

impl Query {
    pub const fn opcode(self) -> u8 {
        match self {
            Self::DeviceValue => 0x29,
            Self::FinalBlock => 0x2B,
        }
    }

    pub const fn payload_len(self) -> usize {
        match self {
            Self::DeviceValue => 8,
            Self::FinalBlock => FINAL_BLOCK_LEN,
        }
    }

    /// 0x5A2D24 / 0x5A2A9C pass six zero header arguments to 0x5A0AE4.
    pub fn local_request(self) -> [u8; GENERIC_LOCAL_LEN] {
        let mut bytes = [0; GENERIC_LOCAL_LEN];
        bytes[0] = 7;
        bytes[1] = self.opcode();
        bytes
    }

    /// Check the mock's explicit scratch-buffer size, then all eight echoed
    /// header bytes as 0x5A0AE4 does. Live framing needs separate validation.
    pub fn decode_local_reply(self, reply: &[u8]) -> Result<&[u8], ProtocolError> {
        require_length(reply, GENERIC_LOCAL_LEN)?;
        let request = self.local_request();
        for offset in 0..GENERIC_HEADER_LEN {
            if reply[offset] != request[offset] {
                return Err(ProtocolError::Header {
                    offset,
                    expected: request[offset],
                    actual: reply[offset],
                });
            }
        }
        Ok(&reply[GENERIC_HEADER_LEN..GENERIC_HEADER_LEN + self.payload_len()])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DeviceValue {
    pub u: u32,
    pub v: u32,
}

impl DeviceValue {
    pub fn decode_local_reply(reply: &[u8]) -> Result<Self, ProtocolError> {
        let data = Query::DeviceValue.decode_local_reply(reply)?;
        Ok(Self {
            u: u32::from_le_bytes(data[..4].try_into().expect("eight-byte payload")),
            v: u32::from_le_bytes(data[4..8].try_into().expect("eight-byte payload")),
        })
    }

    pub const fn needs_initialization(self) -> bool {
        self.u == u32::MAX
    }
}

/// The other six DWORDs are opaque and preserved. This type deliberately does
/// not choose/derive the replacement DWORD; that policy remains analysis G4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalBlock([u8; FINAL_BLOCK_LEN]);

impl FinalBlock {
    pub fn decode_local_reply(reply: &[u8]) -> Result<Self, ProtocolError> {
        let data = Query::FinalBlock.decode_local_reply(reply)?;
        Ok(Self(data.try_into().expect("28-byte payload")))
    }

    pub fn as_bytes(&self) -> &[u8; FINAL_BLOCK_LEN] {
        &self.0
    }

    /// Pure reconstruction of 0x5A2B84 -> 0x5A2B10 -> 0x5A0A28. There is no
    /// live executor for this buffer. The replacement is supplied explicitly.
    pub fn local_write_with_first_dword(&self, replacement: u32) -> [u8; GENERIC_LOCAL_LEN] {
        let mut bytes = [0; GENERIC_LOCAL_LEN];
        bytes[0..3].copy_from_slice(&[7, 0x2B, 1]);
        bytes[8..8 + FINAL_BLOCK_LEN].copy_from_slice(&self.0);
        bytes[8..12].copy_from_slice(&replacement.to_le_bytes());
        bytes
    }
}

/// 0x5A373C calls 0x5A0950 with report ID 07 and zero command/arguments.
pub fn reset_local_request() -> [u8; GENERIC_LOCAL_LEN] {
    let mut bytes = [0; GENERIC_LOCAL_LEN];
    bytes[0] = 7;
    bytes
}

pub fn check_local_record_ack(reply: &[u8]) -> Result<(), ProtocolError> {
    require_length(reply, LOCAL_BUFFER_LEN)?;
    // Report ID validation is an explicit Ratmax check; the vendor record
    // helper itself only tests transport results and response byte 1 == 1.
    if reply[0] != 7 {
        return Err(ProtocolError::Header {
            offset: 0,
            expected: 7,
            actual: reply[0],
        });
    }
    if reply[1] != 1 {
        return Err(ProtocolError::RecordRejected { ack: reply[1] });
    }
    Ok(())
}

fn require_length(bytes: &[u8], expected: usize) -> Result<(), ProtocolError> {
    if bytes.len() != expected {
        return Err(ProtocolError::Length {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}
