//! R3i-derived first-body-window codec. No transport, writer or full dump API.
use crate::{
    protocol::ProtocolError,
    readback::{ByteSpan, ReadbackError, RuntimeDescriptorReply},
};
use serde::Serialize;

/// Fixed eight bytes at sensitivity +8. Constructed only from a framed layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstBodyRead {
    sensitivity_base: u32,
    layout_reply_sha256: String,
}
impl FirstBodyRead {
    pub fn from_layout(layout: &RuntimeDescriptorReply) -> Result<Self, ReadbackError> {
        let base = layout.descriptor().bases().sensitivity;
        ByteSpan::new(base, 256)?;
        Ok(Self {
            sensitivity_base: base,
            layout_reply_sha256: layout.reply_sha256().into(),
        })
    }
    pub fn address(&self) -> u32 {
        self.sensitivity_base + 8
    }
    pub fn request(&self) -> [u8; 64] {
        let mut request = [0; 64];
        request[..3].copy_from_slice(&[7, 0x2f, 0]);
        request[24..28].copy_from_slice(&2u32.to_le_bytes());
        request[28..32].copy_from_slice(&self.address().to_le_bytes());
        request
    }
    pub fn observe_reply(&self, raw: &[u8]) -> Result<BodyObservation, ReadbackError> {
        conservative_echo(&self.request(), raw)?;
        let data = raw[32..40].to_vec();
        let word = |i| u16::from_le_bytes([data[i], data[i + 1]]);
        let words = FirstBodyWords {
            enabled_slots_minus_one: word(0),
            selected_slot_index: word(2),
            first_sensor_words: [word(4), word(6)],
        };
        Ok(BodyObservation {
            request: self.clone(),
            raw_reply: raw.to_vec(),
            candidate: data,
            words,
            conservative_echo_checks_passed: true,
            protocol_correlation_established: false,
        })
    }
}

/// Extra fail-closed policy based on observed R3h frames, not a proven receiver
/// contract or protection against a stale reply repeating the same fields.
pub fn conservative_echo(request: &[u8; 64], raw: &[u8]) -> Result<(), ReadbackError> {
    if raw.len() != 64 {
        return Err(ReadbackError::Protocol {
            error: ProtocolError::Length {
                expected: 64,
                actual: raw.len(),
            },
        });
    }
    for offset in (0..8).chain(24..32) {
        if raw[offset] != request[offset] {
            return Err(ReadbackError::Protocol {
                error: ProtocolError::Header {
                    offset,
                    expected: request[offset],
                    actual: raw[offset],
                },
            });
        }
    }
    Ok(())
}

/// Raw serialized words only. Third sensor word/CPI and full settings absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstBodyWords {
    pub enabled_slots_minus_one: u16,
    pub selected_slot_index: u16,
    pub first_sensor_words: [u16; 2],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BodyObservation {
    pub request: FirstBodyRead,
    pub raw_reply: Vec<u8>,
    pub candidate: Vec<u8>,
    pub words: FirstBodyWords,
    pub conservative_echo_checks_passed: bool,
    pub protocol_correlation_established: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BodyCoverage {
    pub sensitivity_header_candidate_bytes: usize,
    pub sensitivity_body_candidate_bytes: usize,
    pub sensitivity_bytes_missing: usize,
    pub full_sensitivity_checksum_verified: bool,
    pub protocol_correlation_established: bool,
    pub complete_backup: bool,
    pub restoration_supported: bool,
}
impl BodyCoverage {
    pub fn new(header: bool, body: bool) -> Self {
        let header = if header { 8 } else { 0 };
        let body = if body { 8 } else { 0 };
        Self {
            sensitivity_header_candidate_bytes: header,
            sensitivity_body_candidate_bytes: body,
            sensitivity_bytes_missing: 256 - header - body,
            full_sensitivity_checksum_verified: false,
            protocol_correlation_established: false,
            complete_backup: false,
            restoration_supported: false,
        }
    }
}
