//! Normal-mode identity (`0x1F`) and status (`0x2D`) Feature Report codecs.
//! These functions perform no I/O. The policy does not prove device-side
//! non-mutation. The separately gated query worker lives in query_session.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    model::{Core, Model},
    protocol::{GENERIC_LOCAL_LEN, ProtocolError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalQuery {
    Identity,
    Status,
}

impl NormalQuery {
    pub const ALL: [Self; 2] = [Self::Identity, Self::Status];
    pub const fn opcode(self) -> u8 {
        match self {
            Self::Identity => 0x1F,
            Self::Status => 0x2D,
        }
    }
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Identity => 10,
            Self::Status => 24,
        }
    }
    pub const fn header(self) -> [u8; 8] {
        [7, self.opcode(), 0, 0, 0, 0, 0, 0]
    }

    /// Reject any opcode or control-byte variation outside the audited policy.
    pub fn from_header(header: &[u8; 8]) -> Result<Self, QueryError> {
        let query = match header[1] {
            0x1F => Self::Identity,
            0x2D => Self::Status,
            opcode => return Err(QueryError::ForbiddenOpcode { opcode }),
        };
        check_header(query, header)?;
        Ok(query)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QueryError {
    ForbiddenOpcode {
        opcode: u8,
    },
    FrameLength {
        minimum: usize,
        maximum: usize,
        actual: usize,
    },
    Protocol {
        error: ProtocolError,
    },
    UnsupportedModel {
        model_id: u16,
    },
    RejectedState {
        high_byte: u8,
    },
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenOpcode { opcode } => write!(
                f,
                "opcode {opcode:02X} is outside the normal-query allowlist"
            ),
            Self::FrameLength {
                minimum,
                maximum,
                actual,
            } => write!(
                f,
                "offline query frame must be {minimum}..={maximum} bytes, found {actual}; length is outside the audited codec bounds"
            ),
            Self::Protocol { error } => error.fmt(f),
            Self::UnsupportedModel { model_id } => write!(
                f,
                "returned model 0x{model_id:03X} is not ordinary W95 Max 0x578"
            ),
            Self::RejectedState { high_byte } => write!(
                f,
                "state high byte {high_byte} fails the vendor normal-state check (<=1)"
            ),
        }
    }
}
impl std::error::Error for QueryError {}

/// Caller-supplied hypothetical geometry for offline validation. Construction
/// does not attest that a real descriptor has been collected or parsed.
#[derive(Debug, Clone, Copy)]
pub struct OfflineQueryFrame {
    query: NormalQuery,
    length: usize,
}

impl OfflineQueryFrame {
    pub fn new(query: NormalQuery, length: usize) -> Result<Self, QueryError> {
        let minimum = 8 + query.payload_len();
        // The vendor's generic scratch buffer is 72 bytes. Supporting larger
        // physical frames would require separately established semantics.
        if !(minimum..=GENERIC_LOCAL_LEN).contains(&length) {
            return Err(QueryError::FrameLength {
                minimum,
                maximum: GENERIC_LOCAL_LEN,
                actual: length,
            });
        }
        Ok(Self { query, length })
    }

    pub fn request(self) -> Vec<u8> {
        let mut bytes = vec![0; self.length];
        bytes[..8].copy_from_slice(&self.query.header());
        bytes
    }

    pub fn decode(self, reply: &[u8]) -> Result<NormalReply, QueryError> {
        if reply.len() != self.length {
            return Err(QueryError::Protocol {
                error: ProtocolError::Length {
                    expected: self.length,
                    actual: reply.len(),
                },
            });
        }
        check_header(self.query, &reply[..8])?;
        let payload = &reply[8..8 + self.query.payload_len()];
        match self.query {
            NormalQuery::Identity => {
                let packed = u16::from_le_bytes([payload[2], payload[3]]);
                let model_id = packed & 0xFFFC;
                let model = Model::try_from(model_id)
                    .map_err(|_| QueryError::UnsupportedModel { model_id })?;
                let core = match packed & 3 {
                    0 => Core::Four,
                    1 => Core::One,
                    2 => Core::Two,
                    _ => Core::Three,
                };
                Ok(NormalReply::Identity {
                    model,
                    core,
                    packed_model_core: packed,
                    version_compare_word: u16::from_le_bytes([payload[4], payload[5]]),
                    raw_payload: payload.try_into().expect("ten-byte payload"),
                })
            }
            NormalQuery::Status => {
                let state = u32::from_le_bytes(payload[..4].try_into().expect("DWORD"));
                let high_byte = (state >> 24) as u8;
                if high_byte > 1 {
                    return Err(QueryError::RejectedState { high_byte });
                }
                Ok(NormalReply::Status {
                    state_dword: state,
                    state_high_byte: high_byte,
                    display_version_word: u16::from_le_bytes([payload[4], payload[5]]),
                    raw_payload: payload.try_into().expect("24-byte payload"),
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "query", rename_all = "snake_case")]
pub enum NormalReply {
    Identity {
        model: Model,
        core: Core,
        packed_model_core: u16,
        version_compare_word: u16,
        raw_payload: [u8; 10],
    },
    Status {
        state_dword: u32,
        state_high_byte: u8,
        display_version_word: u16,
        raw_payload: [u8; 24],
    },
}

fn check_header(query: NormalQuery, header: &[u8]) -> Result<(), QueryError> {
    for (offset, expected) in query.header().into_iter().enumerate() {
        if header[offset] != expected {
            return Err(QueryError::Protocol {
                error: ProtocolError::Header {
                    offset,
                    expected,
                    actual: header[offset],
                },
            });
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct QuerySpec {
    pub name: NormalQuery,
    pub opcode: u8,
    pub header: [u8; 8],
    pub payload_bytes: usize,
    pub minimum_frame_bytes: usize,
    pub wrapper_va: &'static str,
    pub fields: &'static str,
}

#[derive(Debug, Serialize)]
pub struct QueryAudit {
    pub schema_version: u32,
    pub mode: &'static str,
    pub live_queries_enabled: bool,
    pub device_enumerated: bool,
    pub actual_feature_report_length: Option<usize>,
    pub normal_query_allowlist: Vec<QuerySpec>,
    pub excluded_from_normal_query_mode: Vec<&'static str>,
    pub physical_prerequisites: Vec<&'static str>,
}

pub fn audit() -> QueryAudit {
    QueryAudit {
        schema_version: 1, mode: "offline_query_audit", live_queries_enabled: false,
        device_enumerated: false, actual_feature_report_length: None,
        normal_query_allowlist: NormalQuery::ALL.into_iter().map(|query| QuerySpec {
            name: query, opcode: query.opcode(), header: query.header(), payload_bytes: query.payload_len(),
            minimum_frame_bytes: 8 + query.payload_len(),
            wrapper_va: match query { NormalQuery::Identity => "0x5a3d48", NormalQuery::Status => "0x5a2db0" },
            fields: match query {
                NormalQuery::Identity => "Payload +2 LE WORD: model & FFFC, Core index & 3 (0 -> Core 4); +4 LE WORD: raw firmware comparison word",
                NormalQuery::Status => "Payload +0 LE DWORD high byte <=1; +4 LE WORD: raw version-display word; meanings of remaining bytes unassigned",
            },
        }).collect(),
        excluded_from_normal_query_mode: vec![
            "07 00: reset", "07 09: programming preparation", "07 28: upgrade transition",
            "07 29: boot preflight namespace; the vendor preflight may initialize it",
            "07 2B: finalization namespace", "07 2C: boot model query",
            "07 01 01: firmware records", "07 2F: configuration writes", "07 21: NOR command tunnel",
            "Any nonzero header/control byte, unknown opcode, arbitrary raw request, or automatic initialization",
        ],
        physical_prerequisites: vec![
            "P1: cached sysfs metadata and raw descriptor only; no hidraw handle or vendor report",
            "Candidate filter: USB VID 09DA, nonstandard usage, report ID 07 feature support; model unconfirmed until query",
            "Bind one normal candidate; reject ambiguity and boot interfaces; correlate serial/topology without treating PID as identity",
            "Derive per-ID feature length from the descriptor; local 64/72-byte buffers are not device capabilities",
            "P2: serialize only allowlisted SetFeature/GetFeature query pairs; query 1F before 2D; stop on any failure or mismatch",
            "Feature ioctls lack per-call timeout in audited backend; isolate a future query worker and stop on uncertain outcome without retry/reset",
            "Host audit shows query construction, not a measurement of receiver-side non-mutation",
        ],
    }
}

impl QueryAudit {
    pub fn text(&self) -> String {
        let mut text = "ratmax | OFFLINE QUERY AUDIT\nLive queries: DISABLED | Mouse not enumerated or opened\nActual device report length: UNKNOWN\n\nHost-audited normal query allowlist (future P2 only):\n".to_owned();
        for spec in &self.normal_query_allowlist {
            text.push_str(&format!(
                "07 {:02X}: {} payload bytes; minimum frame {} including ID\n  {}\n",
                spec.opcode, spec.payload_bytes, spec.minimum_frame_bytes, spec.fields
            ));
        }
        text.push_str("\nQueries use zero control bytes and SetFeature then GetFeature.\nAll eight echoed header bytes and the actual reply length must match.\nA query is not literally the absence of an outbound USB transfer.\n\nBefore physical queries:\n");
        for prerequisite in &self.physical_prerequisites {
            text.push_str(&format!("- {prerequisite}\n"));
        }
        text
    }
}
