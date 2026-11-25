//! Offline R3e readback codecs. No transport, device access or write API.
//! Layouts and header observations do not establish a restorable backup.

use crate::{firmware, protocol::ProtocolError};
use serde::Serialize;
use std::fmt;

pub const FRAME_BYTES: usize = 64;
pub const DESCRIPTOR_BYTES: usize = 40;
pub const HEADER_BYTES: u32 = 8;
pub const SENSITIVITY_BYTES: usize = 256;
const DESCRIPTOR_HEADER: [u8; 8] = [7, 5, 0, 0, 0, 0, 0, 0];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReadbackError {
    Protocol {
        error: ProtocolError,
    },
    InvalidDwordCount {
        actual: u32,
    },
    EmptySpan,
    AddressOverflow {
        start: u32,
        bytes: u32,
    },
    OutsideHeader {
        offset: u32,
        bytes: u32,
    },
    LayoutMismatch,
    ConflictingObservation {
        region: HeaderRegion,
        offset: usize,
    },
    UncertainBaseline,
    IncompleteBackup {
        sensitivity_observed: usize,
        sensitivity_required: usize,
        main_header_observed: usize,
    },
}
impl fmt::Display for ReadbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { error } => error.fmt(f),
            Self::InvalidDwordCount { actual } => write!(
                f,
                "read count must be exactly 1 or 2 DWORDs, found {actual}"
            ),
            Self::EmptySpan => f.write_str("an empty byte span is not a read"),
            Self::AddressOverflow { start, bytes } => write!(
                f,
                "{bytes} bytes at {start:08X} exceed the 32-bit address field"
            ),
            Self::OutsideHeader { offset, bytes } => write!(
                f,
                "{bytes} bytes at offset {offset} do not fit DWORD-aligned within an 8-byte header"
            ),
            Self::LayoutMismatch => {
                f.write_str("header observation belongs to another descriptor reply")
            }
            Self::ConflictingObservation { region, offset } => write!(
                f,
                "conflicting {region:?} header observation at byte {offset}"
            ),
            Self::UncertainBaseline => {
                f.write_str("baseline is uncertain; no further observations or restore permitted")
            }
            Self::IncompleteBackup {
                sensitivity_observed,
                sensitivity_required,
                main_header_observed,
            } => write!(
                f,
                "partial observations are not a backup: sensitivity {sensitivity_observed}/{sensitivity_required} bytes, main header {main_header_observed}/8; full profile/NOR coverage and restoration unestablished"
            ),
        }
    }
}
impl std::error::Error for ReadbackError {}
fn length(bytes: &[u8], expected: usize) -> Result<(), ReadbackError> {
    if bytes.len() != expected {
        return Err(ReadbackError::Protocol {
            error: ProtocolError::Length {
                expected,
                actual: bytes.len(),
            },
        });
    }
    Ok(())
}
fn byte(bytes: &[u8], offset: usize, expected: u8) -> Result<(), ReadbackError> {
    if bytes[offset] != expected {
        return Err(ReadbackError::Protocol {
            error: ProtocolError::Header {
                offset,
                expected,
                actual: bytes[offset],
            },
        });
    }
    Ok(())
}

/// Pure arithmetic only: no claim about device capacity, erase spans or valid
/// regions. A final byte at u32::MAX is representable; end-exclusive uses u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ByteSpan {
    start: u32,
    bytes: u32,
}
impl ByteSpan {
    pub fn new(start: u32, bytes: u32) -> Result<Self, ReadbackError> {
        if bytes == 0 {
            return Err(ReadbackError::EmptySpan);
        }
        start
            .checked_add(bytes - 1)
            .ok_or(ReadbackError::AddressOverflow { start, bytes })?;
        Ok(Self { start, bytes })
    }
    pub const fn start(self) -> u32 {
        self.start
    }
    pub const fn bytes(self) -> u32 {
        self.bytes
    }
    pub const fn end_exclusive(self) -> u64 {
        self.start as u64 + self.bytes as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LayoutBases {
    pub sensitivity: u32,
    pub main_profile: u32,
    pub additional_profile: u32,
}

/// Exactly 40 raw metadata bytes. Zero/FF/unknown fields remain raw, without
/// inferring capacity, validity, defaults, model or Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeDescriptor {
    raw_payload: Vec<u8>,
    bases: LayoutBases,
}
impl RuntimeDescriptor {
    pub fn decode_payload(payload: &[u8]) -> Result<Self, ReadbackError> {
        length(payload, DESCRIPTOR_BYTES)?;
        let word = |i| u32::from(u16::from_le_bytes([payload[i], payload[i + 1]]));
        Ok(Self {
            raw_payload: payload.to_vec(),
            bases: LayoutBases {
                sensitivity: word(4),
                main_profile: word(6) | (u32::from(payload[10]) << 16),
                additional_profile: word(8) | (u32::from(payload[11]) << 16),
            },
        })
    }
    pub fn raw_payload(&self) -> &[u8] {
        &self.raw_payload
    }
    pub const fn bases(&self) -> LayoutBases {
        self.bases
    }
}

pub fn descriptor_request() -> [u8; FRAME_BYTES] {
    let mut request = [0; FRAME_BYTES];
    request[..8].copy_from_slice(&DESCRIPTOR_HEADER);
    request
}

/// Framed offline evidence, not attestation of a physical unit or session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeDescriptorReply {
    raw_reply: Vec<u8>,
    descriptor: RuntimeDescriptor,
    /// Digest of all 64 bytes, including unknown bytes/trailer. Not a unit ID.
    reply_sha256: String,
}
impl RuntimeDescriptorReply {
    pub fn decode(reply: &[u8]) -> Result<Self, ReadbackError> {
        length(reply, FRAME_BYTES)?;
        for (offset, expected) in DESCRIPTOR_HEADER.into_iter().enumerate() {
            byte(reply, offset, expected)?;
        }
        Ok(Self {
            raw_reply: reply.to_vec(),
            descriptor: RuntimeDescriptor::decode_payload(&reply[8..48])?,
            reply_sha256: firmware::sha256(reply),
        })
    }
    pub fn raw_reply(&self) -> &[u8] {
        &self.raw_reply
    }
    pub fn descriptor(&self) -> &RuntimeDescriptor {
        &self.descriptor
    }
    pub fn reply_sha256(&self) -> &str {
        &self.reply_sha256
    }
    pub fn header_read(&self, region: HeaderRegion) -> Result<HeaderRead, ReadbackError> {
        let bases = self.descriptor.bases();
        let base = match region {
            HeaderRegion::Sensitivity => bases.sensitivity,
            HeaderRegion::MainProfile => bases.main_profile,
        };
        ByteSpan::new(base, HEADER_BYTES)?;
        Ok(HeaderRead {
            region,
            header_base: base,
            offset: 0,
            count: DwordCount::Two,
            layout_reply_sha256: self.reply_sha256.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderRegion {
    Sensitivity,
    MainProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(into = "u32")]
pub enum DwordCount {
    One,
    Two,
}
impl TryFrom<u32> for DwordCount {
    type Error = ReadbackError;
    fn try_from(actual: u32) -> Result<Self, Self::Error> {
        match actual {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(ReadbackError::InvalidDwordCount { actual }),
        }
    }
}
impl From<DwordCount> for u32 {
    fn from(value: DwordCount) -> Self {
        match value {
            DwordCount::One => 1,
            DwordCount::Two => 2,
        }
    }
}
impl DwordCount {
    pub fn bytes(self) -> u32 {
        u32::from(self) * 4
    }
}

/// Only an audited header, optionally a DWORD-aligned fragment within it. No
/// public raw-address constructor, arbitrary offset, write variant or transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderRead {
    region: HeaderRegion,
    header_base: u32,
    offset: u32,
    count: DwordCount,
    layout_reply_sha256: String,
}
impl HeaderRead {
    /// Offset is relative to the original 8-byte header, not the current part.
    pub fn part(&self, offset: u32, count: DwordCount) -> Result<Self, ReadbackError> {
        if !offset.is_multiple_of(4)
            || u64::from(offset) + u64::from(count.bytes()) > u64::from(HEADER_BYTES)
        {
            return Err(ReadbackError::OutsideHeader {
                offset,
                bytes: count.bytes(),
            });
        }
        let mut read = self.clone();
        read.offset = offset;
        read.count = count;
        Ok(read)
    }
    pub fn requested_span(&self) -> ByteSpan {
        // Construction proved the entire header fits the 32-bit address field.
        ByteSpan {
            start: self.header_base + self.offset,
            bytes: self.count.bytes(),
        }
    }
    pub const fn region(&self) -> HeaderRegion {
        self.region
    }
    pub const fn offset(&self) -> u32 {
        self.offset
    }
    pub const fn count(&self) -> DwordCount {
        self.count
    }
    pub fn request(&self) -> [u8; FRAME_BYTES] {
        let mut request = [0; FRAME_BYTES];
        request[..3].copy_from_slice(&[7, 0x2f, 0]);
        request[24..28].copy_from_slice(&u32::from(self.count).to_le_bytes());
        request[28..32].copy_from_slice(&self.requested_span().start().to_le_bytes());
        request
    }
    /// Frame screening only. The vendor checks opcode alone; Ratmax adds ID
    /// and exact length. No mode, count, address or full-header echo is proven.
    /// Returned bytes are candidate observations, not address-verified storage.
    pub fn observe_reply(&self, reply: &[u8]) -> Result<HeaderObservation, ReadbackError> {
        length(reply, FRAME_BYTES)?;
        byte(reply, 0, 7)?;
        byte(reply, 1, 0x2f)?;
        Ok(HeaderObservation {
            request: self.clone(),
            raw_reply: reply.to_vec(),
            data: reply[32..32 + self.count.bytes() as usize].to_vec(),
            address_count_echo_validated: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderObservation {
    request: HeaderRead,
    raw_reply: Vec<u8>,
    data: Vec<u8>,
    address_count_echo_validated: bool,
}
impl HeaderObservation {
    pub fn request(&self) -> &HeaderRead {
        &self.request
    }
    pub fn raw_reply(&self) -> &[u8] {
        &self.raw_reply
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub const fn address_count_echo_validated(&self) -> bool {
        false
    }
    pub fn storage_header(&self) -> Option<StorageHeader> {
        (self.request.offset == 0 && self.data.len() == HEADER_BYTES as usize)
            .then(|| StorageHeader::from_bytes(&self.data))
    }
}

/// Raw fields only. No marker/checksum validity or restoration is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StorageHeader {
    pub marker_dword: u32,
    pub additive_word: u16,
    pub weighted_word: u16,
}
impl StorageHeader {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            marker_dword: u32::from_le_bytes(bytes[..4].try_into().expect("four bytes")),
            additive_word: u16::from_le_bytes([bytes[4], bytes[5]]),
            weighted_word: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }
}

/// Bounded union of two 8-byte observation windows. Repeated observations do
/// not increase coverage; conflicts/mixed layouts poison the assessment.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderBaseline {
    layout_reply_sha256: String,
    sensitivity: [Option<u8>; 8],
    main_profile: [Option<u8>; 8],
    uncertain: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineAssessment {
    pub sensitivity_header_observed_bytes: usize,
    pub sensitivity_storage_bytes_required: usize,
    pub sensitivity_storage_bytes_not_observed: usize,
    pub main_profile_header_observed_bytes: usize,
    pub full_profile_size_known: bool,
    pub nor_bytes_observed: usize,
    pub address_count_echo_validated: bool,
    pub uncertain: bool,
    pub complete_backup: bool,
    pub restoration_supported: bool,
}
impl HeaderBaseline {
    pub fn new(layout: &RuntimeDescriptorReply) -> Self {
        Self {
            layout_reply_sha256: layout.reply_sha256.clone(),
            sensitivity: [None; 8],
            main_profile: [None; 8],
            uncertain: false,
        }
    }
    pub fn record(&mut self, observation: &HeaderObservation) -> Result<(), ReadbackError> {
        if self.uncertain {
            return Err(ReadbackError::UncertainBaseline);
        }
        if observation.request.layout_reply_sha256 != self.layout_reply_sha256 {
            self.uncertain = true;
            return Err(ReadbackError::LayoutMismatch);
        }
        let target = match observation.request.region {
            HeaderRegion::Sensitivity => &mut self.sensitivity,
            HeaderRegion::MainProfile => &mut self.main_profile,
        };
        let start = observation.request.offset as usize;
        for (i, b) in observation.data.iter().enumerate() {
            if target[start + i].is_some_and(|old| old != *b) {
                self.uncertain = true;
                return Err(ReadbackError::ConflictingObservation {
                    region: observation.request.region,
                    offset: start + i,
                });
            }
        }
        for (i, b) in observation.data.iter().enumerate() {
            target[start + i] = Some(*b);
        }
        Ok(())
    }
    pub fn assessment(&self) -> BaselineAssessment {
        let sensitivity = self.sensitivity.iter().flatten().count();
        BaselineAssessment {
            sensitivity_header_observed_bytes: sensitivity,
            sensitivity_storage_bytes_required: SENSITIVITY_BYTES,
            sensitivity_storage_bytes_not_observed: SENSITIVITY_BYTES - sensitivity,
            main_profile_header_observed_bytes: self.main_profile.iter().flatten().count(),
            full_profile_size_known: false,
            nor_bytes_observed: 0,
            address_count_echo_validated: false,
            uncertain: self.uncertain,
            complete_backup: false,
            restoration_supported: false,
        }
    }
    pub fn storage_header(&self, region: HeaderRegion) -> Option<StorageHeader> {
        let bytes = match region {
            HeaderRegion::Sensitivity => self.sensitivity,
            HeaderRegion::MainProfile => self.main_profile,
        };
        let collected = bytes.into_iter().collect::<Option<Vec<_>>>()?;
        Some(StorageHeader::from_bytes(&collected))
    }
    /// Header evidence can never satisfy a full preservation/restoration gate.
    pub fn require_restorable_backup(&self) -> Result<(), ReadbackError> {
        if self.uncertain {
            return Err(ReadbackError::UncertainBaseline);
        }
        let a = self.assessment();
        Err(ReadbackError::IncompleteBackup {
            sensitivity_observed: a.sensitivity_header_observed_bytes,
            sensitivity_required: SENSITIVITY_BYTES,
            main_header_observed: a.main_profile_header_observed_bytes,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HeaderRequestPreview {
    pub request: HeaderRead,
    pub buffer: Vec<u8>,
}
/// An offline inspection always reports partial, unverified-address coverage.
#[derive(Debug, Serialize)]
pub struct OfflineInspection {
    pub schema_version: u32,
    pub mode: &'static str,
    pub live_readback_enabled: bool,
    pub descriptor_query_buffer: Vec<u8>,
    pub descriptor: RuntimeDescriptorReply,
    pub header_requests: Vec<HeaderRequestPreview>,
    pub observations: Vec<HeaderObservation>,
    pub baseline: BaselineAssessment,
    pub backup_gate_error: String,
    pub limitations: Vec<&'static str>,
}
impl OfflineInspection {
    pub fn new(
        layout_reply: &[u8],
        sensitivity_reply: Option<&[u8]>,
        main_reply: Option<&[u8]>,
    ) -> Result<Self, ReadbackError> {
        let descriptor = RuntimeDescriptorReply::decode(layout_reply)?;
        let mut baseline = HeaderBaseline::new(&descriptor);
        let mut header_requests = Vec::new();
        let mut observations = Vec::new();
        for (region, reply) in [
            (HeaderRegion::Sensitivity, sensitivity_reply),
            (HeaderRegion::MainProfile, main_reply),
        ] {
            let request = descriptor.header_read(region)?;
            if let Some(raw) = reply {
                let observation = request.observe_reply(raw)?;
                baseline.record(&observation)?;
                observations.push(observation);
            }
            header_requests.push(HeaderRequestPreview {
                buffer: request.request().to_vec(),
                request,
            });
        }
        let backup_gate_error = baseline
            .require_restorable_backup()
            .expect_err("headers never authorize restore")
            .to_string();
        Ok(Self {
            schema_version: 1,
            mode: "offline_readback_inspection",
            live_readback_enabled: false,
            descriptor_query_buffer: descriptor_request().to_vec(),
            descriptor,
            header_requests,
            observations,
            baseline: baseline.assessment(),
            backup_gate_error,
            limitations: vec![
                "Input files are offline evidence; decoding does not authenticate a physical unit, Core, session or region capacity.",
                "This inspector never sends reports. query-info excludes 05/2F; query-layout adds 05; dedicated header/body modes alone permit their scoped 2F00 windows.",
                "Addressed replies are screened by length/ID/opcode only; address/count/mode/full-header echoes are unestablished.",
                "At most eight candidate bytes per header; no complete settings/profile/NOR backup or restoration capability.",
                "Raw unknown fields and trailer bytes are preserved; markers/checksums are not verified and never trigger initialization.",
            ],
        })
    }
    pub fn text(&self) -> String {
        let b = self.descriptor.descriptor().bases();
        let a = &self.baseline;
        format!(
            "ratmax | OFFLINE READBACK INSPECTION\nRuntime layout bytes: 40 (64-byte reply)\nSensitivity base: 0x{:08X}\nMain-profile base: 0x{:08X}\nAdditional-profile base: 0x{:08X}\nDescriptor reply SHA-256: {}\n\nCandidate header bytes: sensitivity {}/8; main profile {}/8\nSensitivity storage bytes still unobserved: {}/256\nAddress/count echo verification: UNESTABLISHED\nRestorable backup: NO\n{}\n\nDisplayed addresses/buffers are offline observations and unsent previews.\nNo device access, queries, initialization, reset or writes.\n",
            b.sensitivity,
            b.main_profile,
            b.additional_profile,
            self.descriptor.reply_sha256(),
            a.sensitivity_header_observed_bytes,
            a.main_profile_header_observed_bytes,
            a.sensitivity_storage_bytes_not_observed,
            self.backup_gate_error
        )
    }
}
