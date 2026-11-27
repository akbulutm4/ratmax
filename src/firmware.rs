//! W95 Max `.hexEncode` record cipher and 64-byte Feature Report buffer codecs.
//! Decoding supplies the receiver's programming arguments; erase bounds are separate.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::Error;

pub const RECORD_LEN: usize = 36;
pub const ENCODED_PAYLOAD_LEN: u32 = 32;
pub const RECORD_COUNT: usize = 1692;
pub const IMAGE_LEN: usize = RECORD_COUNT * RECORD_LEN;
pub const LOCAL_BUFFER_LEN: usize = 64;
pub const LOCAL_STREAM_LEN: usize = RECORD_COUNT * LOCAL_BUFFER_LEN;

const HEADER_LEN: usize = LOCAL_BUFFER_LEN - RECORD_LEN;
const HEADER: [u8; HEADER_LEN] = [
    7, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EncodedAddress(u32);

impl EncodedAddress {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EncodedRange {
    pub start: EncodedAddress,
    pub end_exclusive: EncodedAddress,
}

/// Occupied ranges, not evidence that the gap contains a protected bootloader.
pub const W95MAX_RANGES: [EncodedRange; 2] = [
    EncodedRange {
        start: EncodedAddress(0),
        end_exclusive: EncodedAddress(0x5460),
    },
    EncodedRange {
        start: EncodedAddress(0x7FE0),
        end_exclusive: EncodedAddress(0xFF00),
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedRecord([u8; RECORD_LEN]);

impl EncodedRecord {
    /// Inverse of the receiver transform; no device access or address policy.
    pub(crate) fn encode(address: u32, plain: &[u8; 32]) -> Self {
        let mut bytes = [0; RECORD_LEN];
        for (index, &chunk) in plain.as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_le_bytes(chunk);
            let mask = if index == 7 { 0x8913_9813 } else { 0 };
            let cipher = (word ^ 0x2218_4952).wrapping_sub(0xa4a4_55aa) ^ mask;
            bytes[4 + index * 4..8 + index * 4].copy_from_slice(&cipher.to_le_bytes());
        }
        let first = u32::from_le_bytes(bytes[4..8].try_into().expect("DWORD"));
        bytes[..4].copy_from_slice(
            &first
                .wrapping_add(0xa4a4_55aa)
                .wrapping_sub(address)
                .to_le_bytes(),
        );
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bytes.try_into().map_err(|_| Error::Length {
            context: "encoded record",
            expected: RECORD_LEN,
            actual: bytes.len() as u64,
        })?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; RECORD_LEN] {
        &self.0
    }

    pub fn address(&self) -> EncodedAddress {
        let header = u32::from_le_bytes(self.0[..4].try_into().expect("fixed DWORD"));
        let payload0 = u32::from_le_bytes(self.0[4..8].try_into().expect("fixed DWORD"));
        EncodedAddress(payload0.wrapping_sub(header).wrapping_add(0xA4A4_55AA))
    }

    /// Decode the 32-byte payload of a single `.hexEncode` record.
    pub fn decoded_payload(&self) -> [u8; 32] {
        let mut plain = [0; 32];
        for (index, &bytes) in self.0[4..].as_chunks::<4>().0.iter().enumerate() {
            let cipher = u32::from_le_bytes(bytes);
            let mask = if index == 7 { 0x8913_9813 } else { 0 };
            let word = (cipher ^ mask).wrapping_add(0xA4A4_55AA) ^ 0x2218_4952;
            plain[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        plain
    }

    /// Build the 64-byte Feature Report buffer used to program this 32-byte flash record.
    pub fn local_buffer(&self) -> [u8; LOCAL_BUFFER_LEN] {
        let mut buffer = [0; LOCAL_BUFFER_LEN];
        buffer[..HEADER_LEN].copy_from_slice(&HEADER);
        buffer[HEADER_LEN..].copy_from_slice(&self.0);
        buffer
    }

    /// Decode a 64-byte bootloader record Feature Report buffer back into an `EncodedRecord`.
    pub fn from_local_buffer(buffer: &[u8]) -> Result<Self, Error> {
        if buffer.len() != LOCAL_BUFFER_LEN {
            return Err(Error::Length {
                context: "local record buffer",
                expected: LOCAL_BUFFER_LEN,
                actual: buffer.len() as u64,
            });
        }
        if buffer[..HEADER_LEN] != HEADER {
            return Err(Error::BufferHeader);
        }
        Self::parse(&buffer[HEADER_LEN..])
    }
}

/// Structurally valid W95 Max stream, not yet authenticated against an asset.
#[derive(Debug)]
pub struct W95MaxRecords {
    records: Vec<EncodedRecord>,
}

impl W95MaxRecords {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != IMAGE_LEN {
            return Err(Error::Length {
                context: "W95 Max image",
                expected: IMAGE_LEN,
                actual: bytes.len() as u64,
            });
        }
        let expected_addresses = W95MAX_RANGES.iter().flat_map(|range| {
            (range.start.0..range.end_exclusive.0).step_by(ENCODED_PAYLOAD_LEN as usize)
        });
        let mut records = Vec::with_capacity(RECORD_COUNT);
        for (index, (bytes, expected)) in bytes
            .as_chunks::<RECORD_LEN>()
            .0
            .iter()
            .zip(expected_addresses)
            .enumerate()
        {
            let record = EncodedRecord::parse(bytes)?;
            let actual = record.address().get();
            if actual != expected {
                return Err(Error::Address {
                    record: index,
                    expected,
                    actual,
                });
            }
            records.push(record);
        }
        debug_assert_eq!(records.len(), RECORD_COUNT);
        Ok(Self { records })
    }

    pub fn records(&self) -> &[EncodedRecord] {
        &self.records
    }

    pub fn local_buffer_stream(&self) -> Vec<u8> {
        let mut stream = Vec::with_capacity(LOCAL_STREAM_LEN);
        for record in &self.records {
            stream.extend_from_slice(&record.local_buffer());
        }
        stream
    }

    pub fn local_buffer_sha256(&self) -> String {
        let mut hash = Sha256::new();
        for record in &self.records {
            hash.update(record.local_buffer());
        }
        digest_hex(&hash.finalize())
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    digest_hex(&Sha256::digest(bytes))
}

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 15)] as char);
    }
    output
}
