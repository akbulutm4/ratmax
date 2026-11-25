//! Fixed normal-mode read ranges, cryptographic digests, and standard USB/HID
//! descriptors for the W95 Max boot preflight. Contains no vendor firmware code.
use crate::{
    access_job::{BLOCK_BYTES, SETTINGS_ADDRESSES},
    firmware::sha256,
};
use serde::{Deserialize, Serialize};

pub const BANK_BASE: u32 = 0x1fff0000;
pub const COPY_BASE: u32 = 0x3c60;
pub const BANK_BYTES: usize = 0xc00;
pub const BANK_BLOCKS: usize = BANK_BYTES / BLOCK_BYTES;

/// SHA-256 of the verified 3,072-byte revision-2 (original 0028) active boot bank.
pub const ORIGINAL_SHA256: &str =
    "f4aa5cfd31ae900b340602318e5b607f6aba75f664096fb520323acd6cabb584";
/// SHA-256 of the verified 3,072-byte revision-3 (prepared 0034) active boot bank.
pub const PREPARED_SHA256: &str =
    "54942bb76b5e76c4d74f8f9b420871cce4b757b7ef343d637e94a107aeb580d7";
pub const ORIGINAL_VERSION_WORD: u32 = 0xa4a4_0002;
pub const PREPARED_VERSION_WORD: u32 = 0xa4a4_0003;
pub const COVERED_COPY_BYTES: usize = 2784;

/// Standard USB Device Descriptor for bootloader 09DA:D023, revision 2 (bcdDevice 0x0002).
const REV2_DEVICE_DESCRIPTOR: [u8; 18] = [
    18, 1, 16, 1, 0, 0, 0, 64, 218, 9, 35, 208, 2, 0, 0, 0, 0, 1,
];
/// Standard USB Device Descriptor for bootloader 09DA:D023, revision 3 (bcdDevice 0x0003).
const REV3_DEVICE_DESCRIPTOR: [u8; 18] = [
    18, 1, 16, 1, 0, 0, 0, 64, 218, 9, 35, 208, 3, 0, 1, 2, 3, 1,
];
/// Standard USB Configuration + HID Interface + Endpoint Descriptor for bootloader 09DA:D023.
const BOOT_CONFIG_DESCRIPTOR: [u8; 34] = [
    9, 2, 34, 0, 1, 1, 0, 128, 50, 9, 4, 0, 0, 1, 3, 0, 0, 0, 9, 33, 0, 1, 0, 1, 34, 24, 0, 7, 5,
    129, 3, 16, 0, 255,
];
/// Standard 24-byte HID Report Descriptor for bootloader 09DA:D023 (Report ID 7, 63-byte Feature).
pub const BOOT_HID_REPORT_DESCRIPTOR: [u8; 24] = [
    6, 35, 255, 10, 1, 0, 161, 1, 133, 7, 9, 166, 21, 0, 38, 255, 0, 117, 8, 149, 63, 177, 2, 192,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Revision {
    #[default]
    Original2,
    Prepared3,
}

impl Revision {
    pub(crate) fn is_original(&self) -> bool {
        *self == Self::Original2
    }
    pub(crate) fn usb_release(self) -> u16 {
        match self {
            Self::Original2 => 2,
            Self::Prepared3 => 3,
        }
    }
    pub(crate) fn expected_sha256(self) -> &'static str {
        match self {
            Self::Original2 => ORIGINAL_SHA256,
            Self::Prepared3 => PREPARED_SHA256,
        }
    }
    pub(crate) fn matches_bank(self, bytes: &[u8]) -> bool {
        bytes.len() == BANK_BYTES && sha256(bytes) == self.expected_sha256()
    }
    pub(crate) fn from_bank(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BANK_BYTES {
            return None;
        }
        let digest = sha256(bytes);
        [Self::Original2, Self::Prepared3]
            .into_iter()
            .find(|revision| digest == revision.expected_sha256())
    }
    pub(crate) fn usb_descriptors(self) -> Vec<u8> {
        let device = match self {
            Self::Original2 => &REV2_DEVICE_DESCRIPTOR[..],
            Self::Prepared3 => &REV3_DEVICE_DESCRIPTOR[..],
        };
        [device, &BOOT_CONFIG_DESCRIPTOR[..]].concat()
    }
}

pub fn matches_original_bank(bytes: &[u8]) -> bool {
    Revision::Original2.matches_bank(bytes)
}

pub fn matches_prepared_bank(bytes: &[u8]) -> bool {
    Revision::Prepared3.matches_bank(bytes)
}

pub fn matches_known_bank(bytes: &[u8]) -> bool {
    Revision::from_bank(bytes).is_some()
}

/// Structural W95 Max (model `0x0578`) check on the 96-byte `0xFEC0..0xFF20` block.
/// Accepts any W95 Max unit regardless of per-unit serial/calibration bytes.
pub fn valid_w95max_identity(bytes: &[u8]) -> bool {
    if bytes.len() != 96 {
        return false;
    }
    let header_model = u16::from_le_bytes(bytes[6..8].try_into().expect("2"));
    let usb_identity = u32::from_le_bytes(bytes[32..36].try_into().expect("4"));
    let final_model = u16::from_le_bytes(bytes[40..42].try_into().expect("2"));
    let protected_model = u16::from_le_bytes(bytes[70..72].try_into().expect("2"));
    (header_model & !3) == 0x0578
        && usb_identity == 0x09da_712f
        && (final_model & !3) == 0x0578
        && bytes[60..64] == [0xa4; 4]
        && (protected_model & !3) == 0x0578
}

pub const GAPS: [u32; 9] = [
    0xac0, 0xae0, 0xb00, 0xb20, 0xb40, 0xb60, 0xb80, 0xba0, 0xbc0,
];
pub const FIXED_IDENTITY: [u32; 3] = [0xfec0, 0xfee0, 0xff00];
pub const BLOCKS: usize =
    BANK_BLOCKS + GAPS.len() + FIXED_IDENTITY.len() + SETTINGS_ADDRESSES.len();
pub const PASS_BYTES: usize = BLOCKS * BLOCK_BYTES;
pub const IDENTITY_OFFSET: usize = BANK_BYTES + GAPS.len() * BLOCK_BYTES;
pub const SETTINGS_OFFSET: usize = IDENTITY_OFFSET + 96;
pub const MAX_CALLS: u32 = 496;

pub fn address(block: u16) -> Option<u32> {
    let mut index = usize::from(block);
    if index < BANK_BLOCKS {
        return Some(BANK_BASE + (index * BLOCK_BYTES) as u32);
    }
    index -= BANK_BLOCKS;
    if let Some(offset) = GAPS.get(index) {
        return Some(COPY_BASE + offset);
    }
    index -= GAPS.len();
    if let Some(address) = FIXED_IDENTITY.get(index) {
        return Some(*address);
    }
    index -= FIXED_IDENTITY.len();
    SETTINGS_ADDRESSES.get(index).copied()
}

/// Validate capture geometry. Content comparisons follow the complete capture.
pub fn validate_block(block: u16, data: &[u8], pass: &[u8]) -> Result<(), String> {
    let index = usize::from(block);
    if index >= BLOCKS || data.len() != BLOCK_BYTES || pass.len() != index * BLOCK_BYTES {
        return Err("invalid boot preflight cursor or data length".into());
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub active_version_word: String,
    pub expected_version_word: String,
    pub covered_copy_bytes: usize,
    pub differing_covered_copy_bytes: usize,
    pub differing_gap_copy_bytes: usize,
    pub differing_identity_bytes: usize,
    pub matches_embedded_copy_and_identity: bool,
    pub active_bank_sha256: String,
}

pub fn compare(pass: &[u8]) -> Option<Comparison> {
    if pass.len() != PASS_BYTES {
        return None;
    }
    let bank = &pass[..BANK_BYTES];
    let active_bank_sha256 = sha256(bank);
    let revision = Revision::from_bank(bank);
    let known_differences = usize::from(revision.is_none());
    let gap_differences = GAPS
        .iter()
        .enumerate()
        .map(|(index, &offset)| {
            let source = BANK_BYTES + index * BLOCK_BYTES;
            bank[offset as usize..offset as usize + BLOCK_BYTES]
                .iter()
                .zip(&pass[source..source + BLOCK_BYTES])
                .filter(|(active, embedded)| active != embedded)
                .count()
        })
        .sum();
    let identity_start = BANK_BYTES + GAPS.len() * BLOCK_BYTES;
    let identity_differences =
        usize::from(!valid_w95max_identity(&pass[identity_start..identity_start + 96]));
    let expected_word = match revision {
        Some(Revision::Prepared3) => PREPARED_VERSION_WORD,
        _ => ORIGINAL_VERSION_WORD,
    };
    Some(Comparison {
        active_version_word: format!(
            "{:08X}",
            u32::from_le_bytes(bank[BANK_BYTES - 4..].try_into().expect("4"))
        ),
        expected_version_word: format!("{expected_word:08X}"),
        covered_copy_bytes: COVERED_COPY_BYTES,
        differing_covered_copy_bytes: known_differences,
        differing_gap_copy_bytes: gap_differences,
        differing_identity_bytes: identity_differences,
        matches_embedded_copy_and_identity: known_differences == 0
            && gap_differences == 0
            && identity_differences == 0,
        active_bank_sha256,
    })
}

pub fn settings(pass: &[u8]) -> Result<&[u8], String> {
    if pass.len() != PASS_BYTES {
        return Err("incomplete boot preflight pass".into());
    }
    Ok(&pass[PASS_BYTES - 320..])
}
