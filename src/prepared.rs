//! Prepared stock firmware image representation for W95 Max Cores 1–4.

use crate::{assets::ValidatedImage, firmware, model::Core};
use serde::Serialize;

pub const FLASH_BYTES: usize = 65536;
pub const MAX_FEATURE_CALLS: u32 = 25_000;

/// Compute the default USB VID/PID identity DWORD derived from the unit's `U` word.
pub fn default_identity(u: u32) -> u32 {
    let low = u as u16;
    let pid =
        (((u32::from(low) >> 14) * 2 + 1) << 12) | (u32::from(low.wrapping_add(0x8882)) & 0xfff);
    0x09da_0000 | pid
}

pub struct Plan {
    image: ValidatedImage,
    pub(crate) decoded: Vec<u8>,
    pub(crate) covered: Vec<bool>,
}

#[derive(Serialize)]
pub struct Summary {
    pub core: Core,
    pub source_sha256: String,
    pub programmed_ranges: [(u32, u32); 2],
    pub source_covered_bytes: usize,
    pub last_record_index: usize,
    pub target_version: u16,
    pub target_boot_revision: u32,
    pub target_boot_copy_sha256: String,
    pub target_normal_descriptor_sha256: String,
    pub source_default_usb_identity: u32,
}

impl Plan {
    pub(crate) fn image_records(&self) -> &[firmware::EncodedRecord] {
        self.image.records().records()
    }

    pub fn core(&self) -> Core {
        self.image.inspection().core
    }

    pub(crate) fn boot_copy(&self) -> &[u8] {
        let base = if self.core().firmware_index().get() < 2 {
            0x46d4
        } else {
            0x46cc
        };
        &self.decoded[base..base + 3072]
    }

    pub fn new(image: ValidatedImage) -> Result<Self, String> {
        let mut decoded = vec![0; FLASH_BYTES];
        let mut covered = vec![false; FLASH_BYTES];
        for record in image.records().records() {
            let at = record.address().get() as usize;
            decoded[at..at + 32].copy_from_slice(&record.decoded_payload());
            covered[at..at + 32].fill(true);
        }
        let packed_model = u16::from_le_bytes(decoded[0xfec6..0xfec8].try_into().unwrap());
        let boot_base = if image.inspection().firmware_index.get() < 2 {
            0x46d4
        } else {
            0x46cc
        };
        if packed_model != (0x578 | u16::from(image.inspection().firmware_index.get()))
            || decoded[0xfec4..0xfec6] != [0x34, 0]
            || decoded[0xfefc..0xff00] != [0xa4; 4]
            || decoded[boot_base + 0xbfc..boot_base + 0xc00] != [3, 0, 0xa4, 0xa4]
        {
            return Err("prepared image metadata differs from the supported W95 Max target".into());
        }
        Ok(Self {
            image,
            decoded,
            covered,
        })
    }

    pub fn summary(&self) -> Summary {
        let boot_base = if self.image.inspection().firmware_index.get() < 2 {
            0x46d4
        } else {
            0x46cc
        };
        Summary {
            core: self.image.inspection().core,
            source_sha256: self.image.inspection().source_sha256.clone(),
            programmed_ranges: [(0, 0x5460), (0x7fe0, 0xff00)],
            source_covered_bytes: self.covered.iter().filter(|&&b| b).count(),
            last_record_index: firmware::RECORD_COUNT - 1,
            target_version: 0x34,
            target_boot_revision: 0xa4a4_0003,
            target_boot_copy_sha256: firmware::sha256(&self.decoded[boot_base..boot_base + 0xc00]),
            target_normal_descriptor_sha256: firmware::sha256(
                &self.decoded[boot_base + 0xca8..boot_base + 0xca8 + 180],
            ),
            source_default_usb_identity: u32::from_le_bytes(
                self.decoded[0xfee0..0xfee4].try_into().unwrap(),
            ),
        }
    }
}
