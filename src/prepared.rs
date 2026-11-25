//! Prepared stock replay segment. All public entry points are device-free.
//! The composed, physically gated job lives in boot_roundtrip.
pub(crate) mod engine;
mod simulation;

use crate::{assets::ValidatedImage, firmware, model::Core};
use serde::Serialize;

pub use simulation::Scenario;

pub const FLASH_BYTES: usize = 65536;
pub const MAX_FEATURE_CALLS: u32 = 25_000;

/// Default branch of vendor 441560, before runtime mappings/overrides.
/// Acceptance also requires equality with the freshly captured unit identity.
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
    pub mode: &'static str,
    pub core: Core,
    pub source_sha256: String,
    pub physical_execution_available: bool,
    pub programmed_ranges: [(u32, u32); 2],
    pub source_covered_bytes: usize,
    pub last_record_index: usize,
    pub last_record_restores_marker_before_finalization: bool,
    pub target_version: u16,
    pub target_boot_revision: u32,
    pub target_boot_copy_sha256: String,
    pub target_normal_descriptor_sha256: String,
    pub source_default_usb_identity: u32,
    pub max_feature_calls: u32,
    pub policies: Vec<&'static str>,
    pub remaining_integration: Vec<&'static str>,
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
            return Err("prepared image metadata differs from the pinned W95 Max target".into());
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
            mode: "offline_prepared_replay_plan",
            core: self.image.inspection().core,
            source_sha256: self.image.inspection().source_sha256.clone(),
            physical_execution_available: false,
            programmed_ranges: [(0, 0x5460), (0x7fe0, 0xff00)],
            source_covered_bytes: self.covered.iter().filter(|&&b| b).count(),
            last_record_index: firmware::RECORD_COUNT - 1,
            last_record_restores_marker_before_finalization: true,
            target_version: 0x34,
            target_boot_revision: 0xa4a4_0003,
            target_boot_copy_sha256: firmware::sha256(&self.decoded[boot_base..boot_base + 0xc00]),
            target_normal_descriptor_sha256: firmware::sha256(
                &self.decoded[boot_base + 0xca8..boot_base + 0xca8 + 180],
            ),
            source_default_usb_identity: u32::from_le_bytes(
                self.decoded[0xfee0..0xfee4].try_into().unwrap(),
            ),
            max_feature_calls: MAX_FEATURE_CALLS,
            policies: vec![
                "Require verified same-port revision-2 boot binding before this segment.",
                "Read fresh U/V twice; erased or identity-mapping mismatch stops before records.",
                "Capture all 64 KiB twice with distinct seeds; persist both passes before records.",
                "Replay every original 36-byte record in order; check decoded response buffers and stop without retry after a record failure.",
                "Before the final marker-bearing record, read all 64 KiB against the expected prefix with complementary request bytes; close the gate and durably save the verified capture before granting that record.",
                "Read all 64 KiB twice after replay; compare covered bytes to stock and holes to baseline.",
                "Read the post-replay 28-byte final block twice, replace only its first DWORD with the verified original USB identity, then read it back twice.",
                "Require unchanged complete FEC0 page neighbors and U/V after finalization.",
                "Do not reset automatically on failure; incomplete replay cannot roll back by restoring the marker.",
                "Stock replay replaces settings/profile bytes; verification here does not claim preservation of their old values.",
            ],
            remaining_integration: vec![
                "Validate the composed supervised firmware job on hardware; firmware-job-plan/simulate expose its offline path.",
                "Measure target version-0034 return, full flash verification and the active revision-3 bank.",
                "Verify the observed saved-state startup changes and target configuration behavior.",
                "Resolve controller erase granularity and an explicit preservation, migration or stock-reset policy before live image replay.",
            ],
        }
    }

    pub fn simulate(&self, scenario: Scenario) -> serde_json::Value {
        simulation::run(self, scenario)
    }
}
