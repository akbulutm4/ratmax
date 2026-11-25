//! Restore source and records for a user's verified 64 KiB W95 Max backup.
use crate::{
    boot_bank,
    firmware::{self, EncodedRecord},
    preview::read_file,
};
use std::path::Path;

pub const MAX_FEATURE_CALLS: u32 = 40_000;
pub const TOTAL_SECONDS: u64 = 1800;
pub const NORMAL_ENTRY_MAX_FEATURE_CALLS: u32 = 50_000;
pub const NORMAL_ENTRY_TOTAL_SECONDS: u64 = 2400;
pub const RECORDS: usize = 2042;

pub struct Plan {
    pub(crate) original: Vec<u8>,
    pub(crate) sha256: String,
    pub(crate) records: Vec<EncodedRecord>,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Plan {
    pub fn load(directory: &Path) -> Result<Self, String> {
        let report: serde_json::Value =
            serde_json::from_slice(&read_file(&directory.join("session.json"), 1_048_576)?)
                .map_err(|e| e.to_string())?;
        let expected_sha256 = report["result"]["backup"]["sha256"]
            .as_str()
            .filter(|s| is_sha256(s))
            .ok_or_else(|| "restore backup session is missing a valid SHA-256".to_string())?;
        if report["mode"] != "native_normal_firmware_backup"
            || report["result"]["complete"] != true
            || report["result"]["release_lock_allowed"] != true
            || report["result"]["gate_dirty"] != false
            || report["result"]["uncertain"] != false
            || report["worker_reaped"] != true
            || report["worker_state_agreed"] != true
            || report["result"]["backup"]["passes_equal"] != true
            || report["result"]["backup"]["bytes"] != 65536
            || report["result"]["backup"]["matches_fresh_identity_settings_and_embedded_bank"]
                != true
            || report["result"]["marker_program_intents"] != 0
            || report["result"]["reset_intents"] != 0
        {
            return Err("restore requires a completed verified original backup session".into());
        }
        let first = read_file(&directory.join("normal-image.pass0.bin"), 65536)?;
        let second = read_file(&directory.join("normal-image.pass1.bin"), 65536)?;
        if first != second {
            return Err("original backup passes differ".into());
        }
        let plan = Self::from_bytes(first)?;
        if plan.sha256 != expected_sha256 {
            return Err("original backup SHA-256 differs from its session report".into());
        }
        Ok(plan)
    }

    pub fn from_bytes(original: Vec<u8>) -> Result<Self, String> {
        if original.len() != 65536 {
            return Err("restore backup must be exactly 65,536 bytes".into());
        }
        let bank = &original
            [boot_bank::COPY_BASE as usize..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES];
        if !boot_bank::matches_known_bank(bank)
            || !boot_bank::valid_w95max_identity(&original[0xfec0..0xff20])
        {
            return Err("original backup bank or W95 Max identity is invalid".into());
        }
        let sha256 = firmware::sha256(&original);
        // Restore the complete application, including gaps, and both saved-state
        // blocks. Protected FF00-FF3F / FF80-FFFF are compared, never programmed.
        // The final FEE0 block contains the startup marker and always comes last.
        let records = (0..0xfee0)
            .step_by(32)
            .chain([0xff40, 0xff60, 0xfee0])
            .map(|address| {
                EncodedRecord::encode(
                    address as u32,
                    original[address..address + 32].try_into().expect("block"),
                )
            })
            .collect();
        Ok(Self {
            original,
            sha256,
            records,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn embedded_boot_bank(&self) -> &[u8] {
        &self.original
            [boot_bank::COPY_BASE as usize..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES]
    }

    pub fn encoded_records(&self) -> Vec<u8> {
        self.records
            .iter()
            .flat_map(|record| *record.as_bytes())
            .collect()
    }

    pub fn summary_with_entry(&self, from_normal: bool) -> serde_json::Value {
        let mut summary = self.summary();
        summary["from_normal"] = from_normal.into();
        if from_normal {
            summary["entry"]="normal identity and complete image/bank equality, then measured marker/reset boot entry".into();
            summary["max_feature_calls_per_attempt"] = NORMAL_ENTRY_MAX_FEATURE_CALLS.into();
            summary["total_seconds_per_attempt"] = NORMAL_ENTRY_TOTAL_SECONDS.into();
        }
        summary
    }

    pub fn summary(&self) -> serde_json::Value {
        let stream: Vec<u8> = self.records.iter().flat_map(|r| r.local_buffer()).collect();
        let boot_rev = u32::from_le_bytes(
            self.embedded_boot_bank()[boot_bank::BANK_BYTES - 4..]
                .try_into()
                .expect("4"),
        );
        serde_json::json!({"mode":"original_backup_restore_plan", "backup_sha256":self.sha256,
            "physical_execution_available":crate::boot_roundtrip::restore_available(),
            "records":self.records.len(),"record_stream_sha256":firmware::sha256(&stream),
            "programmed_ranges":[[0,65280],[65344,65408]],"programmed_bytes":65344,"protected_bytes":192,
            "first_record_address":0,"last_record_address":65248,"last_record_index":2041,
            "restored_boot_revision":boot_rev,
            "resume_supported":false,"retry_policy":"restart all records from the unchanged original backup",
            "entry":"fresh same-port boot binding and recognized active bank; no intact application required",
            "max_feature_calls_per_attempt":MAX_FEATURE_CALLS,"total_seconds_per_attempt":TOTAL_SECONDS,
            "limitations":["responsive compatible bootloader required", "raw NOR and code options excluded"]})
    }
}
