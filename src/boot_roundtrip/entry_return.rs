//! Authority for undoing boot entry after a proven zero-record operation.
use super::Reference;
use crate::{backup_restore, boot_bank, firmware::sha256, preview::read_file};
use serde::{Deserialize, Serialize};
use std::{
    io::BufRead,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    schema: u8,
    reference_sha256: String,
    backup: PathBuf,
    operation: PathBuf,
    files: std::collections::BTreeMap<PathBuf, String>,
}

#[derive(Debug)]
pub(super) struct Proof {
    pub page: Vec<u8>,
    pub uv: Vec<u8>,
    pub protected_block: Vec<u8>,
    pub fingerprint: String,
}

fn allowed(frame: &[u8], phase: &str) -> bool {
    use crate::access_job::{key_frame, read_frame};
    if frame.len() != 64 || frame[0] != 7 {
        return false;
    }
    match frame[1] {
        0 => frame[1..] == [0; 63],
        0x28 => {
            let mut expected = [0; 64];
            expected[..3].copy_from_slice(&[7, 0x28, 1]);
            // Restore attempts can only clear the entry word before records.
            frame == expected && matches!(phase, "entry-marker" | "restore-clear-marker")
        }
        0x25 => frame == key_frame(0) || frame == key_frame(0x22184952),
        2 => {
            let address = u32::from_le_bytes(frame[28..32].try_into().unwrap());
            let valid = (address < 65536
                || (boot_bank::BANK_BASE..boot_bank::BANK_BASE + 3072).contains(&address))
                && address.is_multiple_of(32);
            valid && frame[..32] == read_frame(2, address, 8)[..32]
        }
        5 | 0x1f | 0x2d => frame[2..] == [0; 62],
        0x29 => {
            frame[2..8] == [0; 6]
                && matches!(frame[8], 0xa5 | 0x5a)
                && frame[8..].iter().all(|b| *b == frame[8])
        }
        _ => false, // In particular: no 01 records, finalization or U/V writes.
    }
}

fn evidence(
    operation: &Path,
    plan: &backup_restore::Plan,
) -> Result<std::collections::BTreeMap<PathBuf, String>, String> {
    let first = operation.join("attempt-0001");
    let mut files = std::collections::BTreeMap::new();
    for pass in [0, 1] {
        let path = first.join(format!("restore-normal-before.pass{pass}.bin"));
        let data = read_file(&path, 68608)?;
        if data.len() != 68608
            || data[65536..] != *plan.embedded_boot_bank()
            || data[..65536]
                .iter()
                .zip(&plan.original)
                .enumerate()
                .any(|(i, (a, b))| i != 0xff45 && a != b)
        {
            return Err("entry return requires a complete matching normal preflight".into());
        }
        files.insert(path, sha256(&data));
    }
    let mut attempts: Vec<_> = std::fs::read_dir(operation)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("attempt-"))
        .map(|e| e.path())
        .collect();
    attempts.sort();
    if attempts.is_empty() {
        return Err("no stopped restore attempts".into());
    }
    for attempt in attempts {
        let path = attempt.join("session.json");
        let bytes = read_file(&path, 1_048_576)?;
        let report: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let pid = report["worker_pid"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= u32::MAX as u64)
            .ok_or("missing worker PID")?;
        if !matches!(
            report["mode"].as_str(),
            Some("native_backup_restore_attempt" | "native_boot_readback_attempt")
        ) || report["worker_reaped"] != true
            || report["result"]["restore"]["record_intents"] != 0
            || Path::new("/proc").join(pid.to_string()).exists()
        {
            return Err("entry return requires reaped zero-record workers".into());
        }
        files.insert(path, sha256(&bytes));
        let journal = attempt.join("journal.jsonl");
        let file = std::fs::File::open(&journal).map_err(|e| e.to_string())?;
        if file.metadata().map_err(|e| e.to_string())?.len() > 128 * 1024 * 1024 {
            return Err("oversized entry-return journal".into());
        }
        let mut digest = sha2::Sha256::new();
        use sha2::Digest;
        let mut grants = 0;
        let mut reader = std::io::BufReader::new(file);
        let mut next_number = 0;
        let mut pending = None;
        loop {
            let mut line = Vec::new();
            if reader
                .read_until(b'\n', &mut line)
                .map_err(|e| e.to_string())?
                == 0
            {
                break;
            }
            if line.len() > 16384 || line.last() != Some(&b'\n') {
                return Err("invalid entry-return journal line".into());
            }
            digest.update(&line);
            let row: serde_json::Value =
                serde_json::from_slice(&line).map_err(|e| e.to_string())?;
            if row["kind"] == "roundtrip_completion" {
                if pending.is_none()
                    || row["value"]["event"] != "completed"
                    || pending.take() != row["value"]["number"].as_u64()
                {
                    return Err("entry-return completion sequence differs".into());
                }
                continue;
            }
            if !matches!(
                row["kind"].as_str(),
                Some("roundtrip_intent" | "roundtrip_cancel")
            ) || pending.is_some()
                || row["value"]["number"].as_u64() != Some(next_number)
            {
                return Err("entry-return grant sequence differs".into());
            }
            pending = Some(next_number);
            next_number += 1;
            if row["kind"] == "roundtrip_cancel" {
                continue;
            }
            grants += 1;
            let action = &row["value"]["action"];
            if action["action"] == "connect" {
                continue;
            }
            if action["action"] != "feature" {
                return Err("unknown granted action".into());
            }
            let frame: Vec<u8> =
                serde_json::from_value(action["frame"].clone()).map_err(|e| e.to_string())?;
            if !allowed(&frame, action["phase"].as_str().unwrap_or("")) {
                return Err("a granted operation prevents marker-only return".into());
            }
        }
        if grants == 0 || grants > 50003 {
            return Err("invalid entry-return grant count".into());
        }
        files.insert(journal, crate::firmware::digest_hex(&digest.finalize()));
    }
    Ok(files)
}

pub(super) fn create(
    reference: &Reference,
    backup: &Path,
    operation: &Path,
    output: &Path,
) -> Result<Proof, String> {
    let backup = std::fs::canonicalize(backup).map_err(|e| e.to_string())?;
    let operation = std::fs::canonicalize(operation).map_err(|e| e.to_string())?;
    let plan = backup_restore::Plan::load(&backup)?;
    let files = evidence(&operation, &plan)?;
    let certificate = Certificate {
        schema: 1,
        reference_sha256: reference.baseline.fingerprint(),
        backup,
        operation,
        files,
    };
    super::executor::save_json(output, &certificate)?;
    load(reference, output)
}

pub(super) fn load(reference: &Reference, path: &Path) -> Result<Proof, String> {
    let bytes = read_file(path, 1_048_576)?;
    let certificate: Certificate = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if certificate.schema != 1 || certificate.reference_sha256 != reference.baseline.fingerprint() {
        return Err("entry-return reference differs".into());
    }
    let plan = backup_restore::Plan::load(&certificate.backup)?;
    if evidence(&certificate.operation, &plan)? != certificate.files {
        return Err("entry-return evidence changed".into());
    }
    Ok(Proof {
        page: plan.original[0xfec0..0xff00].to_vec(),
        uv: plan.original[0xffd0..0xffd8].to_vec(),
        protected_block: plan.original[0xffc0..0xffe0].to_vec(),
        fingerprint: sha256(&bytes),
    })
}
