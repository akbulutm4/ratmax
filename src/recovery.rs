//! Replay the fixed recovery reader and compare saved settings evidence offline.
use crate::{
    access_job::{
        AccessBaseline, AccessJob, BLOCK_BYTES, CallKind, CaptureScope, Completion, JobSummary,
        Phase, SETTINGS_ADDRESSES, SETTINGS_BYTES,
    },
    access_simulation::{self, AccessScenario},
    firmware::sha256,
    preview::read_file,
    query_session::load_access_baseline,
    sensitivity_block::checksums,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SETTINGS_LEN: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    schema_version: u8,
    snapshot: PathBuf,
    information: PathBuf,
    layout: PathBuf,
    headers: PathBuf,
    original: PathBuf,
    target: PathBuf,
    passes: [PathBuf; 2],
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceMatch {
    Original,
    Target,
    Both,
    Neither,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Comparison {
    Stable {
        settings: ReferenceMatch,
        saved_state: ReferenceMatch,
    },
    Unstable,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct SettingsEvidence {
    pub marker: [u8; 4],
    pub firmware_selects_settings: bool,
    pub stored_checksums: [u16; 2],
    pub computed_checksums: [u16; 2],
    pub checksums_match: bool,
}

#[derive(Debug, Serialize)]
pub struct PassEvidence {
    pub bytes: usize,
    pub sha256: String,
    pub settings: Option<SettingsEvidence>,
}

#[derive(Debug, Serialize)]
pub struct ByteDifference {
    pub address: u32,
    pub original: u8,
    pub target: u8,
    pub observed: [Option<u8>; 2],
}

#[derive(Debug, Serialize)]
pub struct RecoveryReplay {
    pub mode: &'static str,
    pub baseline_sha256: String,
    pub original_sha256: String,
    pub target_sha256: String,
    pub job: JobSummary,
    pub comparison: Comparison,
    pub passes: [PassEvidence; 2],
    pub differences: Vec<ByteDifference>,
}

fn settings_evidence(data: &[u8]) -> Result<SettingsEvidence, String> {
    let (sum, weighted) = checksums(data)?;
    let stored = [
        u16::from_le_bytes([data[4], data[5]]),
        u16::from_le_bytes([data[6], data[7]]),
    ];
    Ok(SettingsEvidence {
        marker: data[..4].try_into().expect("validated length"),
        firmware_selects_settings: data[..2] == [0xa4; 2],
        stored_checksums: stored,
        computed_checksums: [sum, weighted],
        checksums_match: stored == [sum, weighted],
    })
}

fn compare(data: &[u8], original: &[u8], target: &[u8]) -> ReferenceMatch {
    match (data == original, data == target) {
        (true, true) => ReferenceMatch::Both,
        (true, false) => ReferenceMatch::Original,
        (false, true) => ReferenceMatch::Target,
        (false, false) => ReferenceMatch::Neither,
    }
}

pub fn replay(
    baseline: AccessBaseline,
    original: &[u8],
    target: &[u8],
    passes: [&[u8]; 2],
) -> Result<RecoveryReplay, String> {
    for (name, data) in [("original", original), ("target", target)] {
        if data.len() != SETTINGS_BYTES {
            return Err(format!(
                "{name} must contain exactly {SETTINGS_BYTES} bytes"
            ));
        }
        let settings = settings_evidence(&data[..SETTINGS_LEN])?;
        if settings.marker != [0xa4; 4] || !settings.checksums_match {
            return Err(format!(
                "{name} must have a complete settings marker and valid checksums"
            ));
        }
    }
    if passes
        .iter()
        .any(|p| p.len() > SETTINGS_BYTES || p.len() % BLOCK_BYTES != 0)
    {
        return Err("observed passes must contain up to ten complete 32-byte windows".into());
    }

    let mut job = AccessJob::with_scope(baseline, CaptureScope::SettingsRecovery)?;
    while let Some(step) = job.next_step() {
        let reply = if step.kind == CallKind::Get
            && let Phase::SettingsPage { pass, block } = step.phase
        {
            let offset = usize::from(block) * BLOCK_BYTES;
            if let Some(data) = passes[usize::from(pass)].get(offset..offset + BLOCK_BYTES) {
                let mut reply = step.frame.clone();
                reply[32..].copy_from_slice(data);
                Completion::GetComplete(reply)
            } else {
                Completion::CompletedFailure("saved replay pass ends before the next window".into())
            }
        } else {
            access_simulation::completion(&step, job.baseline(), &[], AccessScenario::Nominal)
        };
        job.begin(&step)?;
        job.finish(step.number, reply, true)?;
    }

    let result = job.summary();
    let observed = job.images();
    let comparison = if result.complete {
        Comparison::Stable {
            settings: compare(
                &observed[0][..SETTINGS_LEN],
                &original[..SETTINGS_LEN],
                &target[..SETTINGS_LEN],
            ),
            saved_state: compare(
                &observed[0][SETTINGS_LEN..],
                &original[SETTINGS_LEN..],
                &target[SETTINGS_LEN..],
            ),
        }
    } else if observed.iter().all(|pass| pass.len() == SETTINGS_BYTES) && observed[0] != observed[1]
    {
        Comparison::Unstable
    } else {
        Comparison::Incomplete
    };
    let pass_evidence = |data: &[u8]| -> Result<PassEvidence, String> {
        Ok(PassEvidence {
            bytes: data.len(),
            sha256: sha256(data),
            settings: data
                .get(..SETTINGS_LEN)
                .map(settings_evidence)
                .transpose()?,
        })
    };
    let differences = original
        .iter()
        .zip(target)
        .enumerate()
        .filter_map(|(i, (&original, &target))| {
            let observed = observed.map(|pass| pass.get(i).copied());
            (original != target || observed.iter().flatten().any(|&byte| byte != original)).then(
                || ByteDifference {
                    address: SETTINGS_ADDRESSES[i / BLOCK_BYTES] + (i % BLOCK_BYTES) as u32,
                    original,
                    target,
                    observed,
                },
            )
        })
        .collect();
    Ok(RecoveryReplay {
        mode: "offline_settings_recovery_replay",
        baseline_sha256: job.baseline().fingerprint(),
        original_sha256: sha256(original),
        target_sha256: sha256(target),
        job: result,
        comparison,
        passes: [pass_evidence(observed[0])?, pass_evidence(observed[1])?],
        differences,
    })
}

pub fn load(path: &Path) -> Result<RecoveryReplay, String> {
    let raw = read_file(path, 64 * 1024)?;
    let project: Project =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if project.schema_version != 1 {
        return Err("unsupported recovery project schema version".into());
    }
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let baseline = load_access_baseline(
        &root.join(project.snapshot),
        &root.join(project.information),
        &root.join(project.layout),
        &root.join(project.headers),
    )?;
    let read = |path: PathBuf| read_file(&root.join(path), SETTINGS_BYTES);
    let original = read(project.original)?;
    let target = read(project.target)?;
    let [first, second] = project.passes;
    replay(
        baseline,
        &original,
        &target,
        [&read(first)?, &read(second)?],
    )
}
