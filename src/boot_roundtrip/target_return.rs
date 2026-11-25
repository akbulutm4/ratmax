//! Authority and public boundary for returning a verified 0034 image to backup.
use super::{Reference, executor};
use crate::{backup_restore, boot_bank, firmware::sha256, model::Core, preview::read_file};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

pub const MAX_CALLS: u32 = 20_000;
pub const TOTAL_SECONDS: u64 = 900;

pub fn available() -> bool {
    super::PHYSICAL_TARGET_RETURN_RELEASED && super::restore_available()
}

pub fn prepare(
    reference: &Path,
    backup: &Path,
    forward: Option<&Path>,
    core: Option<Core>,
    output: &Path,
    simulate: bool,
) -> Result<serde_json::Value, String> {
    let reference = super::load(reference)?;
    let backup = backup_restore::Plan::load(backup)?;
    let output = crate::access_session::create_output(output)?;
    let generated = output.join("forward-model");
    let model_source = forward.is_none();
    let forward = if let Some(forward) = forward {
        forward
    } else {
        let core = core
            .ok_or("offline target-return plan/model requires Core or a native forward session")?;
        model_forward(&reference, &backup, core, &generated)?;
        &generated
    };
    let proof = freeze(
        &reference,
        &backup,
        forward,
        &output.join("target-authority"),
        !model_source,
    )?;
    let plan = serde_json::json!({"mode":"prepared_target_backup_return_plan","core":proof.core,"proof_sha256":proof.fingerprint,
        "physical_execution_available":false,"entry_feature_limit":MAX_CALLS,"entry_seconds":TOTAL_SECONDS,
        "restore_records":2042,"resume_supported":false,"native_forward_required_for_physical":true,
        "configuration_semantics_verified":false,"downgrade_rewrites_active_bank":true});
    executor::save_json(&output.join("target-return-plan.json"), &plan)?;
    if simulate {
        simulate_proof(&reference, &backup, &proof, &output)
    } else {
        Ok(plan)
    }
}

pub(super) fn model_forward(
    reference: &Reference,
    backup: &backup_restore::Plan,
    core: Core,
    directory: &Path,
) -> Result<(), String> {
    let plan = super::firmware_plan(
        &crate::assets::default_asset_root().ok_or("prepared assets unavailable")?,
        core,
    )?;
    std::fs::create_dir(directory).map_err(|e| e.to_string())?;
    let model = super::simulation::Model::for_firmware_backup(reference, &plan, backup);
    let (state, _) =
        super::engine::Session::new_firmware(reference, &plan, model, Some(directory)).execute();
    if !state.complete {
        return Err(format!("forward model did not complete: {state:?}"));
    }
    executor::save_json(
        &directory.join("firmware-plan.json"),
        &serde_json::json!({"baseline_sha256":reference.baseline.fingerprint(),"firmware":plan.summary()}),
    )?;
    executor::save_json(
        &directory.join("session.json"),
        &serde_json::json!({"mode":"offline_target_return_forward","result":state,
        "worker_reaped":true,"worker_state_agreed":true,"firmware":plan.summary()}),
    )
}

pub(super) fn model_report(
    directory: &Path,
    state: &super::engine::State,
    model: &super::simulation::Model,
) -> Result<serde_json::Value, String> {
    let report = serde_json::json!({"mode":"offline_target_boot_entry","result":state,"worker_reaped":true,"worker_state_agreed":true});
    executor::save_json(&directory.join("session.json"), &report)?;
    let mut journal = Vec::new();
    for (number, row) in model.records.iter().enumerate() {
        for value in [
            serde_json::json!({"kind":"roundtrip_intent","value":{"number":number,"action":row.action}}),
            serde_json::json!({"kind":"roundtrip_completion","value":{"event":"completed","number":number,"result":row.result}}),
        ] {
            serde_json::to_writer(&mut journal, &value).map_err(|e| e.to_string())?;
            journal.push(b'\n');
        }
    }
    executor::save(&directory.join("journal.jsonl"), &journal)?;
    Ok(report)
}

fn simulate_proof(
    reference: &Reference,
    backup: &backup_restore::Plan,
    proof: &Proof,
    output: &Path,
) -> Result<serde_json::Value, String> {
    let entry = output.join("entry");
    std::fs::create_dir(&entry).map_err(|e| e.to_string())?;
    let model = super::simulation::Model::for_target_proof(reference, proof);
    let (state, mut model) =
        super::engine::Session::new_target_bridge(reference, proof, None, model, Some(&entry))
            .execute();
    model_report(&entry, &state, &model)?;
    if !state.complete || !state.target_bridge.as_ref().is_some_and(|s| s.entry_ready) {
        return Err(format!("target bridge entry model failed: {state:?}"));
    }
    model.records.clear();
    let restored = output.join("backup-restore");
    std::fs::create_dir(&restored).map_err(|e| e.to_string())?;
    let (restore, model) =
        super::engine::Session::new_restore_entry(reference, backup, model, Some(&restored), false)
            .execute();
    if !restore.complete {
        return Err(format!("target bridge backup model failed: {restore:?}"));
    }
    let report = serde_json::json!({"mode":"offline_prepared_target_backup_return","core":proof.core,"complete":true,"entry":state,
        "restore":restore,"resume_supported":false,"device_calls":0,"physical_execution_available":false,"restore_actions":model.records.len()});
    executor::save_json(&output.join("target-return.json"), &report)?;
    Ok(report)
}

pub fn worker(
    reference: &Path,
    backup: &Path,
    proof: &Path,
    entry: Option<&Path>,
    boot: bool,
) -> Result<(), String> {
    if !available() {
        return Err("physical prepared-target return worker is disabled in this build".into());
    }
    let reference_data = super::load(reference)?;
    let original = backup_restore::Plan::load(backup)?;
    let target = load(&reference_data, &original, proof, true)?;
    let cleanup = entry.map(|entry| {
        (
            entry,
            if boot {
                super::Mode::Boot
            } else {
                super::Mode::Target(target.core)
            },
        )
    });
    executor::worker_target_bridge(reference, backup, proof, cleanup)
}

pub fn run(
    reference: &Path,
    backup: &Path,
    forward: &Path,
    output: &Path,
) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical prepared-target backup return is disabled in this build".into());
    }
    let reference_data = super::load(reference)?;
    let plan = backup_restore::Plan::load(backup)?;
    let output = crate::access_session::create_output(output)?;
    let authority = output.join("target-authority");
    let proof = freeze(&reference_data, &plan, forward, &authority, true)?;
    let source = output.join("original-backup");
    std::fs::create_dir(&source).map_err(|e| e.to_string())?;
    for pass in [0, 1] {
        executor::save(
            &source.join(format!("normal-image.pass{pass}.bin")),
            &plan.original,
        )?;
    }
    executor::save(
        &source.join("session.json"),
        &read_file(&backup.join("session.json"), 1_048_576)?,
    )?;
    backup_restore::Plan::load(&source)?;
    super::lease::acquire(
        &crate::query_session::lock_path(),
        &output,
        &reference_data.baseline.fingerprint(),
        true,
    )?;
    let entry_path = output.join("entry");
    let entry = executor::run_target_bridge(reference, &source, &authority, &entry_path, None)?;
    let ready = entry["worker_reaped"] == true
        && entry["worker_state_agreed"] == true
        && entry["result"]["complete"] == true
        && entry["result"]["target_bridge"]["entry_ready"] == true
        && entry["result"]["uncertain"] == false;
    let mut result = serde_json::json!({"mode":"prepared_target_backup_return","complete":false,"core":proof.core,
        "proof_sha256":proof.fingerprint,"entry":entry,"resume_supported":false,"whole_configuration_pipeline_complete":false});
    if ready {
        match executor::restore_held(reference, &source, &output) {
            Ok(restored) => {
                result["complete"] = restored["complete"].clone();
                result["restore"] = restored;
            }
            Err(error) => result["restore_error"] = error.into(),
        }
    }
    if result["complete"] != true && result["entry"]["worker_reaped"] == true {
        if result["entry"]["result"]["release_lock_allowed"] == true {
            result["entry_no_persistent_mutation"] = true.into();
        } else {
            let cleanup = (|| {
                cleanup_proof(&reference_data, &plan, &authority, &entry_path, true)?;
                let mode = if super::boot_usb::Binding::discover(
                    reference_data.baseline.binding(),
                    Path::new("/sys"),
                )?
                .is_some()
                {
                    super::Mode::Boot
                } else {
                    super::Mode::Target(proof.core)
                };
                executor::run_target_bridge(
                    reference,
                    &source,
                    &authority,
                    &output.join("entry-cleanup"),
                    Some((&entry_path, mode)),
                )
            })();
            match cleanup {
                Ok(report) => result["entry_cleanup"] = report,
                Err(error) => result["entry_cleanup_error"] = error.into(),
            }
        }
    }
    executor::save_json(&output.join("target-return.json"), &result)?;
    let cleanup = &result["entry_cleanup"];
    if result["complete"] == true
        || result["entry_no_persistent_mutation"] == true
        || (cleanup["worker_reaped"] == true
            && cleanup["worker_state_agreed"] == true
            && cleanup["result"]["complete"] == true
            && cleanup["result"]["target_bridge"]["target_returned"] == true
            && cleanup["result"]["release_lock_allowed"] == true)
    {
        super::lease::release(&crate::query_session::lock_path())?;
    }
    Ok(result)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    schema: u8,
    reference_sha256: String,
    files: BTreeMap<String, String>,
}

pub(super) struct Proof {
    pub core: Core,
    pub image: Vec<u8>,
    pub identity: Vec<u8>,
    pub status: Vec<u8>,
    pub fingerprint: String,
}

impl Proof {
    pub fn page(&self) -> &[u8] {
        &self.image[0xfec0..0xff00]
    }
    pub fn matches(&self, bytes: &[u8], cleared: bool) -> bool {
        bytes.len() == 68608
            && bytes
                .iter()
                .zip(&self.image)
                .enumerate()
                .all(|(i, (a, b))| {
                    (0xff40..0xff80).contains(&i)
                        || if cleared && (0xfefc..0xff00).contains(&i) {
                            *a == 0
                        } else {
                            a == b
                        }
                })
    }
}

const FILES: [&str; 12] = [
    "session.json",
    "firmware-plan.json",
    "firmware-before.pass0.bin",
    "firmware-before.pass1.bin",
    "firmware-replay.pass0.bin",
    "firmware-replay.pass1.bin",
    "firmware-prefix-verified.bin",
    "firmware-finalized-page.bin",
    "target-readback.pass0.bin",
    "target-readback.pass1.bin",
    "target-1f.reply.bin",
    "target-2d.reply.bin",
];

fn allowed_before_records(frame: &[u8]) -> bool {
    if frame.len() != 64 || frame[0] != 7 {
        return false;
    }
    match frame[1] {
        0 => frame[1..] == [0; 63],
        0x28 => {
            let mut expected = [0; 64];
            expected[..3].copy_from_slice(&[7, 0x28, 1]);
            frame == expected
        }
        0x25 => {
            frame == crate::access_job::key_frame(0)
                || frame == crate::access_job::key_frame(0x22184952)
        }
        2 => {
            let at = u32::from_le_bytes(frame[28..32].try_into().unwrap());
            at.is_multiple_of(32)
                && (at < 65536 || (boot_bank::BANK_BASE..boot_bank::BANK_BASE + 3072).contains(&at))
                && frame[..32] == crate::access_job::read_frame(2, at, 8)[..32]
        }
        5 | 0x1f | 0x2d => frame[2..] == [0; 62],
        0x29 => {
            frame[2..8] == [0; 6]
                && matches!(frame[8], 0xa5 | 0x5a)
                && frame[8..].iter().all(|v| *v == frame[8])
        }
        _ => false,
    }
}

fn check_restore_journal(bytes: &[u8]) -> Result<(), String> {
    let mut next = 0u64;
    let mut pending = None;
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.len() > 16384 || line.last() != Some(&b'\n') {
            return Err("invalid stopped restore journal line".into());
        }
        let row: serde_json::Value = serde_json::from_slice(line).map_err(|e| e.to_string())?;
        let n = row["value"]["number"]
            .as_u64()
            .ok_or("missing stopped restore cursor")?;
        if row["kind"] == "roundtrip_completion" {
            if pending.take() != Some(n) || row["value"]["event"] != "completed" {
                return Err("stopped restore completion differs".into());
            }
            continue;
        }
        if !matches!(
            row["kind"].as_str(),
            Some("roundtrip_intent" | "roundtrip_cancel")
        ) || pending.is_some()
            || n != next
        {
            return Err("stopped restore grant sequence differs".into());
        }
        next += 1;
        pending = Some(n);
        if row["kind"] == "roundtrip_cancel" {
            continue;
        }
        let action: super::engine::Action =
            serde_json::from_value(row["value"]["action"].clone()).map_err(|e| e.to_string())?;
        if let super::engine::Action::Feature { frame, .. } = action
            && !allowed_before_records(&frame)
        {
            return Err("a granted backup action prevents target marker-only cleanup".into());
        }
    }
    if next > 50003 {
        return Err("stopped restore grant bound exceeded".into());
    }
    Ok(())
}

fn inspect(
    reference: &Reference,
    backup: &backup_restore::Plan,
    files: &BTreeMap<String, Vec<u8>>,
    native: bool,
) -> Result<Proof, String> {
    let report: serde_json::Value =
        serde_json::from_slice(&files["session.json"]).map_err(|e| e.to_string())?;
    if report.get("offline_fixture").is_some()
        || report["mode"]
            != if native {
                "native_prepared_firmware_job"
            } else {
                "offline_target_return_forward"
            }
        || report["worker_reaped"] != true
        || report["worker_state_agreed"] != true
    {
        return Err(
            "target return requires a completed matching forward job of the correct provenance"
                .into(),
        );
    }
    if native {
        let pid = report["worker_pid"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= u32::MAX as u64)
            .ok_or("missing forward worker PID")?;
        if Path::new("/proc").join(pid.to_string()).exists() {
            return Err("forward worker remains present".into());
        }
    }
    let state = &report["result"];
    if state["complete"] != true
        || state["normal_verified"] != true
        || state["release_lock_allowed"] != true
        || state["uncertain"] != false
        || state["gate_dirty"] != false
        || state["marker_dirty"] != false
        || state["firmware"]["records_acknowledged"] != 1692
        || state["firmware"]["identity_finalized"] != true
        || state["firmware"]["prefix_verified"] != true
    {
        return Err(
            "forward job did not complete programming, finalization and checked normal return"
                .into(),
        );
    }
    let core: Core = serde_json::from_value(state["target_verification"]["core"].clone())
        .map_err(|e| e.to_string())?;
    if state["mode"]
        != serde_json::to_value(super::Mode::Target(core)).map_err(|e| e.to_string())?
        || state["target_verification"]["version"] != 0x34
        || state["firmware"]["ready_for_reset"] != true
    {
        return Err("forward target state differs from completed 0034 return".into());
    }
    let plan = super::firmware_plan(
        &crate::assets::default_asset_root().ok_or("prepared assets unavailable")?,
        core,
    )?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&files["firmware-plan.json"]).map_err(|e| e.to_string())?;
    if manifest["baseline_sha256"] != reference.baseline.fingerprint()
        || manifest["firmware"]["source_sha256"] != plan.summary().source_sha256
        || report["firmware"]["source_sha256"] != plan.summary().source_sha256
    {
        return Err("forward source or original-unit reference differs".into());
    }
    let before = &files["firmware-before.pass0.bin"];
    if before.len() != 65536 || before != &files["firmware-before.pass1.bin"] {
        return Err("forward before captures differ".into());
    }
    let mut expected = backup.original.clone();
    expected[0xfefc..0xff00].fill(0);
    expected[0xff45] = before[0xff45];
    if before != &expected {
        return Err("forward baseline does not preserve the original backed-up unit".into());
    }
    let mut prefix = before.clone();
    for record in plan.image_records().iter().take(1691) {
        let at = record.address().get() as usize;
        prefix[at..at + 32].copy_from_slice(&record.decoded_payload());
    }
    if files["firmware-prefix-verified.bin"] != prefix {
        return Err("forward pre-commit capture differs".into());
    }
    for (i, byte) in expected.iter_mut().enumerate() {
        if plan.covered[i] {
            *byte = plan.decoded[i];
        }
    }
    if files["firmware-replay.pass0.bin"] != expected
        || files["firmware-replay.pass1.bin"] != expected
    {
        return Err("forward replay differs from pinned records and preserved holes".into());
    }
    expected[0xfee0..0xfee4].copy_from_slice(&backup.original[0xfee0..0xfee4]);
    if files["firmware-finalized-page.bin"] != expected[0xfec0..0xff00] {
        return Err("forward finalized page differs".into());
    }
    let image = files["target-readback.pass0.bin"].clone();
    if image.len() != 68608
        || files["target-readback.pass1.bin"].len() != 68608
        || image
            .iter()
            .zip(&files["target-readback.pass1.bin"])
            .enumerate()
            .any(|(i, (a, b))| !(0xff40..0xff80).contains(&i) && a != b)
        || !boot_bank::matches_prepared_bank(&image[65536..])
        || image[..65536]
            .iter()
            .zip(&expected)
            .enumerate()
            .any(|(i, (a, b))| !(0xff40..0xff80).contains(&i) && a != b)
        || state["target_verification"]["returned_flash_sha256"] != sha256(&image[..65536])
        || state["target_verification"]["active_bank_sha256"] != boot_bank::PREPARED_SHA256
    {
        return Err("forward target image or active loader differs".into());
    }
    let identity = files["target-1f.reply.bin"].clone();
    let status = files["target-2d.reply.bin"].clone();
    for (query, raw) in [
        (crate::queries::NormalQuery::Identity, &identity),
        (crate::queries::NormalQuery::Status, &status),
    ] {
        validate_reply(core, query, raw)?;
    }
    Ok(Proof {
        core,
        image,
        identity,
        status,
        fingerprint: String::new(),
    })
}

pub(super) fn validate_reply(
    core: Core,
    query: crate::queries::NormalQuery,
    raw: &[u8],
) -> Result<(), String> {
    use crate::queries::{NormalReply, OfflineQueryFrame};
    let decoded = OfflineQueryFrame::new(query, 64)
        .map_err(|e| e.to_string())?
        .decode(raw)
        .map_err(|e| e.to_string())?;
    if !match decoded {
        NormalReply::Identity {
            core: actual,
            version_compare_word,
            ..
        } => actual == core && version_compare_word == 0x34,
        NormalReply::Status {
            display_version_word,
            ..
        } => display_version_word == 0x34,
    } {
        return Err("0034 target identity or version differs".into());
    }
    Ok(())
}

pub(super) fn freeze(
    reference: &Reference,
    backup: &backup_restore::Plan,
    forward: &Path,
    directory: &Path,
    native: bool,
) -> Result<Proof, String> {
    let files = FILES
        .into_iter()
        .map(|name| Ok((name.to_string(), read_file(&forward.join(name), 1_048_576)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    inspect(reference, backup, &files, native)?;
    std::fs::create_dir(directory).map_err(|e| e.to_string())?;
    for (name, data) in &files {
        executor::save(&directory.join(name), data)?;
    }
    executor::save_json(
        &directory.join("authority.json"),
        &Certificate {
            schema: 1,
            reference_sha256: reference.baseline.fingerprint(),
            files: files
                .iter()
                .map(|(name, data)| (name.clone(), sha256(data)))
                .collect(),
        },
    )?;
    load(reference, backup, directory, native)
}

pub(super) fn load(
    reference: &Reference,
    backup: &backup_restore::Plan,
    directory: &Path,
    native: bool,
) -> Result<Proof, String> {
    let raw = read_file(&directory.join("authority.json"), 65536)?;
    let cert: Certificate = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if cert.schema != 1
        || cert.reference_sha256 != reference.baseline.fingerprint()
        || cert.files.len() != FILES.len()
    {
        return Err("unsupported target-return authority".into());
    }
    let mut files = BTreeMap::new();
    for name in FILES {
        let data = read_file(&directory.join(name), 1_048_576)?;
        if cert.files.get(name) != Some(&sha256(&data)) {
            return Err("target-return frozen input changed".into());
        }
        files.insert(name.to_string(), data);
    }
    let mut proof = inspect(reference, backup, &files, native)?;
    proof.fingerprint = sha256(&raw);
    Ok(proof)
}

pub(super) fn cleanup_proof(
    reference: &Reference,
    backup: &backup_restore::Plan,
    directory: &Path,
    entry: &Path,
    native: bool,
) -> Result<Proof, String> {
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, Read};
    let mut proof = load(reference, backup, directory, native)?;
    let operation = entry.parent().ok_or("missing target entry operation")?;
    let mut restore_evidence = Vec::new();
    let mut attempts = std::fs::read_dir(operation)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter(|item| item.file_name().to_string_lossy().starts_with("attempt-"))
        .map(|item| item.path())
        .collect::<Vec<_>>();
    attempts.sort();
    if !attempts.is_empty() || operation.join("restore.json").exists() {
        let summary = read_file(&operation.join("restore.json"), 1_048_576)?;
        let aggregate: serde_json::Value =
            serde_json::from_slice(&summary).map_err(|e| e.to_string())?;
        if aggregate["attempts"].as_array().map(Vec::len) != Some(attempts.len()) {
            return Err("target cleanup restore attempt inventory differs".into());
        }
        restore_evidence.push(summary);
        for (index, attempt) in attempts.into_iter().enumerate() {
            let bytes = read_file(&attempt.join("session.json"), 1_048_576)?;
            let stopped: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if aggregate["attempts"][index] != stopped
                || stopped["mode"]
                    != if native {
                        "native_backup_restore_attempt"
                    } else {
                        "offline_backup_restore_attempt"
                    }
            {
                return Err("stopped restore report or provenance differs".into());
            }
            if stopped["worker_reaped"] != true
                || stopped["result"]["restore"]["record_intents"] != 0
            {
                return Err("a backup attempt prevents target marker-only cleanup".into());
            }
            if native {
                let pid = stopped["worker_pid"]
                    .as_u64()
                    .filter(|v| *v > 0 && *v <= u32::MAX as u64)
                    .ok_or("missing stopped restore PID")?;
                if Path::new("/proc").join(pid.to_string()).exists() {
                    return Err("restore worker remains present".into());
                }
            }
            restore_evidence.push(bytes);
            let journal = read_file(&attempt.join("journal.jsonl"), 128 * 1024 * 1024)?;
            check_restore_journal(&journal)?;
            restore_evidence.push(journal);
        }
    }
    if operation.join("backup-restore").exists() {
        return Err("unsupported nested restore evidence".into());
    }
    let raw = read_file(&entry.join("session.json"), 1_048_576)?;
    let report: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if report["mode"]
        != if native {
            "native_target_boot_entry"
        } else {
            "offline_target_boot_entry"
        }
        || report["worker_reaped"] != true
        || report["result"]["target_bridge"]["proof_sha256"] != proof.fingerprint
    {
        return Err("target cleanup requires its own stopped zero-record entry".into());
    }
    if native {
        let pid = report["worker_pid"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= u32::MAX as u64)
            .ok_or("missing entry worker PID")?;
        if Path::new("/proc").join(pid.to_string()).exists() {
            return Err("target entry worker remains present".into());
        }
    }
    let file = std::fs::File::open(entry.join("journal.jsonl")).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 64 * 1024 * 1024 {
        return Err("oversized target entry journal".into());
    }
    let mut reader = std::io::BufReader::new(file);
    let mut digest = Sha256::new();
    digest.update(proof.fingerprint.as_bytes());
    digest.update(&raw);
    for bytes in restore_evidence {
        digest.update(bytes);
    }
    let mut next = 0u64;
    let mut pending = None;
    let mut marker_grant = false;
    loop {
        let mut bytes = Vec::new();
        if reader
            .by_ref()
            .take(16385)
            .read_until(b'\n', &mut bytes)
            .map_err(|e| e.to_string())?
            == 0
        {
            break;
        }
        if bytes.len() > 16384 || bytes.last() != Some(&b'\n') {
            return Err("invalid target entry journal line".into());
        }
        digest.update(&bytes);
        let row: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let n = row["value"]["number"]
            .as_u64()
            .ok_or("missing target entry cursor")?;
        if row["kind"] == "roundtrip_completion" {
            if pending.take() != Some(n) || row["value"]["event"] != "completed" {
                return Err("target entry completion sequence differs".into());
            }
            continue;
        }
        if !matches!(
            row["kind"].as_str(),
            Some("roundtrip_intent" | "roundtrip_cancel")
        ) || pending.is_some()
            || n != next
        {
            return Err("target entry grant sequence differs".into());
        }
        next += 1;
        pending = Some(n);
        if row["kind"] == "roundtrip_cancel" {
            continue;
        }
        let action: super::engine::Action =
            serde_json::from_value(row["value"]["action"].clone()).map_err(|e| e.to_string())?;
        if let super::engine::Action::Feature { frame, .. } = action {
            if frame.len() != 64 || frame[0] != 7 {
                return Err("invalid target entry frame".into());
            }
            let allowed = allowed_before_records(&frame);
            marker_grant |= frame[1] == 0x28;
            if !allowed {
                return Err("a granted action prevents target marker-only cleanup".into());
            }
        }
    }
    if next == 0 || next > u64::from(MAX_CALLS) + 4 {
        return Err("invalid target entry grant count".into());
    }
    if marker_grant {
        for pass in [0, 1] {
            let bytes = read_file(
                &entry.join(format!("target-entry-before.pass{pass}.bin")),
                68608,
            )?;
            if !proof.matches(&bytes, false) {
                return Err("target cleanup requires complete matching preflight captures".into());
            }
            digest.update(&bytes);
        }
    }
    proof.fingerprint = crate::firmware::digest_hex(&digest.finalize());
    Ok(proof)
}
