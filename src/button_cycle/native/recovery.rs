//! Standalone whole-page restoration, including a stopped coordinator's journal.
use super::*;

/// Only called after the lease has identified an absent coordinator and worker.
/// A partial final line cannot have authorized an operation: permissions are
/// sent only after a complete journal line has been synced.
pub(super) fn seal_stopped(source: &Source, directory: &Path, pid: u32) -> Result<(), String> {
    if pid == 0 || Path::new("/proc").join(pid.to_string()).exists() {
        return Err("previous worker is still present".into());
    }
    let journal_path = directory.join("journal.jsonl");
    let raw = crate::preview::read_file(&journal_path, 16 * 1024 * 1024)?;
    let end = raw.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    if end != raw.len() {
        save(&directory.join("journal.before-recovery.bin"), &raw)?;
        let file = OpenOptions::new()
            .write(true)
            .open(&journal_path)
            .map_err(|e| e.to_string())?;
        file.set_len(end as u64)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
    }
    let mut pending = None;
    let mut binding = source.binding.clone();
    let mut saved = BTreeMap::new();
    let mut programs = 0;
    let mut features = 0;
    let mut bound = false;
    for line in raw[..end]
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row: serde_json::Value = serde_json::from_slice(line).map_err(|e| e.to_string())?;
        let value = &row["value"];
        match row["kind"].as_str() {
            Some("button_intent") => {
                let action: Action =
                    serde_json::from_value(value["action"].clone()).map_err(|e| e.to_string())?;
                if let Action::Bind { binding: proposed } = &action {
                    binding = *proposed.clone();
                }
                source.validate_action(&action, &binding)?;
                pending = Some(action);
            }
            Some("button_grant") if value["permit"] == true => {
                match pending.as_ref().ok_or("grant without intent")? {
                    Action::Bind { .. } => bound = true,
                    Action::Feature { kind, frame, .. } => {
                        features += 1;
                        if *kind == CallKind::Set && frame[1] == 0x2f {
                            programs += 1;
                        }
                    }
                    Action::Save { name, bytes } => {
                        if crate::preview::read_file(&directory.join(name), 16384)? != *bytes {
                            return Err("durable recovery capture differs from granted save".into());
                        }
                        saved.insert(name.clone(), sha256(bytes));
                    }
                    _ => (),
                }
            }
            Some("button_completion") => pending = None,
            _ => (),
        }
    }
    let mode = if directory
        .file_name()
        .is_some_and(|s| s.to_string_lossy().starts_with("recovery-"))
    {
        "native_button_recovery"
    } else {
        "native_button_cycle"
    };
    save_json(
        &directory.join("session.json"),
        &serde_json::json!({
            "mode":mode,"native":source.native,"source_sha256":source.fingerprint,"binding":binding,
            "worker_pid":pid,"worker_reaped":true,"worker_state_agreed":false,"worker_exit_success":false,
            "result":State {uncertain:true,failure:Some("coordinator stopped before publishing its session report".into()),..State::default()},
            "saved_sha256":saved,"program_grants":programs,"feature_grants":features,"bound_granted":bound,
            "full_device_reads":0,"burst_bytes":32,"stopped_report_reconstructed":true,
            "predecessor_absence_confirmed":true,"incomplete_journal_tail_bytes":raw.len()-end
        }),
    )
}

fn previous(source: &Source, root: &Path, lock: &Path) -> Result<Vec<PathBuf>, String> {
    let inherited = root.join("prior-attempts.json");
    let mut paths: Vec<PathBuf> = if inherited.exists() {
        serde_json::from_slice(&crate::preview::read_file(&inherited, 65536)?)
            .map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };
    let mut own: Vec<_> = fs::read_dir(root)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            p.is_dir()
                && (name == "attempt-0001"
                    || (name.starts_with("recovery-")
                        && name[9..].len() == 4
                        && name[9..].bytes().all(|b| b.is_ascii_digit())))
        })
        .collect();
    own.sort();
    for directory in own {
        if !directory.join("session.json").exists() {
            let pid = crate::boot_roundtrip::lease::stopped_worker(
                lock,
                &directory,
                &source.baseline.fingerprint(),
            )?;
            seal_stopped(source, &directory, pid)?;
        }
        paths.push(fs::canonicalize(directory).map_err(|e| e.to_string())?);
    }
    let unique: BTreeSet<_> = paths.iter().collect();
    if unique.len() != paths.len() {
        return Err("duplicate restoration predecessor".into());
    }
    Ok(paths)
}

pub(crate) fn run(prior: &Path, output: &Path) -> Result<serde_json::Value, String> {
    let prior = fs::canonicalize(prior).map_err(|e| e.to_string())?;
    let original = Source::load(&prior.join("source"), true)?;
    if let Ok(raw) = crate::preview::read_file(&prior.join("cycle.json"), 1_048_576) {
        let report: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if report["original_restored"] == true && report["lease_released"] == true {
            return Err("the recorded run has already restored the original configuration".into());
        }
    }
    let lock = crate::query_session::lock_path();
    let mut paths = previous(&original, &prior, &lock)?;
    let before = crate::discovery::collect(Path::new("/sys"))?;
    let binding = crate::boot_roundtrip::normal_binding(&before, original.baseline.binding())?;
    Proof::make(&original, &paths, binding)?;
    let output = crate::access_session::create_output(output)?;
    before.save(&output.join("before"))?;
    let source_dir = output.join("source");
    fs::create_dir(&source_dir).map_err(|e| e.to_string())?;
    for name in [
        "authority.json",
        "project.json",
        "image.bin",
        "baseline.json",
        "binding.json",
    ] {
        save(
            &source_dir.join(name),
            &crate::preview::read_file(&original.directory.join(name), 1_048_576)?,
        )?;
    }
    let source = Source::load(&source_dir, true)?;
    save_json(&output.join("prior-attempts.json"), &paths)?;
    crate::boot_roundtrip::lease::acquire(&lock, &output, &source.baseline.fingerprint(), true)?;
    let mut reports = Vec::new();
    let mut restored = false;
    for number in 1..=3 {
        let binding = crate::boot_roundtrip::normal_binding(
            &crate::discovery::collect(Path::new("/sys"))?,
            source.baseline.binding(),
        )?;
        let proof = Proof::make(&source, &paths, binding.clone())?;
        let proof_path = output.join(format!("recovery-{number:04}.json"));
        save_json(&proof_path, &proof)?;
        let directory = output.join(format!("recovery-{number:04}"));
        let report = actor(
            &source,
            binding,
            Some(&proof_path),
            ActorContext {
                directory: &directory,
                root: &output,
                lock: Some(&lock),
                action_timeout: Duration::from_secs(5),
            },
            || spawn_native(&source, Some(&proof_path), &directory),
        )?;
        restored =
            report["result"]["release_allowed"] == true && report["worker_state_agreed"] == true;
        let retry = report["worker_reaped"] == true
            && (report["result"]["uncertain"] == true
                || report["saved_sha256"]["recovery-before.json"].is_string());
        reports.push(report);
        paths.push(directory);
        if restored || !retry {
            break;
        }
    }
    let after = crate::discovery::collect(Path::new("/sys"))?;
    after.save(&output.join("after"))?;
    if restored {
        let binding: Binding = serde_json::from_value(reports.last().unwrap()["binding"].clone())
            .map_err(|e| e.to_string())?;
        restored = binding.revalidate_control(&after).is_ok();
    }
    let report = serde_json::json!({"mode":"supervised_button_recovery","complete":restored,"original_restored":restored,"lease_released":restored,"attempts":reports,"full_device_reads":0,"burst_bytes":32,"resume_supported":false});
    save_json(&output.join("cycle.json"), &report)?;
    if restored {
        crate::boot_roundtrip::lease::release(&lock)?;
    }
    Ok(report)
}
