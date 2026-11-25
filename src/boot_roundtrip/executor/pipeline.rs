use super::*;
use crate::boot_roundtrip::pipeline::{Plan, Request};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone)]
pub(super) struct Control {
    pub root: PathBuf,
    pub directory: PathBuf,
    pub full_allowed: bool,
}
impl Control {
    fn stopped(&self) -> bool {
        self.directory
            .parent()
            .unwrap_or(&self.root)
            .join("STOP")
            .exists()
            || (!self.root.join("read-budget.json").exists() && self.root.join("STOP").exists())
    }
    pub fn cancel(&self, action: &Action) -> bool {
        self.stopped()
            && matches!(action,Action::Feature {phase,kind:crate::access_job::CallKind::Set,..} if matches!(phase.as_str(),"preset-forward-records"|"preset-config-stage"|"preset-config-commit"|"preset-config-runtime"|"workflow-before-entry"))
    }
    pub fn before(&self, remote: &Remote, action: &Action) -> Result<(), Fault> {
        if matches!(action,Action::Feature{phase,kind:crate::access_job::CallKind::Set,frame,..} if phase=="preset-restore-full-prefix" && frame[28..32]==[0;4])
        {
            if !self.full_allowed {
                return Err(Fault::uncertain(
                    "full read was not admitted for this worker",
                ));
            }
            save_json(&self.root.join("full-read-used.json"),&serde_json::json!({"worker_directory":self.directory,"coordinator_pid":std::process::id(),"budget":1,"consumed_before_first_full_read_grant":true})).map_err(Fault::uncertain)?;
        }
        if let Action::Observe { phase, seconds, .. } = action {
            save_json(&self.directory.join(format!("observe-{phase}.json")),&serde_json::json!({"phase":phase,"seconds":seconds,"started_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|Fault::known(e.to_string()))?.as_millis()})).map_err(Fault::uncertain)?;
            let until = Instant::now() + Duration::from_secs(u64::from(*seconds));
            while Instant::now() < until
                && !self.stopped()
                && !self.root.join(format!("continue-{phase}")).exists()
            {
                remote.cached(action, None)?;
                std::thread::sleep(Duration::from_millis(100));
            }
            save_json(
                &self.directory.join(format!("observe-{phase}-end.json")),
                &serde_json::json!({"phase":phase,"ended":true}),
            )
            .map_err(Fault::uncertain)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    native: bool,
    budget_root: PathBuf,
    files: BTreeMap<String, String>,
    #[serde(default)]
    source_directory: Option<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    source: PathBuf,
    source_sha256: String,
    budget_root: PathBuf,
    recovery: Option<Mode>,
    full_read: bool,
}

fn asset_names(request: &Request) -> Result<Vec<String>, String> {
    let manifest = crate::assets::Manifest::embedded().map_err(|e| e.to_string())?;
    let mut names = vec![manifest.asset(request.core).source().to_string()];
    if let Some(settings) = &request.workflow
        && let Mode::Target(core) = settings.entry
    {
        names.push(manifest.asset(core).source().to_string());
    }
    names.sort();
    names.dedup();
    Ok(names)
}

pub(in crate::boot_roundtrip) fn load_source(
    directory: &Path,
    native: bool,
) -> Result<(Plan, String), String> {
    let raw = crate::preview::read_file(&directory.join("authority.json"), 65536)?;
    let authority: Authority = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if native && !authority.native {
        return Err("a model source cannot authorize physical flashing".into());
    }
    let request: Request = serde_json::from_slice(&crate::preview::read_file(
        &directory.join("project.json"),
        65536,
    )?)
    .map_err(|e| e.to_string())?;
    if request.baseline != Path::new("baseline")
        || request.backup != Path::new("backup")
        || request.assets != Path::new("assets")
    {
        return Err("frozen preset paths differ".into());
    }
    if native
        && request
            .workflow
            .as_ref()
            .is_some_and(|w| w.model_entry.is_some())
    {
        return Err("model entry state cannot authorize physical execution".into());
    }
    if request
        .workflow
        .as_ref()
        .and_then(|w| w.model_entry.as_deref())
        .is_some_and(|p| p != Path::new("model-entry"))
    {
        return Err("frozen model entry path differs".into());
    }
    if authority
        .source_directory
        .as_ref()
        .is_some_and(|p| p != directory)
    {
        return Err("frozen source directory was moved".into());
    }
    if let Some(budget) = request.workflow.as_ref().and_then(|w| w.budget.as_ref()) {
        if budget != &authority.budget_root || !directory.starts_with(budget) {
            return Err("workflow source moved outside its shared read budget".into());
        }
        let reference = super::super::load(&directory.join("baseline"))?;
        let backup_plan = crate::backup_restore::Plan::load(&directory.join("backup"))?;
        crate::workflow::validate_budget(
            budget,
            &reference.baseline.fingerprint(),
            backup_plan.sha256(),
            authority.native,
        )?;
        if crate::preview::read_file(&budget.join("read-budget.json"), 65536)?
            != crate::preview::read_file(&directory.join("read-budget.json"), 65536)?
        {
            return Err("shared read-budget authority changed".into());
        }
    } else if authority.budget_root != directory.parent().ok_or("missing original budget root")? {
        return Err("preset authority moved to another budget root".into());
    }
    let assets = asset_names(&request)?;
    let mut expected: std::collections::BTreeSet<String> = [
        "project.json",
        "baseline/session.json",
        "baseline/boot-preflight.pass0.candidate.bin",
        "baseline/boot-preflight.pass1.candidate.bin",
        "backup/session.json",
        "backup/normal-image.pass0.bin",
        "backup/normal-image.pass1.bin",
    ]
    .into_iter()
    .map(str::to_string)
    .chain(assets.into_iter().map(|asset| format!("assets/{asset}")))
    .collect();
    if request
        .workflow
        .as_ref()
        .is_some_and(|w| w.budget.is_some())
    {
        expected.insert("read-budget.json".into());
    }
    if request
        .workflow
        .as_ref()
        .is_some_and(|w| w.model_entry.is_some())
    {
        expected.insert("model-entry/cycle.json".into());
        expected.insert("model-entry/model-state.bin".into());
    }

    if authority
        .files
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err("preset authority file set differs".into());
    }
    for (name, want) in authority.files {
        if Path::new(&name).is_absolute()
            || Path::new(&name)
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("invalid preset authority path".into());
        }
        if crate::firmware::sha256(&crate::preview::read_file(
            &directory.join(name),
            1_048_576,
        )?) != want
        {
            return Err("frozen preset source changed".into());
        }
    }
    Ok((
        Plan::load(&directory.join("project.json"))?,
        crate::firmware::sha256(&raw),
    ))
}
pub(in crate::boot_roundtrip) fn freeze(
    project: &Path,
    directory: &Path,
    native: bool,
) -> Result<(Plan, String), String> {
    let plan = Plan::load(project)?;
    std::fs::create_dir(directory).map_err(|e| e.to_string())?;
    let mut files = BTreeMap::new();
    let mut put = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let path = directory.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        save(&path, bytes)?;
        files.insert(name.into(), crate::firmware::sha256(bytes));
        Ok(())
    };
    for name in [
        "session.json",
        "boot-preflight.pass0.candidate.bin",
        "boot-preflight.pass1.candidate.bin",
    ] {
        put(
            &format!("baseline/{name}"),
            &crate::preview::read_file(&plan.request.baseline.join(name), 1_048_576)?,
        )?;
    }
    for name in [
        "session.json",
        "normal-image.pass0.bin",
        "normal-image.pass1.bin",
    ] {
        put(
            &format!("backup/{name}"),
            &crate::preview::read_file(&plan.request.backup.join(name), 1_048_576)?,
        )?;
    }
    for asset in asset_names(&plan.request)? {
        put(
            &format!("assets/{asset}"),
            &crate::preview::read_file(&plan.request.assets.join(asset), 1_048_576)?,
        )?;
    }
    let budget_root = plan
        .request
        .workflow
        .as_ref()
        .and_then(|w| w.budget.clone())
        .unwrap_or(directory.parent().ok_or("missing budget root")?.into());
    if plan
        .request
        .workflow
        .as_ref()
        .is_some_and(|w| w.budget.is_some())
    {
        crate::workflow::validate_budget(
            &budget_root,
            &plan.reference.baseline.fingerprint(),
            plan.backup.sha256(),
            native,
        )?;
        if !directory.starts_with(&budget_root) {
            return Err("workflow output is outside its reviewed budget".into());
        }
        put(
            "read-budget.json",
            &crate::preview::read_file(&budget_root.join("read-budget.json"), 65536)?,
        )?;
    }
    if let Some(entry) = plan
        .request
        .workflow
        .as_ref()
        .and_then(|w| w.model_entry.as_ref())
    {
        if native {
            return Err("a model state is not a physical baseline".into());
        }
        for name in ["cycle.json", "model-state.bin"] {
            put(
                &format!("model-entry/{name}"),
                &crate::preview::read_file(&entry.join(name), 1_048_576)?,
            )?;
        }
    }
    let mut request = Request {
        baseline: "baseline".into(),
        backup: "backup".into(),
        assets: "assets".into(),
        ..plan.request.clone()
    };
    if let Some(settings) = &mut request.workflow
        && settings.model_entry.is_some()
    {
        settings.model_entry = Some("model-entry".into());
    }
    put(
        "project.json",
        &serde_json::to_vec_pretty(&request).map_err(|e| e.to_string())?,
    )?;
    save_json(
        &directory.join("authority.json"),
        &Authority {
            native,
            budget_root,
            files,
            source_directory: Some(directory.into()),
        },
    )?;
    load_source(directory, native)
}
fn current_mode(plan: &Plan) -> Result<Mode, String> {
    let report = discovery::collect(Path::new("/sys"))?;
    if super::super::boot_usb::Binding::discover(
        plan.reference.baseline.binding(),
        Path::new("/sys"),
    )?
    .is_some()
    {
        return Ok(Mode::Boot);
    }
    for mode in [Mode::Normal]
        .into_iter()
        .chain(crate::model::Core::ALL.map(Mode::Target))
    {
        if connection::select_binding(&report, plan.reference.baseline.binding(), mode)
            .ok()
            .flatten()
            .is_some()
        {
            return Ok(mode);
        }
    }
    Err("same-port original, selected target or supported boot device absent".into())
}
fn actor(
    plan: &Plan,
    source: &Path,
    source_sha: &str,
    root: &Path,
    directory: &Path,
    recovery: Option<Mode>,
) -> Result<serde_json::Value, String> {
    std::fs::create_dir(directory).map_err(|e| e.to_string())?;
    let full_read = !root.join("full-read-used.json").exists();
    let request = WorkerRequest {
        source: source.into(),
        source_sha256: source_sha.into(),
        budget_root: root.into(),
        recovery,
        full_read,
    };
    let request_path = directory.join("worker-request.json");
    save_json(&request_path, &request)?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("worker.stderr.txt"))
        .map_err(|e| e.to_string())?;
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("journal.jsonl"))
        .map_err(|e| e.to_string())?;
    let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg("__preset-cycle-worker")
        .arg(&request_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .map_err(|e| e.to_string())?;
    let pid = child.id();
    if let Err(e) = super::super::lease::worker(&query_session::lock_path(), directory, pid) {
        let _ = stop(&mut child);
        return Err(e);
    }
    let input = child.stdin.take().ok_or("preset worker stdin absent")?;
    let stdout = child.stdout.take().ok_or("preset worker stdout absent")?;
    let (send_event, events) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let event = read::<Event>(&mut reader);
            let end = event.is_err();
            if send_event.send(event).is_err() || end {
                break;
            }
        }
    });
    let remote = Remote {
        cycle: Some(Control {
            root: root.into(),
            directory: directory.into(),
            full_allowed: full_read,
        }),
        cancel_path: None,
        input: Box::new(input),
        events,
        log,
        original: plan.reference.baseline.binding().clone(),
        bound: None,
        number: 0,
        start: Instant::now(),
        total_budget: Duration::from_secs(crate::boot_roundtrip::pipeline::TOTAL_SECONDS),
        #[cfg(test)]
        offline_protocol_test: false,
    };
    let (mut state, mut remote) =
        Session::new_pipeline(plan, remote, Some(directory), recovery, full_read).execute();
    let agreed = remote.finish(&state);
    let final_binding = remote.bound.clone();
    drop(remote);
    let stopped = stop(&mut child);
    let reaped = stopped.is_ok();
    if !agreed || stopped != Ok(true) {
        state.uncertain = true;
        state.complete = false;
        state.release_lock_allowed = false;
    }
    if state.release_lock_allowed {
        let report = discovery::collect(Path::new("/sys"))?;
        if final_binding
            .as_ref()
            .is_none_or(|b| b.released(&report).is_err())
        {
            state.complete = false;
            state.release_lock_allowed = false;
            state.uncertain = true;
        }
    }
    let report = serde_json::json!({"mode":"native_preset_cycle","native":true,"source_sha256":source_sha,"result":state,"worker_pid":pid,"worker_reaped":reaped,"worker_state_agreed":agreed,"worker_exit_success":stopped==Ok(true),"full_read_admitted":full_read,"binding":final_binding,"budget_root":root});
    save_json(&directory.join("session.json"), &report)?;
    Ok(report)
}

fn seal_stopped_predecessor(
    plan: &Plan,
    source: &Path,
    source_sha: &str,
    root: &Path,
) -> Result<(), String> {
    let lock = query_session::lock_path();
    if !lock.exists() {
        return Ok(());
    }
    let worker: serde_json::Value = serde_json::from_slice(&crate::preview::read_file(
        &lock.join("worker.json"),
        65536,
    )?)
    .map_err(|e| e.to_string())?;
    let directory = PathBuf::from(
        worker["session"]
            .as_str()
            .ok_or("unknown preceding preset worker")?,
    );
    let pid = super::super::lease::stopped_worker(
        &lock,
        &directory,
        &plan.reference.baseline.fingerprint(),
    )?;
    let request: WorkerRequest = serde_json::from_slice(&crate::preview::read_file(
        &directory.join("worker-request.json"),
        65536,
    )?)
    .map_err(|e| e.to_string())?;
    if request.source != source
        || request.source_sha256 != source_sha
        || request.budget_root != root
    {
        return Err("preceding worker has a different preset authority or budget".into());
    }
    let report_path = directory.join("session.json");
    if report_path.exists() {
        let report: serde_json::Value =
            serde_json::from_slice(&crate::preview::read_file(&report_path, 1_048_576)?)
                .map_err(|e| e.to_string())?;
        if report["worker_pid"] != pid
            || report["source_sha256"] != source_sha
            || report["native"] != true
        {
            return Err("preceding preset report differs from its lease".into());
        }
        if report["worker_reaped"] == true {
            return Ok(());
        }
        std::fs::rename(
            &report_path,
            directory.join("session.before-stopped-recovery.json"),
        )
        .map_err(|e| e.to_string())?;
    }
    save_json(
        &report_path,
        &serde_json::json!({"mode":"native_preset_cycle","native":true,"source_sha256":source_sha,"budget_root":root,"worker_pid":pid,"worker_reaped":true,"worker_state_agreed":false,"stopped_report_reconstructed":true,"result":State {uncertain:true,failure:Some("recorded coordinator and worker are absent; retrying the entire original backup".into()),..State::default()}}),
    )
}

pub(in crate::boot_roundtrip) fn run(
    project: &Path,
    output: &Path,
    recover: bool,
) -> Result<serde_json::Value, String> {
    let output = crate::access_session::create_output(output)?;
    let (plan, source_sha, source, root) = if recover {
        let prior = std::fs::canonicalize(project).map_err(|e| e.to_string())?;
        let metadata = if prior.join("cycle.json").exists() {
            prior.join("cycle.json")
        } else {
            prior.join("run-intent.json")
        };
        let report: serde_json::Value =
            serde_json::from_slice(&crate::preview::read_file(&metadata, 1_048_576)?)
                .map_err(|e| e.to_string())?;
        if report["mode"] != "bounded_preset_configuration_cycle" || report["native"] != true {
            return Err("recovery requires a native preset-cycle authority".into());
        }
        if report["original_restored"] == true && report["lease_released"] == true {
            return Err("the recorded preset test has already restored its original backup".into());
        }
        let source = PathBuf::from(
            report["source"]
                .as_str()
                .ok_or("missing original preset authority")?,
        );
        let root = PathBuf::from(
            report["budget_root"]
                .as_str()
                .ok_or("missing shared preset read budget")?,
        );
        let (plan, fp) = load_source(&source, true)?;
        let expected_root = plan
            .request
            .workflow
            .as_ref()
            .and_then(|w| w.budget.clone())
            .unwrap_or(source.parent().ok_or("source parent absent")?.into());
        if root != expected_root
            || report["source_sha256"] != fp
            || !source.starts_with(&root)
            || source.file_name() != Some(std::ffi::OsStr::new("source"))
        {
            return Err("preset recovery authority or original budget root differs".into());
        }
        seal_stopped_predecessor(&plan, &source, &fp, &root)?;
        (plan, fp, source, root)
    } else {
        let source = output.join("source");
        let (plan, fp) = freeze(project, &source, true)?;
        {
            let root = plan
                .request
                .workflow
                .as_ref()
                .and_then(|w| w.budget.clone())
                .unwrap_or(output.clone());
            (plan, fp, source, root)
        }
    };
    if recover && root.join(format!("restored-{source_sha}.json")).exists() {
        return Err("the original budget session has already restored its backup".into());
    }
    save_json(&output.join("plan.json"), &plan.summary())?;
    save_json(
        &output.join("run-intent.json"),
        &serde_json::json!({"mode":"bounded_preset_configuration_cycle","native":true,"source":source,"source_sha256":source_sha,"budget_root":root,"coordinator_pid":std::process::id()}),
    )?;
    super::super::lease::acquire(
        &query_session::lock_path(),
        &output,
        &plan.reference.baseline.fingerprint(),
        recover,
    )?;
    let mut attempts = Vec::new();
    let mut restored = false;
    let mut succeeded = false;
    let mut untouched = false;
    let mut error = None;
    for index in 0..4 {
        let attempt = (|| {
            let mode = if recover || index != 0 {
                Some(current_mode(&plan)?)
            } else {
                None
            };
            actor(
                &plan,
                &source,
                &source_sha,
                &root,
                &output.join(format!("attempt-{index:04}")),
                mode,
            )
        })();
        let report = match attempt {
            Ok(report) => report,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        succeeded = report["result"]["complete"] == true
            && report["result"]["release_lock_allowed"] == true;
        restored = succeeded && report["result"]["pipeline"]["original_boot_bank_verified"] == true;
        untouched = report["worker_reaped"] == true
            && (report["result"]["feature_calls"] == 0
                || (report["result"]["marker_program_intents"] == 0
                    && report["result"]["release_lock_allowed"] == true
                    && report["result"]["pipeline"]["forward_records"] == 0
                    && report["result"]["pipeline"]["restore_records"] == 0
                    && report["result"]["pipeline"]["configuration_programs"] == 0
                    && report["result"]["pipeline"]["runtime_programs"] == 0));
        let retry = report["worker_reaped"] == true
            && report["result"]["pipeline"]["retry_allowed"] == true;
        attempts.push(report);
        if succeeded || untouched || !retry {
            break;
        }
    }
    let requested_complete = succeeded
        && (recover
            || attempts
                .first()
                .is_some_and(|r| r["result"]["complete"] == true));
    let full_prefix_verified = attempts
        .last()
        .is_some_and(|r| r["result"]["pipeline"]["full_restore_prefix_verified"] == true);
    let report = serde_json::json!({"mode":"bounded_preset_configuration_cycle","native":true,"complete":requested_complete,"original_restored":restored,"desired_configuration_kept":attempts.first().is_some_and(|r|r["result"]["pipeline"]["desired_configuration_kept"]==true),"inspected":attempts.first().is_some_and(|r|r["result"]["pipeline"]["inspected"]==true),"device_unchanged_no_test_writes":untouched,"source":source,"source_sha256":source_sha,"budget_root":root,"full_device_reads_admitted":u8::from(root.join("full-read-used.json").exists()),"latest_restore_full_prefix_verified":full_prefix_verified,"burst_bytes":32,"attempts":attempts,"error":error,"resume_supported":false,"lease_released":succeeded||untouched});
    save_json(&output.join("cycle.json"), &report)?;
    if restored {
        save_json(
            &root.join(format!("restored-{source_sha}.json")),
            &serde_json::json!({"source_sha256":source_sha,"verified_session":output,"native":true}),
        )?;
    }
    if succeeded || untouched {
        super::super::lease::release(&query_session::lock_path())?;
    }
    Ok(report)
}

pub(in crate::boot_roundtrip) fn worker(request: &Path) -> Result<(), String> {
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        let request: WorkerRequest =
            serde_json::from_slice(&crate::preview::read_file(request, 65536)?)
                .map_err(|e| e.to_string())?;
        let (plan, fp) = load_source(&request.source, true)?;
        if plan.request.workflow.is_some() {
            if !crate::workflow::available() {
                return Err("workflow worker is disabled in this build".into());
            }
        } else if !crate::boot_roundtrip::pipeline::available()
            && !(request.recovery.is_some() && crate::workflow::available())
        {
            return Err("preset worker is disabled in this build".into());
        }

        let expected_root = plan
            .request
            .workflow
            .as_ref()
            .and_then(|w| w.budget.clone())
            .unwrap_or(
                request
                    .source
                    .parent()
                    .ok_or("source parent absent")?
                    .into(),
            );
        if request.budget_root != expected_root {
            return Err("worker read budget differs from frozen authority".into());
        }
        if fp != request.source_sha256
            || (request.full_read && request.budget_root.join("full-read-used.json").exists())
        {
            return Err("preset authority or read-budget admission changed".into());
        }
        let native = Native {
            original: plan.reference.baseline.binding().clone(),
            bound: None,
            transport: None,
            reset_sent: false,
        };
        let guarded = Guarded {
            inner: native,
            input: BufReader::new(std::io::stdin().lock()),
            output: std::io::stdout().lock(),
            number: 0,
        };
        let (state, mut guarded) =
            Session::new_pipeline(&plan, guarded, None, request.recovery, request.full_read)
                .execute();
        guarded.finish(&state)
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        let _ = request;
        Err("preset worker backend unavailable".into())
    }
}

pub(in crate::boot_roundtrip) fn model_workflow(
    project: &Path,
    output: &Path,
    recover: bool,
) -> Result<serde_json::Value, String> {
    let output = crate::access_session::create_output(output)?;
    let (plan, source, fp, root) = if recover {
        let report: serde_json::Value = serde_json::from_slice(&crate::preview::read_file(
            &project.join("cycle.json"),
            1_048_576,
        )?)
        .map_err(|e| e.to_string())?;
        if report["native"] != false || report["original_restored"] == true {
            return Err("model restoration requires an unrestored model workflow job".into());
        }
        let source = PathBuf::from(report["source"].as_str().ok_or("model source absent")?);
        let root = PathBuf::from(
            report["budget_root"]
                .as_str()
                .ok_or("model budget absent")?,
        );
        let (plan, fp) = load_source(&source, false)?;
        let expected_root = plan
            .request
            .workflow
            .as_ref()
            .and_then(|w| w.budget.clone())
            .unwrap_or(source.parent().ok_or("source parent absent")?.into());
        if root != expected_root || !source.starts_with(&root) || report["source_sha256"] != fp {
            return Err("model source or read budget differs".into());
        }
        (plan, source, fp, root)
    } else {
        let source = output.join("source");
        let (plan, fp) = freeze(project, &source, false)?;
        {
            let root = plan
                .request
                .workflow
                .as_ref()
                .and_then(|w| w.budget.clone())
                .unwrap_or(output.clone());
            (plan, source, fp, root)
        }
    };
    if recover && root.join(format!("restored-{fp}.json")).exists() {
        return Err("model original backup is already restored".into());
    }
    if plan.request.workflow.is_none() {
        return Err("workflow settings missing".into());
    }
    save_json(&output.join("plan.json"), &plan.summary())?;
    let model = super::super::simulation::run_workflow_model(&plan, &output, recover, &root)?;
    let state = &model["result"];
    let report = serde_json::json!({"mode":"bounded_preset_configuration_cycle","native":false,"device_operations":0,"complete":state["complete"],"result":state,"desired_configuration_kept":state["pipeline"]["desired_configuration_kept"],"inspected":state["pipeline"]["inspected"],"original_restored":state["pipeline"]["original_boot_bank_verified"],"lease_released":state["release_lock_allowed"],"source":source,"source_sha256":fp,"budget_root":root,"full_device_reads_admitted":u8::from(root.join("full-read-used.json").exists()),"model_final_application_equals_original":model["model_final_application_equals_original"],"model_final_bank_equals_original":model["model_final_bank_equals_original"],"model_state_sha256":model["model_state_sha256"],"model_runtime":model["model_runtime"],"burst_bytes":32});
    save_json(&output.join("cycle.json"), &report)?;
    if report["original_restored"] == true {
        save_json(
            &root.join(format!("restored-{fp}.json")),
            &serde_json::json!({"source_sha256":fp,"native":false,"verified_session":output}),
        )?;
    }
    Ok(report)
}
