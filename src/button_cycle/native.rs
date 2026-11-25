use super::*;
use crate::query_session::Binding;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
mod ipc;
pub(super) mod recovery;
mod source;
#[cfg(all(target_os = "linux", feature = "linux-query"))]
use ipc::{Driver, Guarded};
use ipc::{Action, Remote};
use source::{Proof, Source};
const MAX_ACTIONS: u32 = MAX_CALLS + 64;

fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("missing button output parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn save_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    save(
        path,
        &serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
}
pub(super) fn validate_captured(reference: &Windows, captured: &Windows) -> Result<(), String> {
    if reference.keys().collect::<Vec<_>>() != captured.keys().collect::<Vec<_>>() {
        return Err("button original sparse extents differ".into());
    }
    for (&at, want) in reference {
        let got = &captured[&at];
        if got.len() != 32 {
            return Err("button original window length differs".into());
        }
        for (i, (&a, &b)) in got.iter().zip(want).enumerate() {
            if at == 0xff40 && i == 5 && a <= 6 {
                continue;
            }
            if a != b {
                return Err("button original sparse bytes differ from pinned backup".into());
            }
        }
    }
    Ok(())
}

fn stop(child: &mut Child) -> Result<bool, String> {
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(status.success());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().map_err(|e| e.to_string())?;
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("button worker stop remains unproven".into())
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
struct Native {
    binding: Option<Binding>,
    transport: Option<Box<dyn crate::transport::LocalFeatureTransport>>,
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl Native {
    fn cached(&self) -> Result<(), String> {
        self.binding
            .as_ref()
            .ok_or("button worker has no bound handle")?
            .revalidate_control(&crate::discovery::collect(Path::new("/sys"))?)
    }
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl Driver for Native {
    fn bind(&mut self, binding: &Binding) -> Result<(), String> {
        if self.transport.is_some() {
            return Err("button worker cannot reopen a handle".into());
        }
        self.transport = Some(Box::new(crate::query_session::open_transition_transport(
            binding,
        )?));
        self.binding = Some(binding.clone());
        self.cached()
    }
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl Link for Native {
    fn validate(&mut self) -> Result<(), String> {
        self.cached()
    }
    fn call(&mut self, _phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion {
        if let Err(e) = self.cached() {
            return Completion::Uncertain(e);
        }
        let Some(device) = self.transport.as_mut() else {
            return Completion::Uncertain("button handle closed".into());
        };
        match kind {
            CallKind::Set => device
                .set_local(frame)
                .map(|()| Completion::SetComplete)
                .unwrap_or_else(|e| Completion::Uncertain(e.to_string())),
            CallKind::Get => device
                .get_local(7, 64)
                .map(Completion::GetComplete)
                .unwrap_or_else(|e| Completion::Uncertain(e.to_string())),
        }
    }
    fn save(&mut self, _name: &str, _bytes: &[u8]) -> Result<(), String> {
        Err("worker persistence must be mediated by coordinator".into())
    }
    fn settle(&mut self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(500));
        self.cached()
    }
}

fn execute_remote<'a>(
    source: &'a Source,
    proof: Option<&Proof>,
    remote: Remote<'a>,
) -> (State, Remote<'a>) {
    let session = Session::new(
        &source.plan,
        &source.baseline,
        source.original.clone(),
        source.target.clone(),
        remote,
    );
    if source.read_only {
        session.inspect()
    } else if let Some(proof) = proof {
        session.recover(proof.captured.clone(), proof.possible_program)
    } else {
        session.execute()
    }
}

type Spawned = (Child, Box<dyn Write + Send>, Box<dyn BufRead + Send>);

struct ActorContext<'a> {
    directory: &'a Path,
    root: &'a Path,
    lock: Option<&'a Path>,
    action_timeout: Duration,
}

fn actor(
    source: &Source,
    binding: Binding,
    proof: Option<&Path>,
    context: ActorContext<'_>,
    mut spawn: impl FnMut() -> Result<Spawned, String>,
) -> Result<serde_json::Value, String> {
    let ActorContext {
        directory,
        root,
        lock,
        action_timeout,
    } = context;
    fs::create_dir(directory).map_err(|e| e.to_string())?;
    let recovery = proof
        .map(|p| Proof::load(source, p, source.native))
        .transpose()?;
    let expected = recovery
        .as_ref()
        .map(|p| &p.binding)
        .unwrap_or(&source.binding);
    if &binding != expected {
        return Err("button actor binding differs from frozen authority".into());
    }
    let proof_sha256 = proof
        .map(|p| crate::preview::read_file(p, 65536).map(|b| sha256(&b)))
        .transpose()?;
    let (mut child, input, reader) = spawn()?;
    let pid = child.id();
    let result = (|| {
        if let Some(lock) = lock {
            crate::boot_roundtrip::lease::worker(lock, directory, pid)?;
        }
        let mut remote = Remote::new(
            source,
            binding.clone(),
            proof_sha256.clone(),
            input,
            reader,
            directory,
            proof.is_none().then(|| root.join("STOP")),
        )?;
        remote.action_timeout = action_timeout;
        let bind = remote.bind();
        let (mut state, mut remote) = if let Err(e) = bind {
            (
                State {
                    uncertain: true,
                    failure: Some(e),
                    ..State::default()
                },
                remote,
            )
        } else {
            execute_remote(source, recovery.as_ref(), remote)
        };
        let agreed = remote.finish(&state);
        let saved = remote.saved.clone();
        let programs = remote.program_grants;
        let features = remote.feature_grants;
        let bound = remote.bound_granted;
        if !agreed {
            state.uncertain = true;
            state.complete = false;
            state.release_allowed = false;
        }
        drop(remote);
        Ok::<_, String>((state, agreed, saved, programs, features, bound))
    })();
    let stopped = stop(&mut child);
    let reaped = stopped.is_ok();
    let (mut state, agreed, saved, programs, features, bound) = match result {
        Ok(v) => v,
        Err(e) => (
            State {
                uncertain: true,
                failure: Some(e),
                ..State::default()
            },
            false,
            BTreeMap::new(),
            0,
            0,
            false,
        ),
    };
    if !reaped || stopped != Ok(true) {
        state.complete = false;
        state.release_allowed = false;
        state.uncertain = true;
    }
    let mut report = serde_json::json!({"mode":if proof.is_some(){"native_button_recovery"}else{"native_button_cycle"},"native":source.native,"source_sha256":source.fingerprint,
        "binding":binding,"proof_sha256":proof_sha256,"result":state,"worker_pid":pid,"worker_reaped":reaped,
        "worker_exit_success":stopped==Ok(true),"worker_state_agreed":agreed,"saved_sha256":saved,
        "program_grants":programs,"feature_grants":features,"bound_granted":bound,"full_device_reads":0,"burst_bytes":32});
    if reaped && features == 0 {
        report["device_features_untouched"] = true.into();
    }
    save_json(&directory.join("session.json"), &report)?;
    Ok(report)
}

fn spawn_native(
    source: &Source,
    proof: Option<&Path>,
    directory: &Path,
) -> Result<Spawned, String> {
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("worker.stderr.txt"))
        .map_err(|e| e.to_string())?;
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command.arg("__button-cycle-worker").arg(&source.directory);
    if let Some(proof) = proof {
        command.arg(proof);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .map_err(|e| e.to_string())?;
    let input = child.stdin.take();
    let output = child.stdout.take();
    match (input, output) {
        (Some(input), Some(output)) => {
            Ok((child, Box::new(input), Box::new(BufReader::new(output))))
        }
        _ => {
            let _ = stop(&mut child);
            Err("button worker pipes absent".into())
        }
    }
}

pub(super) fn run(
    project: &Path,
    baseline: &Path,
    output: &Path,
    seconds: u16,
    read_only: bool,
) -> Result<serde_json::Value, String> {
    let reference = crate::boot_roundtrip::load(baseline)?;
    let before = crate::discovery::collect(Path::new("/sys"))?;
    let binding = crate::boot_roundtrip::normal_binding(&before, reference.baseline.binding())?;
    let output = crate::access_session::create_output(output)?;
    before.save(&output.join("before"))?;
    let source = Source::freeze_options(
        project,
        &reference.baseline,
        &binding,
        &output.join("source"),
        true,
        seconds,
        read_only,
    )?;
    let lock = crate::query_session::lock_path();
    crate::boot_roundtrip::lease::acquire(&lock, &output, &source.baseline.fingerprint(), false)?;
    let first = output.join("attempt-0001");
    let initial = actor(
        &source,
        binding,
        None,
        ActorContext {
            directory: &first,
            root: &output,
            lock: Some(&lock),
            action_timeout: Duration::from_secs(5),
        },
        || spawn_native(&source, None, &first),
    )?;
    let mut reports = vec![initial];
    let mut paths = vec![first];
    let mut released = reports[0]["result"]["release_allowed"] == true
        || reports[0]["device_features_untouched"] == true;
    let mut recovery_error = None;
    for number in 1..=3 {
        if released || reports.last().unwrap()["worker_reaped"] != true {
            break;
        }
        let recover = (|| {
            let current = crate::boot_roundtrip::normal_binding(
                &crate::discovery::collect(Path::new("/sys"))?,
                source.baseline.binding(),
            )?;
            let proof = Proof::make(&source, &paths, current.clone())?;
            let proof_path = output.join(format!("recovery-{number:04}.json"));
            save_json(&proof_path, &proof)?;
            let directory = output.join(format!("recovery-{number:04}"));
            let report = actor(
                &source,
                current,
                Some(&proof_path),
                ActorContext {
                    directory: &directory,
                    root: &output,
                    lock: Some(&lock),
                    action_timeout: Duration::from_secs(5),
                },
                || spawn_native(&source, Some(&proof_path), &directory),
            )?;
            released = report["result"]["release_allowed"] == true;
            let retry = report["result"]["uncertain"] == true
                || report["saved_sha256"]["recovery-before.json"].is_string();
            reports.push(report);
            paths.push(directory);
            Ok::<_, String>(retry)
        })();
        match recover {
            Ok(true) => (),
            Ok(false) => break,
            Err(e) => {
                recovery_error = Some(e);
                break;
            }
        }
    }
    let after = crate::discovery::collect(Path::new("/sys"))?;
    after.save(&output.join("after"))?;
    if released {
        let final_binding: Binding =
            serde_json::from_value(reports.last().unwrap()["binding"].clone())
                .map_err(|e| e.to_string())?;
        if final_binding.revalidate_control(&after).is_err() {
            released = false;
        }
    }
    let complete =
        reports[0]["result"]["complete"] == true && reports[0]["worker_state_agreed"] == true;
    let original_restored = released
        && reports.last().unwrap()["worker_state_agreed"] == true
        && reports.last().unwrap()["result"]["original_restored"] == true;
    let report = serde_json::json!({"mode":"supervised_button_cycle","complete":complete && released,"original_restored":original_restored,
        "attempts":reports,"recovery_error":recovery_error,"full_device_reads":0,"burst_bytes":32,
        "resume_supported":false,"lease_released":released,"configuration_behavior_physically_qualified":false,"read_only":source.read_only,"observation_seconds":source.observation_seconds});
    save_json(&output.join("cycle.json"), &report)?;
    if released {
        crate::boot_roundtrip::lease::release(&lock)?;
    }
    Ok(report)
}

pub(super) fn worker(source: &Path, proof: Option<&Path>) -> Result<(), String> {
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        let source = Source::load(source, true)?;
        let recovery = proof.map(|p| Proof::load(&source, p, true)).transpose()?;
        let binding = recovery
            .as_ref()
            .map(|p| p.binding.clone())
            .unwrap_or_else(|| source.binding.clone());
        let proof_sha256 = proof
            .map(|p| crate::preview::read_file(p, 65536).map(|v| sha256(&v)))
            .transpose()?;
        let mut guarded = Guarded {
            driver: Native {
                binding: None,
                transport: None,
            },
            input: BufReader::new(std::io::stdin().lock()),
            output: std::io::stdout().lock(),
            source: &source,
            binding,
            proof_sha256,
            number: 0,
        };
        guarded.bind()?;
        let session = Session::new(
            &source.plan,
            &source.baseline,
            source.original.clone(),
            source.target.clone(),
            guarded,
        );
        let (state, mut guarded) = if source.read_only {
            session.inspect()
        } else if let Some(proof) = recovery {
            session.recover(proof.captured, proof.possible_program)
        } else {
            session.execute()
        };
        guarded.finish(&state)
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        let _ = (source, proof);
        Err("native button backend unavailable".into())
    }
}
