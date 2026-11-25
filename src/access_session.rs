//! Separate temporary-access executor. Type-checked, but BOTH native entry points
//! refuse before input/output/device access until a later reviewed source change.
use crate::{
    access_job::*,
    access_simulation::{self, AccessScenario},
    firmware, query_session,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const PHYSICAL_ACCESS_RELEASED: bool = false;
const PHYSICAL_SETTINGS_READBACK_RELEASED: bool = false;
const PHYSICAL_SETTINGS_RECOVERY_RELEASED: bool = false;
const PHYSICAL_BOOT_BANK_RELEASED: bool = false;
const fn scope_available(scope: CaptureScope) -> bool {
    let released = match scope {
        CaptureScope::Firmware => PHYSICAL_ACCESS_RELEASED,
        CaptureScope::SettingsPages => PHYSICAL_SETTINGS_READBACK_RELEASED,
        CaptureScope::SettingsRecovery => PHYSICAL_SETTINGS_RECOVERY_RELEASED,
        CaptureScope::BootBank => PHYSICAL_BOOT_BANK_RELEASED,
    };
    released && query_session::live_available()
}
pub const fn physical_execution_available() -> bool {
    scope_available(CaptureScope::Firmware)
        || scope_available(CaptureScope::SettingsPages)
        || scope_available(CaptureScope::SettingsRecovery)
        || scope_available(CaptureScope::BootBank)
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum WorkerCommand {
    Open {
        baseline: Box<AccessBaseline>,
        scope: CaptureScope,
    },
    Advance {
        number: u32,
        elapsed_ms: u64,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerEvent {
    Ready {
        baseline_sha256: String,
        scope: CaptureScope,
    },
    Step {
        step: Step,
        result: Completion,
        binding_matches: bool,
        call_performed: bool,
        summary: JobSummary,
    },
}
fn send(w: &mut impl Write, v: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *w, v).map_err(|e| e.to_string())?;
    w.write_all(b"\n")
        .and_then(|_| w.flush())
        .map_err(|e| e.to_string())
}
fn line(r: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut b = vec![];
    r.take(16385)
        .read_until(b'\n', &mut b)
        .map_err(|e| e.to_string())?;
    if b.len() > 16384 || b.last() != Some(&b'\n') {
        return Err("access IPC ended/overlong/unterminated".into());
    }
    Ok(b)
}
fn fresh(b: &AccessBaseline) -> Result<(), String> {
    b.binding()
        .revalidate(&crate::discovery::collect(Path::new("/sys"))?)
}

pub fn worker_main() -> Result<(), String> {
    if !physical_execution_available() {
        return Err(
            "physical access-key execution is disabled pending review; no device accessed".into(),
        );
    }
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        use crate::transport::LocalFeatureTransport;
        let mut input = BufReader::new(std::io::stdin().lock());
        let mut output = std::io::stdout().lock();
        let WorkerCommand::Open { baseline, scope } =
            serde_json::from_slice(&line(&mut input)?).map_err(|e| e.to_string())?
        else {
            return Err("access worker needs Open".into());
        };
        if !scope_available(scope) {
            return Err("requested access scope is disabled pending review".into());
        }
        let mut job = AccessJob::with_scope(*baseline, scope)?;
        let mut transport = query_session::open_access_transport(job.baseline().binding())?;
        send(
            &mut output,
            &WorkerEvent::Ready {
                baseline_sha256: job.baseline().fingerprint(),
                scope,
            },
        )?;
        while !job.summary().terminal {
            let WorkerCommand::Advance { number, elapsed_ms } =
                serde_json::from_slice(&line(&mut input)?).map_err(|e| e.to_string())?
            else {
                return Err("access worker cannot reopen".into());
            };
            job.tick(elapsed_ms);
            let step = job.next_step().ok_or("access worker has no step")?;
            if number != step.number {
                return Err("access worker cursor mismatch".into());
            }
            let before = fresh(job.baseline());
            job.begin(&step)?;
            let performed = before.is_ok();
            let result = match before {
                Err(e) => Completion::Uncertain(format!("pre-call binding failed: {e}")),
                Ok(()) => match step.kind {
                    CallKind::Set => match transport.set_local(&step.frame) {
                        Ok(()) => Completion::SetComplete,
                        Err(e) => Completion::CompletedFailure(e.to_string()),
                    },
                    CallKind::Get => match transport.get_local(7, 64) {
                        Ok(raw) => Completion::GetComplete(raw),
                        Err(e) => Completion::CompletedFailure(e.to_string()),
                    },
                },
            };
            let binding_matches = performed && fresh(job.baseline()).is_ok();
            job.finish(number, result.clone(), binding_matches)?;
            send(
                &mut output,
                &WorkerEvent::Step {
                    step,
                    result,
                    binding_matches,
                    call_performed: performed,
                    summary: job.summary(),
                },
            )?;
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    Err("native access backend unavailable".into())
}

/// Native run is refused before baselines, output creation, lock or node open.
pub fn run(
    snapshot: &Path,
    info: &Path,
    layout: &Path,
    headers: &Path,
    output: &Path,
    scope: CaptureScope,
) -> Result<serde_json::Value, String> {
    if !scope_available(scope) {
        return Err(
            "physical access-key execution is disabled pending review; no device accessed".into(),
        );
    }
    let (mode, prefix, session_limits) = match scope {
        CaptureScope::Firmware => ("native_temporary_access_job", "internal-flash", limits()),
        CaptureScope::SettingsPages => (
            "native_seeded_settings_readback",
            "settings-pages",
            vec![
                "Packed passes contain E000–E0FF followed by FF40–FF7F.",
                "Closure verifies the observed 02 header behavior and matching normal replies.",
                "A verified capture provides baseline bytes. Partial-page programming and restoration require separate evidence.",
            ],
        ),
        CaptureScope::SettingsRecovery => (
            "native_settings_recovery_readback",
            "recovery-pages",
            vec![
                "Packed passes contain E000–E0FF followed by FF40–FF7F.",
                "Closure uses the FEC0 metadata witness and matching normal replies.",
                "Agreement establishes captured bytes. Compare the marker, checksums and reference bytes separately.",
            ],
        ),
        CaptureScope::BootBank => (
            "native_boot_bank_preflight",
            "boot-preflight",
            vec![
                "Two seeded passes cover the fixed boot bank, embedded-copy gaps, identity blocks and settings pages.",
                "The normal RAM gate is closed using the measured FEC0 witness and matching normal replies.",
                "Persistent writes, reset and boot entry are outside this readback scope.",
            ],
        ),
    };
    let baseline = query_session::load_access_baseline(snapshot, info, layout, headers)?;
    let mut job = AccessJob::with_scope(baseline, scope)?;
    let out = create_output(output)?;
    let mut log = new_file(&out.join("journal.jsonl"))?;
    query_session::acquire_lock(&query_session::lock_path())?;
    let mut worker_stop: Option<WorkerStop> = None;
    let result = (|| -> Result<(), String> {
        crate::discovery::collect(Path::new("/sys"))?.save(&out.join("before"))?;
        fresh(job.baseline())?;
        let stderr = new_file(&out.join("worker.stderr.txt"))?;
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("__access-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|e| e.to_string())?;
        worker_stop = Some(supervise(
            &mut child,
            &mut job,
            &mut log,
            Duration::from_secs(5),
            fresh,
        )?);
        crate::discovery::collect(Path::new("/sys"))?.save(&out.join("after"))?;
        fresh(job.baseline())?;
        Ok(())
    })();
    if let Err(e) = result {
        job.mark_uncertain(e);
    }
    persist_images(&out, &job, prefix)?;
    let report = serde_json::json!({
        "mode": mode,
        "scope": scope,
        "baseline": job.baseline(),
        "result": job.summary(),
        "worker_stop": worker_stop,
        "limits": session_limits,
        "boot_preflight": (scope == CaptureScope::BootBank).then(|| serde_json::json!({
            "bank_base": crate::boot_bank::BANK_BASE,
            "bank_bytes": crate::boot_bank::BANK_BYTES,
            "copy_base": crate::boot_bank::COPY_BASE,
            "copy_gaps": crate::boot_bank::GAPS,
            "fixed_identity_addresses": crate::boot_bank::FIXED_IDENTITY,
            "settings_addresses": SETTINGS_ADDRESSES,
            "blocks_per_pass": crate::boot_bank::BLOCKS,
            "packed_pass_bytes": crate::boot_bank::PASS_BYTES,
            "comparison": crate::boot_bank::compare(job.images()[0]),
        })),
    });
    save_json(&out.join("session.json"), &report)?;
    if job.summary().release_lock_allowed {
        fs::remove_dir_all(query_session::lock_path()).map_err(|e| e.to_string())?;
    }
    Ok(report)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WorkerStop {
    pid: u32,
    reaped: bool,
    exit_success: Option<bool>,
    kill_requested: bool,
}
fn stop_child(child: &mut Child, job: &mut AccessJob) -> WorkerStop {
    let mut stop = WorkerStop {
        pid: child.id(),
        reaped: false,
        exit_success: None,
        kill_requested: false,
    };
    for round in 0..2 {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(s)) => {
                    stop.reaped = true;
                    stop.exit_success = Some(s.success());
                    if !s.success() {
                        job.mark_uncertain("access worker exited unsuccessfully");
                    }
                    return stop;
                }
                Ok(None) => (),
                Err(e) => {
                    job.mark_uncertain(e.to_string());
                    return stop;
                }
            }
            if Instant::now() >= until {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        job.mark_uncertain("access worker stop/cancellation is unproven");
        if round == 0 {
            stop.kill_requested = true;
            let _ = child.kill();
        }
    }
    stop
}
fn supervise(
    child: &mut Child,
    job: &mut AccessJob,
    log: &mut File,
    deadline: Duration,
    mut binding_check: impl FnMut(&AccessBaseline) -> Result<(), String>,
) -> Result<WorkerStop, String> {
    let mut input = child.stdin.take().ok_or("missing access stdin")?;
    let stdout = child.stdout.take().ok_or("missing access stdout")?;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        loop {
            let v = line(&mut r)
                .and_then(|b| serde_json::from_slice::<WorkerEvent>(&b).map_err(|e| e.to_string()));
            let stop = v.is_err();
            if tx.send(v).is_err() || stop {
                break;
            }
        }
    });
    let start = Instant::now();
    let result = (|| -> Result<(), String> {
        let open = WorkerCommand::Open {
            baseline: Box::new(job.baseline().clone()),
            scope: job.scope(),
        };
        query_session::journal(log, "access_open", &open)?;
        send(&mut input, &open)?;
        let ready = rx.recv_timeout(deadline).map_err(|e| e.to_string())??;
        query_session::journal(log, "access_worker_event", &ready)?;
        if !matches!(ready, WorkerEvent::Ready { baseline_sha256, scope }
            if baseline_sha256 == job.baseline().fingerprint() && scope == job.scope())
        {
            return Err("access worker ready mismatch".into());
        }
        while !job.summary().terminal {
            let elapsed_ms =
                u64::try_from(start.elapsed().as_millis()).map_err(|e| e.to_string())?;
            job.tick(elapsed_ms);
            let Some(step) = job.next_step() else {
                break;
            };
            binding_check(job.baseline())?;
            // Durable intent precedes the pessimistic enable mark and IPC grant.
            query_session::journal(log, "access_step_intent", &step)?;
            job.begin(&step)?;
            send(
                &mut input,
                &WorkerCommand::Advance {
                    number: step.number,
                    elapsed_ms,
                },
            )?;
            let event = rx
                .recv_timeout(deadline)
                .map_err(|e| format!("access call/IPC uncertain: {e}"))??;
            query_session::journal(log, "access_worker_event", &event)?;
            let WorkerEvent::Step {
                step: observed,
                result,
                binding_matches,
                call_performed,
                summary,
            } = event
            else {
                return Err("unexpected access worker ready".into());
            };
            if observed != step
                || (!call_performed
                    && (binding_matches || !matches!(result, Completion::Uncertain(_))))
            {
                return Err("forged access step or call status".into());
            }
            job.finish(step.number, result, binding_matches)?;
            if job.summary() != summary {
                return Err("access worker/coordinator verdict mismatch".into());
            }
        }
        Ok(())
    })();
    if let Err(e) = &result {
        job.mark_uncertain(e.clone());
    }
    drop(input);
    let stop = stop_child(child, job);
    Ok(stop)
}
pub(crate) fn create_output(path: &Path) -> Result<std::path::PathBuf, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if ["/dev", "/sys", "/proc"]
        .iter()
        .any(|p| parent.starts_with(p))
    {
        return Err("access output must be a host directory".into());
    }
    let out = parent.join(path.file_name().ok_or("output directory required")?);
    fs::create_dir(&out).map_err(|e| format!("access output must be new: {e}"))?;
    Ok(out)
}
fn new_file(p: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .map_err(|e| e.to_string())
}
fn save_json(p: &Path, v: &impl Serialize) -> Result<(), String> {
    let mut f = new_file(p)?;
    serde_json::to_writer_pretty(&mut f, v).map_err(|e| e.to_string())?;
    f.write_all(b"\n")
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
fn persist_images(out: &Path, job: &AccessJob, prefix: &str) -> Result<(), String> {
    for (pass, data) in job.images().into_iter().enumerate() {
        if !data.is_empty() {
            let mut f = new_file(&out.join(format!("{prefix}.pass{pass}.candidate.bin")))?;
            f.write_all(data)
                .and_then(|_| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
fn limits() -> Vec<&'static str> {
    vec![
        "Candidate 64 KiB mapped internal flash only; actual installed chip/geometry and code options/boot ROM/external NOR coverage are unproven.",
        "Two matching reads and settings checksums do not prove restoration, authenticity, or a complete profile/NOR backup.",
        "Closure verifies the observed 02 header behavior and matching normal replies. The prior key value and error latch remain unknown.",
        "Completed read failures require one cleanup attempt; uncertain calls or changed binding prohibit blind cleanup/reset/retry.",
        "The installed 0028 header exchange has been observed. The metadata probe and full mapped flash reads still require physical verification.",
    ]
}
pub fn prepare(
    baseline: AccessBaseline,
    output: &Path,
    scenario: Option<AccessScenario>,
) -> Result<serde_json::Value, String> {
    baseline.validate()?;
    let out = create_output(output)?;
    let plan = serde_json::json!({
        "mode": "offline_temporary_access_plan",
        "physical_execution_available": false,
        "baseline_sha256": baseline.fingerprint(),
        "baseline": baseline,
        "closure_probe": {"address": 0xE000, "count_words": 2},
        "metadata_probe": {"address": 0xFEC0, "count_words": 8},
        "internal_flash_start": 0,
        "internal_flash_bytes": IMAGE_BYTES,
        "dump_passes": 2,
        "dump_block_bytes": BLOCK_BYTES,
        "dump_count_words": 8,
        "max_feature_calls": MAX_CALLS,
        "max_ioctls_including_cached_metadata": MAX_CALLS + 1,
        "open_window_budget_ms": OPEN_BUDGET_MS,
        "per_call_deadline_ms": 5000,
        "maximum_key_enable_assignments": 1,
        "maximum_key_close_assignments": 1,
        "cleanup_after_completed_read_failure": true,
        "cleanup_after_uncertain_call_or_changed_binding": false,
        "limits": limits(),
    });
    let id = firmware::sha256(&serde_json::to_vec(&plan).map_err(|e| e.to_string())?);
    save_json(&out.join("plan.json"), &plan)?;
    if let Some(scenario) = scenario {
        let (report, job) = access_simulation::simulate(baseline, scenario)?;
        persist_images(&out, &job, "SYNTHETIC-internal-flash")?;
        save_json(&out.join("simulation.json"), &report)?;
        return Ok(serde_json::json!({"plan_sha256":id,"simulation":report,"output":out}));
    }
    Ok(
        serde_json::json!({"mode":"offline_temporary_access_plan","plan_sha256":id,"physical_execution_available":false,"output":out,"max_feature_calls":MAX_CALLS}),
    )
}
