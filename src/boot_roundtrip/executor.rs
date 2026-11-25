use super::{
    Fault, Mode, connection,
    connection::DeviceBinding,
    engine::{Action, Answer, Link, Session, State},
};
use crate::{
    access_job::CallKind,
    discovery,
    query_session::{self, Binding},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

type TargetRequest<'a> = (&'a Path, &'a Path, Option<(&'a Path, Mode)>);
pub(super) mod pipeline;
#[derive(Clone, Copy)]
enum RestoreOperation<'a> {
    Image(&'a Path, bool),
    Probe(&'a Path),
    EntryReturn(&'a Path, Mode),
    Target(&'a Path, &'a Path, Option<(&'a Path, Mode)>),
}
impl<'a> RestoreOperation<'a> {
    fn target(self) -> Option<TargetRequest<'a>> {
        if let Self::Target(backup, proof, cleanup) = self {
            Some((backup, proof, cleanup))
        } else {
            None
        }
    }
    fn image(self) -> Option<(&'a Path, bool)> {
        match self {
            Self::Image(path, normal) => Some((path, normal)),
            Self::Probe(path) => Some((path, true)),
            _ => None,
        }
    }
    fn entry_return(self) -> Option<(&'a Path, Mode)> {
        if let Self::EntryReturn(path, mode) = self {
            Some((path, mode))
        } else {
            None
        }
    }
}

pub(super) fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub(super) fn save_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    save(path, &bytes)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Proposal {
        number: u32,
        action: Action,
    },
    Completed {
        number: u32,
        result: Result<Answer, Fault>,
    },
    Done {
        state: Box<State>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    number: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    cancel: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalRelease {
    number: u32,
    release_after_done: bool,
}

fn send(output: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|error| error.to_string())?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|error| error.to_string())
}

fn read<T: for<'de> Deserialize<'de>>(input: &mut impl BufRead) -> Result<T, String> {
    let mut bytes = Vec::new();
    input
        .take(16385)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 16384 || bytes.last() != Some(&b'\n') {
        return Err("round-trip IPC ended or exceeded its line bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
struct Guarded<T: Link, R: BufRead, W: Write> {
    inner: T,
    input: R,
    output: W,
    number: u32,
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl<T: Link, R: BufRead, W: Write> Guarded<T, R, W> {
    fn finish(&mut self, state: &State) -> Result<(), String> {
        send(
            &mut self.output,
            &Event::Done {
                state: Box::new(state.clone()),
            },
        )?;
        // Retain the native handle while the coordinator validates the final
        // completion and independently reaches the same state. EOF/mismatch
        // fails closed; the outer supervisor still bounds and reaps the worker.
        let release: FinalRelease = read(&mut self.input)?;
        if release.number != self.number || !release.release_after_done {
            return Err("worker final release differs from completed cursor".into());
        }
        Ok(())
    }
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl<T: Link, R: BufRead, W: Write> Link for Guarded<T, R, W> {
    fn perform(&mut self, action: &Action) -> Result<Answer, Fault> {
        send(
            &mut self.output,
            &Event::Proposal {
                number: self.number,
                action: action.clone(),
            },
        )
        .map_err(Fault::uncertain)?;
        let grant: Grant = read(&mut self.input).map_err(Fault::uncertain)?;
        if grant.number != self.number {
            return Err(Fault::uncertain("worker grant cursor differs"));
        }
        let result = if grant.cancel {
            Err(Fault::known("coordinator canceled before device action"))
        } else {
            self.inner.perform(action)
        };
        send(
            &mut self.output,
            &Event::Completed {
                number: self.number,
                result: result.clone(),
            },
        )
        .map_err(Fault::uncertain)?;
        self.number += 1;
        result
    }
}

struct Remote {
    cycle: Option<pipeline::Control>,
    cancel_path: Option<std::path::PathBuf>,
    input: Box<dyn Write + Send>,
    events: mpsc::Receiver<Result<Event, String>>,
    log: File,
    original: Binding,
    bound: Option<DeviceBinding>,
    number: u32,
    start: Instant,
    total_budget: Duration,
    #[cfg(test)]
    offline_protocol_test: bool,
}

impl Remote {
    fn finish(&mut self, state: &State) -> bool {
        if !matches!(self.receive(Duration::from_secs(5)),Ok(Event::Done{state:worker}) if *worker==*state)
        {
            return false;
        }
        send(
            &mut self.input,
            &FinalRelease {
                number: self.number,
                release_after_done: true,
            },
        )
        .is_ok()
    }
    fn receive(&self, timeout: Duration) -> Result<Event, Fault> {
        self.events
            .recv_timeout(timeout)
            .map_err(|error| {
                Fault::uncertain(format!("round-trip IPC deadline or termination: {error}"))
            })?
            .map_err(Fault::uncertain)
    }

    fn cached(&self, action: &Action, answer: Option<&Answer>) -> Result<(), Fault> {
        #[cfg(test)]
        if self.offline_protocol_test {
            return Ok(());
        }
        if answer.is_some()
            && matches!(action,Action::Feature{kind:CallKind::Set,frame,..} if frame[1]==0)
        {
            return Ok(());
        }
        match (action, answer) {
            (
                Action::Connect {
                    mode: Mode::Boot, ..
                },
                None,
            ) => {
                if !super::boot_control_available() {
                    return Err(Fault::known("boot USB control transport is disabled"));
                }
                super::boot_usb::Binding::discover(&self.original, Path::new("/sys"))
                    .map_err(Fault::uncertain)?;
            }
            (Action::Connect { mode, previous }, Some(Answer::Connected(binding))) => {
                connection::validate_connection(*mode, binding, &self.original)?;
                match binding.as_ref() {
                    DeviceBinding::Usb(usb) => usb
                        .revalidate(Path::new("/sys"), super::boot_usb::Ownership::Claimed)
                        .map_err(Fault::uncertain)?,
                    DeviceBinding::Hid(hid) => {
                        if *mode == Mode::Boot {
                            return Err(Fault::uncertain(
                                "native boot connection attempted hidraw polling",
                            ));
                        }
                        let report =
                            discovery::collect(Path::new("/sys")).map_err(Fault::uncertain)?;
                        if connection::select_binding(&report, &self.original, *mode)
                            .map_err(Fault::uncertain)?
                            .as_ref()
                            != Some(hid)
                        {
                            return Err(Fault::uncertain(
                                "coordinator binding differs from worker",
                            ));
                        }
                    }
                }
                if let Some(old) = previous {
                    let report = discovery::collect(Path::new("/sys")).map_err(Fault::uncertain)?;
                    if old.released(&report).is_ok()
                        && !(*mode == Mode::Normal && old.product_id() == self.original.product_id)
                    {
                        return Err(Fault::uncertain(
                            "previous interface remains present after reset",
                        ));
                    }
                }
            }
            (Action::Feature { mode, .. } | Action::Observe { mode, .. }, _) => {
                let bound = self
                    .bound
                    .as_ref()
                    .ok_or_else(|| Fault::uncertain("coordinator has no opened binding"))?;
                connection::validate_connection(*mode, bound, &self.original)?;
                match bound {
                    DeviceBinding::Usb(usb) => usb
                        .revalidate(Path::new("/sys"), super::boot_usb::Ownership::Claimed)
                        .map_err(Fault::uncertain)?,
                    DeviceBinding::Hid(hid) => {
                        let report =
                            discovery::collect(Path::new("/sys")).map_err(Fault::uncertain)?;
                        hid.revalidate_control(&report).map_err(Fault::uncertain)?;
                        if connection::select_binding(&report, &self.original, *mode)
                            .map_err(Fault::uncertain)?
                            .as_ref()
                            != Some(hid)
                        {
                            return Err(Fault::uncertain("coordinator HID mode became ambiguous"));
                        }
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}

impl Link for Remote {
    fn perform(&mut self, action: &Action) -> Result<Answer, Fault> {
        if self.start.elapsed() > self.total_budget {
            return Err(Fault::uncertain("round-trip overall deadline expired"));
        }
        let Event::Proposal {
            number,
            action: proposed,
        } = self.receive(Duration::from_secs(5))?
        else {
            return Err(Fault::uncertain("worker did not propose its next action"));
        };
        if number != self.number || &proposed != action {
            return Err(Fault::uncertain("worker proposed a different action"));
        }
        let cancel = self.cycle.as_ref().is_some_and(|c| c.cancel(action))
            || self.cancel_path.as_ref().is_some_and(|p| p.exists())
                && !matches!(action,Action::Feature{phase,..} if matches!(phase.as_str(),"close-gate"|"verify-closed"));
        if !cancel {
            self.cached(action, None)?;
            if let Some(control) = self.cycle.clone() {
                control.before(self, action)?;
            }
        }
        query_session::journal(
            &mut self.log,
            if cancel {
                "roundtrip_cancel"
            } else {
                "roundtrip_intent"
            },
            &serde_json::json!({"number":number,"action":action}),
        )
        .map_err(Fault::uncertain)?;
        send(&mut self.input, &Grant { number, cancel }).map_err(Fault::uncertain)?;
        let deadline = if matches!(action, Action::Connect { .. }) {
            Duration::from_secs(25)
        } else {
            Duration::from_secs(5)
        };
        let event = self.receive(deadline)?;
        query_session::journal(&mut self.log, "roundtrip_completion", &event)
            .map_err(Fault::uncertain)?;
        let Event::Completed {
            number: completed,
            result,
        } = event
        else {
            return Err(Fault::uncertain("worker returned a different IPC event"));
        };
        if completed != number {
            return Err(Fault::uncertain("worker completion cursor differs"));
        }
        self.number += 1;
        let answer = result?;
        self.cached(action, Some(&answer))?;
        if let Answer::Connected(binding) = &answer {
            self.bound = Some(*binding.clone());
        }
        Ok(answer)
    }
}

fn stop(child: &mut Child) -> Result<bool, String> {
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(status.success());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().map_err(|error| error.to_string())?;
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("worker cancellation remains unverified".into())
}

pub(super) fn run(reference_path: &Path, output: &Path) -> Result<serde_json::Value, String> {
    run_inner(reference_path, output, None, false, false, None, false)
}

pub(super) fn run_firmware(
    reference_path: &Path,
    output: &Path,
    assets: &Path,
    core: crate::model::Core,
) -> Result<serde_json::Value, String> {
    run_inner(
        reference_path,
        output,
        Some((assets, core)),
        false,
        false,
        None,
        false,
    )
}

pub(super) fn run_backup(
    reference_path: &Path,
    output: &Path,
) -> Result<serde_json::Value, String> {
    run_inner(reference_path, output, None, true, false, None, false)
}

fn run_inner(
    reference_path: &Path,
    output: &Path,
    firmware: Option<(&Path, crate::model::Core)>,
    normal_backup: bool,
    gate_close_only: bool,
    restore_operation: Option<RestoreOperation<'_>>,
    lock_held: bool,
) -> Result<serde_json::Value, String> {
    let restore_backup = restore_operation.and_then(RestoreOperation::image);
    let return_request = restore_operation.and_then(RestoreOperation::entry_return);
    let readback_only = matches!(restore_operation, Some(RestoreOperation::Probe(_)));
    let target_request = restore_operation.and_then(RestoreOperation::target);
    let reference = super::load(reference_path)?;
    let target_proof = target_request
        .map(|(backup, proof, cleanup)| {
            let backup = crate::backup_restore::Plan::load(backup)?;
            if let Some((entry, _)) = cleanup {
                super::target_return::cleanup_proof(&reference, &backup, proof, entry, true)
            } else {
                super::target_return::load(&reference, &backup, proof, true)
            }
        })
        .transpose()?;
    let entry_return = return_request
        .map(|(path, mode)| super::entry_return::load(&reference, path).map(|proof| (proof, mode)))
        .transpose()?;
    let plan = firmware
        .map(|(assets, core)| super::firmware_plan(assets, core))
        .transpose()?;
    let restore = restore_backup
        .map(|(path, _)| crate::backup_restore::Plan::load(path))
        .transpose()?;
    let output = crate::access_session::create_output(output)?;
    if let Some(plan) = &plan {
        save_json(
            &output.join("firmware-plan.json"),
            &serde_json::json!({
                "firmware":plan.summary(),"baseline_sha256":reference.baseline.fingerprint(),
                "total_budget_seconds":super::FIRMWARE_TOTAL_SECONDS,"maximum_feature_calls":super::FIRMWARE_MAX_FEATURE_CALLS,
                "whole_configuration_pipeline_complete":false,
            }),
        )?;
    }
    if let Some(restore) = &restore {
        save_json(
            &output.join("restore-plan.json"),
            &restore.summary_with_entry(restore_backup.is_some_and(|(_, normal)| normal)),
        )?;
    }
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("journal.jsonl"))
        .map_err(|error| error.to_string())?;
    let before = discovery::collect(Path::new("/sys"))?;
    before.save(&output.join("before"))?;
    let entry_mode = if let Some(proof) = &target_proof {
        target_request
            .and_then(|(_, _, cleanup)| cleanup.map(|(_, mode)| mode))
            .unwrap_or(Mode::Target(proof.core))
    } else if let Some((_, mode)) = return_request {
        mode
    } else if restore_backup.is_some_and(|(_, normal)| !normal) {
        Mode::Boot
    } else {
        Mode::Normal
    };
    if entry_mode == Mode::Boot {
        if !super::boot_control_available() {
            return Err("boot USB control transport is disabled".into());
        }
        super::boot_usb::Binding::discover(reference.baseline.binding(), Path::new("/sys"))?
            .ok_or("expected same-port boot USB device absent")?;
    } else {
        connection::select_binding(&before, reference.baseline.binding(), entry_mode)?
            .ok_or("expected same-port entry device absent")?;
    }
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("worker.stderr.txt"))
        .map_err(|error| error.to_string())?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    if !lock_held {
        super::lease::acquire(
            &query_session::lock_path(),
            &output,
            &reference.baseline.fingerprint(),
            false,
        )?;
    }
    (|| {
        let mut command = Command::new(executable);
        if let Some((backup, proof, cleanup)) = target_request {
            command
                .arg("__firmware-target-worker")
                .arg(reference_path)
                .arg(backup)
                .arg(proof);
            if let Some((entry, mode)) = cleanup {
                command
                    .arg(if mode == Mode::Boot {
                        "cleanup-boot"
                    } else {
                        "cleanup-target"
                    })
                    .arg(entry);
            } else {
                command.arg("entry");
            }
        } else if let Some((proof, mode)) = return_request {
            command
                .arg("__entry-return-worker")
                .arg(reference_path)
                .arg(proof)
                .arg(if mode == Mode::Boot { "boot" } else { "normal" });
        } else if let Some(RestoreOperation::Probe(backup)) = restore_operation {
            command
                .arg("__boot-readback-worker")
                .arg(reference_path)
                .arg(backup);
        } else if let Some((backup, normal)) = restore_backup {
            command
                .arg("__firmware-restore-worker")
                .arg(reference_path)
                .arg(backup)
                .arg(if normal { "normal" } else { "boot" });
        } else if let Some((assets, core)) = firmware {
            command
                .arg("__firmware-job-worker")
                .arg(reference_path)
                .arg(assets)
                .arg(core.number().to_string());
        } else if gate_close_only {
            command
                .arg("__firmware-gate-close-worker")
                .arg(reference_path);
        } else if normal_backup {
            command.arg("__firmware-backup-worker").arg(reference_path);
        } else {
            command.arg("__boot-roundtrip-worker").arg(reference_path);
        }
        let spawn = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn();
        let mut child = match spawn {
            Ok(child) => child,
            Err(error) => {
                if !lock_held {
                    super::lease::release(&query_session::lock_path())?;
                }
                return Err(error.to_string());
            }
        };
        if let Err(error) = super::lease::worker(&query_session::lock_path(), &output, child.id()) {
            let _ = stop(&mut child);
            return Err(error);
        }
        let input = child
            .stdin
            .take()
            .ok_or("round-trip worker stdin missing")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("round-trip worker stdout missing")?;
        let (sender, events) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let event = read::<Event>(&mut reader);
                let ended = event.is_err();
                if sender.send(event).is_err() || ended {
                    break;
                }
            }
        });
        let remote = Remote {
            cycle: None,
            cancel_path: restore
                .as_ref()
                .map(|_| output.parent().unwrap_or(&output).join("STOP"))
                .or_else(|| {
                    target_request
                        .filter(|(_, _, cleanup)| cleanup.is_none())
                        .map(|_| output.parent().unwrap_or(&output).join("STOP"))
                }),
            input: Box::new(input),
            events,
            log,
            original: reference.baseline.binding().clone(),
            bound: None,
            number: 0,
            start: Instant::now(),
            total_budget: Duration::from_secs(if target_proof.is_some() {
                super::target_return::TOTAL_SECONDS
            } else if entry_return.is_some() {
                120
            } else if gate_close_only {
                60
            } else if restore_backup.is_some_and(|(_, normal)| normal) {
                crate::backup_restore::NORMAL_ENTRY_TOTAL_SECONDS
            } else if restore.is_some() {
                crate::backup_restore::TOTAL_SECONDS
            } else if plan.is_some() {
                super::FIRMWARE_TOTAL_SECONDS
            } else if normal_backup {
                900
            } else {
                120
            }),
            #[cfg(test)]
            offline_protocol_test: false,
        };
        let (mut state, mut remote) = if let Some(proof) = &target_proof {
            Session::new_target_bridge(
                &reference,
                proof,
                target_request.and_then(|(_, _, cleanup)| cleanup.map(|(_, mode)| mode)),
                remote,
                Some(&output),
            )
            .execute()
        } else if let Some((proof, mode)) = &entry_return {
            Session::new_entry_return(&reference, proof, *mode, remote, Some(&output)).execute()
        } else if readback_only {
            Session::new_readback(
                &reference,
                restore.as_ref().ok_or("missing readback plan")?,
                remote,
                Some(&output),
            )
            .execute()
        } else if let Some(restore) = &restore {
            Session::new_restore_entry(
                &reference,
                restore,
                remote,
                Some(&output),
                restore_backup.is_some_and(|(_, normal)| normal),
            )
            .execute()
        } else {
            match &plan {
                Some(plan) => {
                    Session::new_firmware(&reference, plan, remote, Some(&output)).execute()
                }
                None if gate_close_only => {
                    Session::new_gate_close(&reference, remote, Some(&output)).execute()
                }
                None if normal_backup => {
                    Session::new_backup(&reference, remote, Some(&output)).execute()
                }
                None => Session::new(&reference, remote, Some(&output)).execute(),
            }
        };
        let agreed = remote.finish(&state);
        let final_binding = remote.bound.clone();
        drop(remote);
        let stopped = stop(&mut child);
        let reaped = stopped.is_ok();
        if !agreed || stopped != Ok(true) {
            state.uncertain = true;
            state.complete = false;
            state.release_lock_allowed = false;
            state.cleanup_failure = Some("worker exit or final state agreement failed".into());
        }
        let after = discovery::collect(Path::new("/sys"))?;
        after.save(&output.join("after"))?;
        if state.release_lock_allowed
            && let Some(binding) = final_binding
            && binding.released(&after).is_err()
        {
            state.uncertain = true;
            state.complete = false;
            state.release_lock_allowed = false;
            state.cleanup_failure = Some("final cached binding changed".into());
        }
        let report = serde_json::json!({"mode":if target_request.is_some(){if target_request.is_some_and(|(_,_,cleanup)|cleanup.is_some()) {"native_target_pre_record_return"}else{"native_target_boot_entry"}}else if entry_return.is_some(){"native_pre_record_entry_return"}else if readback_only{"native_boot_readback_attempt"}else if restore.is_some(){"native_backup_restore_attempt"}else if gate_close_only{"native_normal_gate_close"}else if normal_backup{"native_normal_firmware_backup"}else if plan.is_some(){"native_prepared_firmware_job"}else{"native_boot_roundtrip"}, "result":state,
            "worker_pid":child.id(),"worker_reaped":reaped,"worker_state_agreed":agreed,
            "reference_directory":reference_path,"whole_configuration_pipeline_complete":false,
            "firmware":plan.as_ref().map(|p|p.summary())});
        save_json(&output.join("session.json"), &report)?;
        if state.release_lock_allowed && !lock_held {
            super::lease::release(&query_session::lock_path())?;
        }
        Ok(report)
    })()
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
struct Native {
    original: Binding,
    bound: Option<(Mode, DeviceBinding)>,
    transport: Option<Box<dyn crate::transport::LocalFeatureTransport>>,
    reset_sent: bool,
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
#[derive(Default)]
struct OpenAttempts {
    failures: u8,
    last_error: Option<String>,
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl OpenAttempts {
    fn observe<T>(&mut self, result: Result<T, String>) -> Result<Option<T>, Fault> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                self.failures += 1;
                self.last_error = Some(error);
                if self.failures >= 32 {
                    Err(Fault::known(format!(
                        "control open failed after 32 bounded attempts: {}",
                        self.last_error.as_deref().unwrap_or("unknown")
                    )))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl Link for Native {
    fn perform(&mut self, action: &Action) -> Result<Answer, Fault> {
        use crate::access_job::Completion;
        match action {
            Action::Connect { mode, previous } => {
                if previous.as_deref() != self.bound.as_ref().map(|(_, binding)| binding)
                    || (previous.is_some() && !self.reset_sent)
                {
                    return Err(Fault::uncertain("native reconnect cursor differs"));
                }
                self.transport = None;
                let start = Instant::now();
                let mut opens = OpenAttempts::default();
                loop {
                    if start.elapsed() > Duration::from_secs(20) {
                        return Err(Fault::known(format!(
                            "expected same-port USB mode did not appear; last open error: {:?}",
                            opens.last_error
                        )));
                    }
                    if let Ok(report) = discovery::collect(Path::new("/sys"))
                        && report.complete()
                    {
                        if previous
                            .as_ref()
                            .is_some_and(|old| old.released(&report).is_ok())
                            && !(*mode == Mode::Normal
                                && previous.as_ref().is_some_and(|old| {
                                    old.product_id() == self.original.product_id
                                }))
                        {
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                        if *mode == Mode::Boot {
                            if !super::boot_control_available() {
                                return Err(Fault::known("boot USB control transport is disabled"));
                            }
                            if let Some(binding) = super::boot_usb::Binding::discover(
                                &self.original,
                                Path::new("/sys"),
                            )? && let Some(device) =
                                opens.observe(super::boot_usb::open(&binding))?
                            {
                                let binding = DeviceBinding::Usb(binding);
                                self.transport = Some(device);
                                self.bound = Some((*mode, binding.clone()));
                                self.reset_sent = false;
                                return Ok(Answer::Connected(Box::new(binding)));
                            }
                        } else if let Some(binding) =
                            connection::select_binding(&report, &self.original, *mode)?
                            && let Some(device) =
                                opens.observe(query_session::open_transition_transport(&binding))?
                        {
                            let binding = DeviceBinding::Hid(binding);
                            self.transport = Some(Box::new(device));
                            self.bound = Some((*mode, binding.clone()));
                            self.reset_sent = false;
                            return Ok(Answer::Connected(Box::new(binding)));
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Action::Feature {
                mode, kind, frame, ..
            } => {
                let (current, binding) = self.bound.as_ref().ok_or_else(|| {
                    Fault::uncertain("native feature call without an open binding")
                })?;
                if current != mode {
                    return Err(Fault::uncertain("native feature mode differs"));
                }
                let check = || -> Result<(), Fault> {
                    connection::validate_connection(*mode, binding, &self.original)?;
                    match binding {
                        DeviceBinding::Usb(usb) => usb
                            .revalidate(Path::new("/sys"), super::boot_usb::Ownership::Claimed)
                            .map_err(Fault::uncertain)?,
                        DeviceBinding::Hid(hid) => {
                            let report =
                                discovery::collect(Path::new("/sys")).map_err(Fault::uncertain)?;
                            hid.revalidate_control(&report).map_err(Fault::uncertain)?;
                            if connection::select_binding(&report, &self.original, *mode)?.as_ref()
                                != Some(hid)
                            {
                                return Err(Fault::uncertain("native HID mode became ambiguous"));
                            }
                        }
                    }
                    Ok(())
                };
                check()?;
                let device = self
                    .transport
                    .as_mut()
                    .ok_or_else(|| Fault::uncertain("native handle is closed"))?;
                if *kind == CallKind::Set && frame[1] == 0 {
                    let result = device.set_local(frame);
                    self.reset_sent = true;
                    self.transport = None;
                    return Ok(Answer::ResetAttempt {
                        acknowledged: result.is_ok(),
                        error: result.err().map(|error| error.to_string()),
                    });
                }
                let completion = match kind {
                    CallKind::Set => {
                        device
                            .set_local(frame)
                            .map_err(|error| Fault::uncertain(error.to_string()))?;
                        Completion::SetComplete
                    }
                    CallKind::Get => Completion::GetComplete(
                        device
                            .get_local(7, 64)
                            .map_err(|error| Fault::uncertain(error.to_string()))?,
                    ),
                };
                check()?;
                Ok(Answer::Feature(completion))
            }
            Action::Observe { mode, .. } => {
                if self.bound.as_ref().map(|(m, _)| m) != Some(mode) || self.transport.is_none() {
                    return Err(Fault::uncertain("observation lost its held native handle"));
                }
                Ok(Answer::Observed)
            }
        }
    }
}

pub(super) fn worker(reference_path: &Path) -> Result<(), String> {
    worker_inner(reference_path, None, false, false, None)
}
pub(super) fn worker_firmware(
    reference_path: &Path,
    assets: &Path,
    core: crate::model::Core,
) -> Result<(), String> {
    worker_inner(reference_path, Some((assets, core)), false, false, None)
}
pub(super) fn worker_backup(reference_path: &Path) -> Result<(), String> {
    worker_inner(reference_path, None, true, false, None)
}
fn worker_inner(
    reference_path: &Path,
    firmware: Option<(&Path, crate::model::Core)>,
    normal_backup: bool,
    gate_close_only: bool,
    restore_operation: Option<RestoreOperation<'_>>,
) -> Result<(), String> {
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        let restore_backup = restore_operation.and_then(RestoreOperation::image);
        let return_request = restore_operation.and_then(RestoreOperation::entry_return);
        let readback_only = matches!(restore_operation, Some(RestoreOperation::Probe(_)));
        let target_request = restore_operation.and_then(RestoreOperation::target);
        let reference = super::load(reference_path)?;
        let target_proof = target_request
            .map(|(backup, proof, cleanup)| {
                let backup = crate::backup_restore::Plan::load(backup)?;
                if let Some((entry, _)) = cleanup {
                    super::target_return::cleanup_proof(&reference, &backup, proof, entry, true)
                } else {
                    super::target_return::load(&reference, &backup, proof, true)
                }
            })
            .transpose()?;
        let entry_return = return_request
            .map(|(path, mode)| {
                super::entry_return::load(&reference, path).map(|proof| (proof, mode))
            })
            .transpose()?;
        let plan = firmware
            .map(|(assets, core)| super::firmware_plan(assets, core))
            .transpose()?;
        let restore = restore_backup
            .map(|(path, _)| crate::backup_restore::Plan::load(path))
            .transpose()?;
        let native = Native {
            original: reference.baseline.binding().clone(),
            bound: None,
            transport: None,
            reset_sent: false,
        };
        let link = Guarded {
            inner: native,
            input: BufReader::new(std::io::stdin().lock()),
            output: std::io::stdout().lock(),
            number: 0,
        };
        let (state, mut link) = if let Some(proof) = &target_proof {
            Session::new_target_bridge(
                &reference,
                proof,
                target_request.and_then(|(_, _, cleanup)| cleanup.map(|(_, mode)| mode)),
                link,
                None,
            )
            .execute()
        } else if let Some((proof, mode)) = &entry_return {
            Session::new_entry_return(&reference, proof, *mode, link, None).execute()
        } else if readback_only {
            Session::new_readback(
                &reference,
                restore.as_ref().ok_or("missing readback plan")?,
                link,
                None,
            )
            .execute()
        } else if let Some(restore) = &restore {
            Session::new_restore_entry(
                &reference,
                restore,
                link,
                None,
                restore_backup.is_some_and(|(_, normal)| normal),
            )
            .execute()
        } else {
            match &plan {
                Some(plan) => Session::new_firmware(&reference, plan, link, None).execute(),
                None if gate_close_only => {
                    Session::new_gate_close(&reference, link, None).execute()
                }
                None if normal_backup => Session::new_backup(&reference, link, None).execute(),
                None => Session::new(&reference, link, None).execute(),
            }
        };
        link.finish(&state)
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        let _ = (
            reference_path,
            firmware,
            normal_backup,
            gate_close_only,
            restore_operation,
        );
        Err("native round-trip backend unavailable".into())
    }
}

pub(super) fn run_gate_close(reference: &Path, output: &Path) -> Result<serde_json::Value, String> {
    run_inner(reference, output, None, false, true, None, false)
}
pub(super) fn worker_gate_close(reference: &Path) -> Result<(), String> {
    worker_inner(reference, None, false, true, None)
}

pub(super) fn worker_restore(
    reference: &Path,
    backup: &Path,
    from_normal: bool,
) -> Result<(), String> {
    worker_inner(
        reference,
        None,
        false,
        false,
        Some(RestoreOperation::Image(backup, from_normal)),
    )
}

pub(super) fn run_target_bridge(
    reference: &Path,
    backup: &Path,
    proof: &Path,
    output: &Path,
    cleanup: Option<(&Path, Mode)>,
) -> Result<serde_json::Value, String> {
    run_inner(
        reference,
        output,
        None,
        false,
        false,
        Some(RestoreOperation::Target(backup, proof, cleanup)),
        true,
    )
}

pub(super) fn worker_target_bridge(
    reference: &Path,
    backup: &Path,
    proof: &Path,
    cleanup: Option<(&Path, Mode)>,
) -> Result<(), String> {
    worker_inner(
        reference,
        None,
        false,
        false,
        Some(RestoreOperation::Target(backup, proof, cleanup)),
    )
}

pub(super) fn restore_held(
    reference: &Path,
    backup: &Path,
    output: &Path,
) -> Result<serde_json::Value, String> {
    let plan = crate::backup_restore::Plan::load(backup)?;
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    save(&output.join("restore-records.bin"), &plan.encoded_records())?;
    save_json(&output.join("restore-plan.json"), &plan.summary())?;
    retry_restore(output, plan.sha256(), None, false, |_, directory| {
        run_inner(
            reference,
            directory,
            None,
            false,
            false,
            Some(RestoreOperation::Image(backup, false)),
            true,
        )
    })
}

pub(super) fn worker_readback(reference: &Path, backup: &Path) -> Result<(), String> {
    worker_inner(
        reference,
        None,
        false,
        false,
        Some(RestoreOperation::Probe(backup)),
    )
}

pub(super) fn worker_entry_return(
    reference: &Path,
    proof: &Path,
    mode: Mode,
) -> Result<(), String> {
    worker_inner(
        reference,
        None,
        false,
        false,
        Some(RestoreOperation::EntryReturn(proof, mode)),
    )
}

/// The caller owns one lock across every attempt. Never adopts an old lock or
/// repeats traffic while a previous worker may still own a handle.
pub(super) fn retry_restore(
    output: &Path,
    expected_backup_sha256: &str,
    max_attempts: Option<u32>,
    return_before_records: bool,
    mut attempt: impl FnMut(u32, &Path) -> Result<serde_json::Value, String>,
) -> Result<serde_json::Value, String> {
    if max_attempts == Some(0) {
        return Err("attempt limit must be positive".into());
    }
    let mut reports = Vec::new();
    let mut complete = false;
    let reason = loop {
        if output.join("STOP").exists() {
            break "canceled_before_next_attempt";
        }
        let number = u32::try_from(reports.len()).map_err(|e| e.to_string())? + 1;
        let directory = output.join(format!("attempt-{number:04}"));
        let report = match attempt(number, &directory) {
            Ok(report) => report,
            Err(error) => {
                reports.push(
                    serde_json::json!({"attempt":number,"failure":error,"worker_reaped":null}),
                );
                break "attempt_start_or_supervision_failed";
            }
        };
        complete = report["result"]["complete"] == true
            && report["worker_state_agreed"] == true
            && report["result"]["normal_verified"] == true
            && report["result"]["restore"]["restored_image_sha256"] == expected_backup_sha256;
        let reaped = report["worker_reaped"] == true;
        let retryable = reaped
            && report["result"]["mode"] == "boot"
            && report["result"]["restore"]["retry_allowed"] == true;
        let no_records = report["result"]["restore"]["record_intents"] == 0;
        reports.push(report);
        if !reaped {
            complete = false;
            break "previous_worker_not_proven_stopped";
        }
        if complete {
            break "verified_restore_complete";
        }
        if return_before_records && no_records {
            break "pre_record_failure_return_required";
        }
        if !retryable {
            break "fresh_boot_recovery_or_identity_review_required";
        }
        if max_attempts.is_some_and(|limit| number >= limit) {
            break "attempt_limit_reached";
        }
    };
    let report = serde_json::json!({"mode":"backup_restore_retries","complete":complete,
        "stop_reason":reason,"attempts":reports,"resume_supported":false,
        "backup_sha256":expected_backup_sha256});
    save_json(&output.join("restore.json"), &report)?;
    Ok(report)
}

fn entry_return_verified(report: &serde_json::Value) -> bool {
    let r = &report["entry_return"];
    r["result"]["complete"] == true
        && r["worker_reaped"] == true
        && r["worker_state_agreed"] == true
        && r["result"]["release_lock_allowed"] == true
        && r["result"]["normal_verified"] == true
        && r["result"]["mode"] == "normal"
}

pub(super) fn run_restore(
    reference: &Path,
    backup: &Path,
    output: &Path,
    max_attempts: Option<u32>,
    from_normal: bool,
) -> Result<serde_json::Value, String> {
    run_backup_operation(reference, backup, output, max_attempts, from_normal, false)
}
pub(super) fn run_readback(
    reference: &Path,
    backup: &Path,
    output: &Path,
) -> Result<serde_json::Value, String> {
    run_backup_operation(reference, backup, output, Some(1), true, true)
}
fn run_backup_operation(
    reference: &Path,
    backup: &Path,
    output: &Path,
    max_attempts: Option<u32>,
    from_normal: bool,
    readback_only: bool,
) -> Result<serde_json::Value, String> {
    if max_attempts == Some(0) {
        return Err("attempt limit must be positive".into());
    }
    let loaded_reference = super::load(reference)?;
    let plan = crate::backup_restore::Plan::load(backup)?;
    let output = crate::access_session::create_output(output)?;
    // Freeze the verified source once. Worker and coordinator reload this same
    // pinned snapshot; a partial-attempt readback never becomes a restore source.
    let source = output.join("original-backup");
    std::fs::create_dir(&source).map_err(|e| e.to_string())?;
    for pass in [0, 1] {
        save(
            &source.join(format!("normal-image.pass{pass}.bin")),
            &plan.original,
        )?;
    }
    save(
        &source.join("session.json"),
        &crate::preview::read_file(&backup.join("session.json"), 1_048_576)?,
    )?;
    crate::backup_restore::Plan::load(&source)?;
    save_json(
        &output.join("restore-plan.json"),
        &plan.summary_with_entry(from_normal),
    )?;
    if !readback_only {
        save(&output.join("restore-records.bin"), &plan.encoded_records())?;
    }
    super::lease::acquire(
        &query_session::lock_path(),
        &output,
        &loaded_reference.baseline.fingerprint(),
        true,
    )?;
    let result = retry_restore(
        &output,
        plan.sha256(),
        max_attempts,
        from_normal,
        |number, directory| {
        run_inner(
            reference,
            directory,
            None,
            false,
            false,
            Some(if readback_only {
                RestoreOperation::Probe(&source)
            } else {
                RestoreOperation::Image(&source, from_normal && number == 1)
            }),
            true,
        )
    });
    let result = if from_normal && result.as_ref().is_ok_and(|r| r["complete"] != true) {
        let mut report = result?;
        let proof_path = output.join("entry-return-proof.json");
        match super::entry_return::create(&loaded_reference, &source, &output, &proof_path) {
            Ok(_) => {
                let cleanup = (|| {
                    let mode = if super::boot_usb::Binding::discover(
                        loaded_reference.baseline.binding(),
                        Path::new("/sys"),
                    )?
                    .is_some()
                    {
                        Mode::Boot
                    } else {
                        Mode::Normal
                    };
                    run_inner(
                        reference,
                        &output.join("entry-return"),
                        None,
                        false,
                        false,
                        Some(RestoreOperation::EntryReturn(&proof_path, mode)),
                        true,
                    )
                })();
                match cleanup {
                    Ok(cleanup) => report["entry_return"] = cleanup,
                    Err(error) => report["entry_return_error"] = error.into(),
                }
            }
            Err(reason) => report["entry_return_refused"] = reason.into(),
        }
        if readback_only {
            report["mode"] = "boot_readback_with_entry_return".into();
            report["capture_complete"] =
                report["attempts"][0]["result"]["restore"]["boot_readback_verified"].clone();
            report["complete"] =
                (report["capture_complete"] == true && entry_return_verified(&report)).into();
            save_json(&output.join("boot-readback.json"), &report)?;
        }
        save_json(&output.join("restore-with-return.json"), &report)?;
        Ok(report)
    } else {
        result
    };
    // Failure retains the lock for review. The same invocation retains its own
    // lock between retries, so another job can never enter during recovery.
    if result
        .as_ref()
        .is_ok_and(|r| r["complete"] == true || entry_return_verified(r))
    {
        super::lease::release(&query_session::lock_path())?;
    }
    result
}
