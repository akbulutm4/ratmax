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

pub(super) mod pipeline;

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
        return Err("worker IPC ended or exceeded its line bound".into());
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
}

impl Remote {
    fn finish(&mut self, state: &State) -> bool {
        if !matches!(self.receive(Duration::from_secs(5)), Ok(Event::Done { state: worker }) if *worker == *state)
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
                Fault::uncertain(format!("worker IPC deadline or termination: {error}"))
            })?
            .map_err(Fault::uncertain)
    }

    fn cached(&self, action: &Action, answer: Option<&Answer>) -> Result<(), Fault> {
        if answer.is_some()
            && matches!(action, Action::Feature { kind: CallKind::Set, frame, .. } if frame[1] == 0)
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
            return Err(Fault::uncertain("workflow overall deadline expired"));
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
                && !matches!(action, Action::Feature { phase, .. } if matches!(phase.as_str(), "close-gate" | "verify-closed"));
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
            &serde_json::json!({"number": number, "action": action}),
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
