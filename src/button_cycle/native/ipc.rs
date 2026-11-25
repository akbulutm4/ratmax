use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    Bind {
        binding: Box<Binding>,
    },
    Feature {
        phase: String,
        kind: CallKind,
        frame: Vec<u8>,
    },
    Save {
        name: String,
        bytes: Vec<u8>,
    },
    Settle {
        milliseconds: u64,
    },
    Observe {
        phase: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "reply",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Reply {
    Bound(Box<Binding>),
    Feature(Completion),
    Saved,
    Settled,
    Observed,
    Denied(String),
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Proposal {
        number: u32,
        source_sha256: String,
        proof_sha256: Option<String>,
        action: Action,
    },
    Completed {
        number: u32,
        reply: Reply,
    },
    Done {
        number: u32,
        state: State,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    number: u32,
    permit: bool,
    reason: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    number: u32,
    release_after_done: bool,
}

fn send(output: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|e| e.to_string())?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|e| e.to_string())
}
fn read<T: for<'de> Deserialize<'de>>(input: &mut impl BufRead) -> Result<T, String> {
    let mut bytes = Vec::new();
    input
        .take(32769)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 32768 || bytes.last() != Some(&b'\n') {
        return Err("button IPC line ended or exceeded bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
pub(crate) trait Driver: Link {
    fn bind(&mut self, binding: &Binding) -> Result<(), String>;
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
pub(super) struct Guarded<'a, D, R, W> {
    pub driver: D,
    pub input: R,
    pub output: W,
    pub source: &'a Source,
    pub binding: Binding,
    pub proof_sha256: Option<String>,
    pub number: u32,
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl<D: Driver, R: BufRead, W: Write> Guarded<'_, D, R, W> {
    fn perform(&mut self, action: Action) -> Result<Reply, String> {
        if self.number >= MAX_ACTIONS {
            return Err("button worker action limit".into());
        }
        self.source.validate_action(&action, &self.binding)?;
        send(
            &mut self.output,
            &Event::Proposal {
                number: self.number,
                source_sha256: self.source.fingerprint.clone(),
                proof_sha256: self.proof_sha256.clone(),
                action: action.clone(),
            },
        )?;
        let grant: Grant = read(&mut self.input)?;
        if grant.number != self.number {
            return Err("button worker grant cursor differs".into());
        }
        let reply = if !grant.permit {
            Reply::Denied(grant.reason.ok_or("denied button grant lacks reason")?)
        } else {
            if grant.reason.is_some() {
                return Err("permitted button grant includes error".into());
            }
            match &action {
                Action::Bind { binding } => match self.driver.bind(binding) {
                    Ok(()) => Reply::Bound(binding.clone()),
                    Err(e) => Reply::Feature(Completion::Uncertain(e)),
                },
                Action::Feature { phase, kind, frame } => Reply::Feature(
                    self.driver.call(
                        phase,
                        *kind,
                        frame
                            .as_slice()
                            .try_into()
                            .map_err(|_| "button frame length")?,
                    ),
                ),
                Action::Save { .. } => Reply::Saved,
                Action::Settle { .. } => match self.driver.settle() {
                    Ok(()) => Reply::Settled,
                    Err(e) => Reply::Denied(e),
                },
                Action::Observe { phase } => match self.driver.observe(phase) {
                    Ok(()) => Reply::Observed,
                    Err(e) => Reply::Denied(e),
                },
            }
        };
        send(
            &mut self.output,
            &Event::Completed {
                number: self.number,
                reply: reply.clone(),
            },
        )?;
        self.number += 1;
        Ok(reply)
    }
    pub fn bind(&mut self) -> Result<(), String> {
        match self.perform(Action::Bind {
            binding: Box::new(self.binding.clone()),
        })? {
            Reply::Bound(b) if *b == self.binding => Ok(()),
            _ => Err("button worker bind failed".into()),
        }
    }
    pub fn finish(&mut self, state: &State) -> Result<(), String> {
        send(
            &mut self.output,
            &Event::Done {
                number: self.number,
                state: state.clone(),
            },
        )?;
        let release: Release = read(&mut self.input)?;
        if release.number != self.number || !release.release_after_done {
            return Err("button final release differs".into());
        }
        Ok(())
    }
}

fn feature(reply: Result<Reply, String>) -> Completion {
    match reply {
        Ok(Reply::Feature(c)) => c,
        Ok(Reply::Denied(e)) => Completion::CompletedFailure(e),
        Ok(_) => Completion::Uncertain("button feature reply kind differs".into()),
        Err(e) => Completion::Uncertain(e),
    }
}
fn saved(reply: Result<Reply, String>) -> Result<(), String> {
    match reply {
        Ok(Reply::Saved | Reply::Settled | Reply::Observed) => Ok(()),
        Ok(Reply::Denied(e)) => Err(e),
        _ => Err("button non-feature completion differs".into()),
    }
}
#[cfg(all(target_os = "linux", feature = "linux-query"))]
impl<D: Driver, R: BufRead, W: Write> Link for Guarded<'_, D, R, W> {
    fn validate(&mut self) -> Result<(), String> {
        self.driver.validate()
    }
    fn call(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion {
        feature(self.perform(Action::Feature {
            phase: phase.into(),
            kind,
            frame: frame.to_vec(),
        }))
    }
    fn save(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        saved(self.perform(Action::Save {
            name: name.into(),
            bytes: bytes.to_vec(),
        }))
    }
    fn settle(&mut self) -> Result<(), String> {
        saved(self.perform(Action::Settle { milliseconds: 500 }))
    }
    fn observe(&mut self, phase: &str) -> Result<(), String> {
        saved(self.perform(Action::Observe {
            phase: phase.into(),
        }))
    }
}

pub(super) struct Remote<'a> {
    pub source: &'a Source,
    pub binding: Binding,
    pub proof_sha256: Option<String>,
    input: Box<dyn Write + Send>,
    events: mpsc::Receiver<Result<Event, String>>,
    pub log: File,
    pub directory: PathBuf,
    pub cancel_path: Option<PathBuf>,
    pub number: u32,
    pub poisoned: bool,
    pub saved: BTreeMap<String, String>,
    pub program_grants: u32,
    pub feature_grants: u32,
    pub bound_granted: bool,
    pub start: Instant,
    pub action_timeout: Duration,
    pub total_timeout: Duration,
}
impl<'a> Remote<'a> {
    pub fn new(
        source: &'a Source,
        binding: Binding,
        proof_sha256: Option<String>,
        input: Box<dyn Write + Send>,
        reader: impl BufRead + Send + 'static,
        directory: &Path,
        cancel_path: Option<PathBuf>,
    ) -> Result<Self, String> {
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("journal.jsonl"))
            .map_err(|e| e.to_string())?;
        let (events_tx, events) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = reader;
            loop {
                let event = read::<Event>(&mut reader);
                let end = event.is_err();
                if events_tx.send(event).is_err() || end {
                    break;
                }
            }
        });
        Ok(Self {
            source,
            binding,
            proof_sha256,
            input,
            events,
            log,
            directory: directory.into(),
            cancel_path,
            number: 0,
            poisoned: false,
            saved: BTreeMap::new(),
            program_grants: 0,
            feature_grants: 0,
            bound_granted: false,
            start: Instant::now(),
            action_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(120 + 3 * u64::from(source.observation_seconds)),
        })
    }
    fn cached(&self) -> Result<(), String> {
        #[cfg(test)]
        if !self.source.native {
            return Ok(());
        }
        let snapshot = crate::discovery::collect(Path::new("/sys"))?;
        self.binding.revalidate_control(&snapshot)?;
        if crate::boot_roundtrip::normal_binding(&snapshot, self.source.baseline.binding())?
            != self.binding
        {
            return Err("button control binding became ambiguous".into());
        }
        Ok(())
    }
    fn receive(&mut self) -> Result<Event, String> {
        if self.poisoned {
            return Err("button IPC already uncertain".into());
        }
        let remaining = self
            .total_timeout
            .checked_sub(self.start.elapsed())
            .ok_or("button total deadline expired")?;
        self.events
            .recv_timeout(self.action_timeout.min(remaining))
            .map_err(|e| format!("button IPC deadline or termination: {e}"))?
    }
    fn perform(&mut self, action: Action) -> Result<Reply, String> {
        let result = self.perform_inner(action);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn perform_inner(&mut self, action: Action) -> Result<Reply, String> {
        if self.number >= MAX_ACTIONS {
            return Err("button coordinator action bound".into());
        }
        self.source.validate_action(&action, &self.binding)?;
        let Event::Proposal {
            number,
            source_sha256,
            proof_sha256,
            action: proposed,
        } = self.receive()?
        else {
            return Err("button worker omitted proposal".into());
        };
        if number != self.number
            || source_sha256 != self.source.fingerprint
            || proof_sha256 != self.proof_sha256
            || proposed != action
        {
            return Err("button worker proposal differs from independent plan".into());
        }
        self.cached()?;
        crate::query_session::journal(
            &mut self.log,
            "button_intent",
            &serde_json::json!({"number":number,"action":action}),
        )?;
        if let Action::Observe { phase } = &action
            && self.source.observation_seconds > 0
        {
            let seconds = self.source.observation_seconds;
            save_json(
                &self.directory.join(format!("{phase}-observation.json")),
                &serde_json::json!({"phase":phase,"seconds":seconds,"source_sha256":self.source.fingerprint,"started_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis()}),
            )?;
            eprintln!(
                "W95 Max {phase}: test the buttons and normal pointing now ({seconds}s maximum). Continue with continue-{phase}, or STOP to restore."
            );
            let end = Instant::now() + Duration::from_secs(u64::from(seconds));
            while Instant::now() < end {
                if self.directory.parent().is_some_and(|root| {
                    root.join(format!("continue-{phase}")).exists() || root.join("STOP").exists()
                }) {
                    break;
                }
                self.cached()?;
                std::thread::sleep(Duration::from_millis(100));
            }
            save_json(
                &self.directory.join(format!("{phase}-observation-end.json")),
                &serde_json::json!({"phase":phase,"ended_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis()}),
            )?;
        }
        let cancel = self.cancel_path.as_ref().is_some_and(|p| p.exists())
            && matches!(&action,Action::Feature{phase,..} if phase=="preflight" || phase.starts_with("edit-"));
        let mut reason = cancel
            .then(|| "button edit canceled; original restoration remains permitted".to_string());
        if reason.is_none()
            && let Action::Save { name, bytes } = &action
        {
            if let Err(e) = save(&self.directory.join(name), bytes) {
                reason = Some(e);
            } else {
                self.saved.insert(name.clone(), sha256(bytes));
            }
        }
        let permit = reason.is_none();
        crate::query_session::journal(
            &mut self.log,
            "button_grant",
            &serde_json::json!({"number":number,"permit":permit,"reason":reason}),
        )?;
        if permit {
            if matches!(action, Action::Bind { .. }) {
                self.bound_granted = true;
            }
            if let Action::Feature { kind, frame, .. } = &action {
                self.feature_grants += 1;
                if *kind == CallKind::Set && frame[1] == 0x2f {
                    self.program_grants += 1;
                }
            }
        }
        send(
            &mut self.input,
            &Grant {
                number,
                permit,
                reason: reason.clone(),
            },
        )?;
        let Event::Completed {
            number: completed,
            reply,
        } = self.receive()?
        else {
            return Err("button worker omitted completion".into());
        };
        if completed != number || (reason.is_some() && reply != Reply::Denied(reason.unwrap())) {
            return Err("button completion or denial differs".into());
        }
        crate::query_session::journal(
            &mut self.log,
            "button_completion",
            &serde_json::json!({"number":number,"reply":reply}),
        )?;
        self.number += 1;
        self.cached()?;
        Ok(reply)
    }
    pub fn bind(&mut self) -> Result<(), String> {
        match self.perform(Action::Bind {
            binding: Box::new(self.binding.clone()),
        })? {
            Reply::Bound(b) if *b == self.binding => Ok(()),
            _ => Err("button native bind failed".into()),
        }
    }
    pub fn finish(&mut self, state: &State) -> bool {
        if self.poisoned {
            return false;
        }
        if !matches!(self.receive(),Ok(Event::Done{number,state:worker}) if number==self.number && worker==*state)
        {
            return false;
        }
        if self.cached().is_err() {
            return false;
        }
        if crate::query_session::journal(
            &mut self.log,
            "button_done",
            &serde_json::json!({"number":self.number,"state":state}),
        )
        .is_err()
            || crate::query_session::journal(
                &mut self.log,
                "button_release",
                &serde_json::json!({"number":self.number,"release_after_done":true}),
            )
            .is_err()
        {
            return false;
        }
        send(
            &mut self.input,
            &Release {
                number: self.number,
                release_after_done: true,
            },
        )
        .is_ok()
    }
}
impl Link for Remote<'_> {
    fn validate(&mut self) -> Result<(), String> {
        self.cached()
    }
    fn call(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion {
        feature(self.perform(Action::Feature {
            phase: phase.into(),
            kind,
            frame: frame.to_vec(),
        }))
    }
    fn save(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        saved(self.perform(Action::Save {
            name: name.into(),
            bytes: bytes.to_vec(),
        }))
    }
    fn settle(&mut self) -> Result<(), String> {
        saved(self.perform(Action::Settle { milliseconds: 500 }))
    }
    fn observe(&mut self, phase: &str) -> Result<(), String> {
        saved(self.perform(Action::Observe {
            phase: phase.into(),
        }))
    }
}
