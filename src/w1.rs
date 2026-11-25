//! Fixed W95 Max CPI edit-and-restore job. Native entry points are build gated.
#[cfg(all(target_os = "linux", feature = "linux-query"))]
use crate::{
    access_job::{AccessJob, CaptureScope},
    settings_cycle::Candidate,
};
use std::path::Path;

const PHYSICAL_W1_RELEASED: bool = false;

pub fn available() -> bool {
    PHYSICAL_W1_RELEASED && crate::query_session::live_available()
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
fn check_candidate(c: &Candidate) -> Result<(), String> {
    if c.selected_slot != 0
        || c.original.len() != 256
        || c.target.len() != 256
        || c.original[32..] != c.target[32..]
    {
        return Err("W1 requires a slot-0 256-byte CPI candidate preserving trailing bytes".into());
    }
    AccessJob::with_scope(c.baseline.clone(), CaptureScope::SettingsRecovery)?;
    Ok(())
}

pub fn run(project: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical W1 is disabled in this build".into());
    }
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg("__w1-worker")
        .arg(project)
        .arg(output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            if !status.success() {
                let mut detail = String::new();
                if let Some(stderr) = child.stderr.take() {
                    let _ = stderr.take(4096).read_to_string(&mut detail);
                }
                return Err(format!("W1 worker exited {status}. {}", detail.trim()));
            }
            let bytes = std::fs::read(output.join("session.json")).map_err(|e| e.to_string())?;
            return serde_json::from_slice(&bytes).map_err(|e| e.to_string());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            for _ in 0..100 {
                if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                    return Err("W1 deadline expired; worker stopped with state uncertain".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            return Err("W1 deadline expired; worker cancellation is unverified".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn worker(project: &Path, output: &Path) -> Result<(), String> {
    if !available() {
        return Err("physical W1 is disabled in this build".into());
    }
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    return job::native(project, output);
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        let _ = (project, output);
        Err("native W1 unavailable".into())
    }
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
mod job {
    use crate::{
        access_job::{AccessBaseline, AccessJob, CallKind, CaptureScope, Completion, Phase},
        query_session::journal,
        settings_cycle::{Candidate, Pages, apply_fields},
        transport::LocalFeatureTransport,
        w1::check_candidate,
    };
    use serde::Serialize;
    use serde_json::json;
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        path::Path,
        time::Duration,
    };

    const MAX_CALLS: u32 = 554;
    const SETTING_BYTES: usize = 256;

    #[derive(Default, Serialize)]
    struct ResultState {
        calls: u32,
        program_intents: u8,
        apply_intents: u8,
        quiesced: bool,
        resume_attempted: bool,
        gate_closed: bool,
        uncertain: bool,
        edited: bool,
        restored: bool,
        failure: Option<String>,
        cleanup_failure: Option<String>,
    }

    struct Session<'a> {
        transport: &'a mut dyn LocalFeatureTransport,
        check_binding: &'a mut dyn FnMut() -> Result<(), String>,
        baseline: &'a AccessBaseline,
        output: &'a Path,
        log: &'a mut File,
        settle: Duration,
        state: ResultState,
    }

    fn frame(opcode: u8) -> [u8; 64] {
        let mut r = [0; 64];
        r[..2].copy_from_slice(&[7, opcode]);
        r
    }

    fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| {
                f.write_all(bytes)?;
                f.sync_all()
            })
            .map_err(|e| e.to_string())
    }

    impl Session<'_> {
        fn exchange(
            &mut self,
            label: &str,
            kind: CallKind,
            frame: &[u8],
        ) -> Result<Completion, String> {
            if self.state.uncertain || self.state.calls >= MAX_CALLS {
                return Err("W1 call budget or completion is uncertain".into());
            }
            let result = (|| {
                (self.check_binding)()?;
                journal(
                    self.log,
                    "w1_intent",
                    &json!({"phase":label, "number":self.state.calls, "kind":kind, "frame":frame}),
                )?;
                self.state.calls += 1;
                let completion = match kind {
                    CallKind::Set => self
                        .transport
                        .set_local(frame)
                        .map(|()| Completion::SetComplete),
                    CallKind::Get => self.transport.get_local(7, 64).map(Completion::GetComplete),
                };
                journal(
                    self.log,
                    "w1_completion",
                    &json!({"number":self.state.calls-1, "result":completion.as_ref().ok(), "error":completion.as_ref().err()}),
                )?;
                (self.check_binding)()?;
                completion.map_err(|e| e.to_string())
            })();
            if result.is_err() {
                self.state.uncertain = true;
            }
            result
        }

        fn set(&mut self, phase: &str, frame: &[u8; 64]) -> Result<(), String> {
            self.exchange(phase, CallKind::Set, frame)?;
            Ok(())
        }

        fn capture(&mut self, label: &str) -> Result<Pages, String> {
            let mut job =
                AccessJob::with_scope(self.baseline.clone(), CaptureScope::SettingsRecovery)?;
            let previously_closed = self.state.gate_closed;
            let mut attempted_closed_probe = false;
            self.state.gate_closed = false;
            while let Some(step) = job.next_step() {
                attempted_closed_probe |= step.phase == Phase::PreClosed;
                job.begin(&step)?;
                let result = self.exchange(label, step.kind, &step.frame)?;
                job.finish(step.number, result, true)?;
            }
            let result = job.summary();
            self.state.gate_closed = result.gate == crate::access_job::Gate::ClosedObserved
                || (previously_closed && !attempted_closed_probe);
            journal(
                self.log,
                "w1_capture",
                &json!({"label":label, "result":result}),
            )?;
            for (i, data) in job.images().into_iter().enumerate() {
                if !data.is_empty() {
                    save(&self.output.join(format!("{label}.pass{i}.bin")), data)?;
                }
            }
            if !result.complete {
                return Err(format!(
                    "{label} readback incomplete: {:?}",
                    result.primary_failure
                ));
            }
            job.images()[0]
                .try_into()
                .map_err(|_| format!("{label} has the wrong extent"))
        }

        fn verify(&mut self, label: &str, expected: &Pages) -> Result<(), String> {
            let current = self.capture(label)?;
            if &current != expected {
                return Err(format!(
                    "{label} differs from the expected full settings and saved-state bytes"
                ));
            }
            Ok(())
        }

        fn processing(&mut self, quiesce: bool) -> Result<(), String> {
            let phase = if quiesce { "quiesce" } else { "resume" };
            self.state.resume_attempted = !quiesce;
            self.state.quiesced = true;
            let mut r = frame(0x20);
            r[7] = u8::from(quiesce);
            self.set(phase, &r)?;
            let Completion::GetComplete(raw) = self.exchange(phase, CallKind::Get, &r)? else {
                return Err("processing state read did not return data".into());
            };
            if raw != r {
                return Err(format!(
                    "{phase} did not return the expected zero status and selector"
                ));
            }
            self.state.quiesced = quiesce;
            Ok(())
        }

        fn program(&mut self, phase: &str, data: &[u8]) -> Result<(), String> {
            if !self.state.quiesced
                || !self.state.gate_closed
                || self.state.program_intents >= 4
                || !matches!(data.len(), 4 | 32)
            {
                return Err(
                    "W1 program requires a quiesced, verified gate state and bounded payload"
                        .into(),
                );
            }
            let mut r = frame(0x2f);
            r[2] = 1;
            r[24] = (data.len() / 4) as u8;
            r[28..32].copy_from_slice(&0xe000u32.to_le_bytes());
            r[32..32 + data.len()].copy_from_slice(data);
            self.state.program_intents += 1;
            self.set(phase, &r)
        }

        fn leg(&mut self, prefix: &str, start: &Pages, goal: &Pages) -> Result<(), String> {
            self.processing(true)?;
            self.verify(&format!("{prefix}-quiesced"), start)?;
            let mut staged = *goal;
            staged[..4].fill(0xff);
            self.program(&format!("{prefix}-stage-write"), &staged[..32])?;
            self.verify(&format!("{prefix}-staged"), &staged)?;
            self.program(&format!("{prefix}-marker-write"), &goal[..4])?;
            self.verify(&format!("{prefix}-committed"), goal)?;
            let mut apply = frame(0x0d);
            apply[8..16].copy_from_slice(&apply_fields(goal, 0x10));
            self.state.apply_intents += 1;
            self.set(&format!("{prefix}-apply"), &apply)?;
            self.processing(false)?;
            std::thread::sleep(self.settle);
            self.verify(&format!("{prefix}-final"), goal)
        }

        fn run(&mut self, c: &Candidate) -> Result<(), String> {
            let original = self.capture("initial")?;
            if original
                .iter()
                .zip(&c.original)
                .enumerate()
                .any(|(i, (a, b))| i != 261 && a != b)
            {
                return Err(
                    "fresh settings or saved-state bytes differ from the reviewed original".into(),
                );
            }
            let mut target = original;
            target[..SETTING_BYTES].copy_from_slice(&c.target[..SETTING_BYTES]);
            save(&self.output.join("original.bin"), &original)?;
            save(&self.output.join("target.bin"), &target)?;
            File::open(self.output)
                .and_then(|d| d.sync_all())
                .map_err(|e| e.to_string())?;
            self.leg("edit", &original, &target)?;
            self.state.edited = true;
            self.leg("restore", &target, &original)?;
            self.state.restored = true;
            Ok(())
        }

        fn finish(&mut self, c: &Candidate) {
            if let Err(e) = self.run(c) {
                self.state.failure = Some(e);
                if self.state.quiesced
                    && !self.state.resume_attempted
                    && self.state.gate_closed
                    && !self.state.uncertain
                    && let Err(e) = self.processing(false)
                {
                    self.state.cleanup_failure = Some(e);
                }
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    pub(super) fn native(project: &Path, output: &Path) -> Result<(), String> {
        use crate::{
            access_session::create_output, discovery, query_session, settings_cycle::load_candidate,
        };
        let candidate = load_candidate(project)?;
        check_candidate(&candidate)?;
        let output = create_output(output)?;
        let mut log = File::create(output.join("journal.jsonl")).map_err(|e| e.to_string())?;
        let lock = query_session::lock_path();
        query_session::acquire_lock(&lock)?;
        let binding = candidate.baseline.binding();
        let snapshot = || discovery::collect(Path::new("/sys"));
        let prepare = (|| {
            let before = snapshot()?;
            before.save(&output.join("before"))?;
            binding.revalidate(&before)?;
            query_session::open_access_transport(binding)
        })();
        let mut transport = match prepare {
            Ok(t) => t,
            Err(e) => {
                std::fs::remove_dir(&lock).map_err(|e| e.to_string())?;
                return Err(e);
            }
        };
        let mut session = Session {
            transport: &mut transport,
            check_binding: &mut || binding.revalidate(&snapshot()?),
            baseline: &candidate.baseline,
            output: &output,
            log: &mut log,
            settle: Duration::from_millis(500),
            state: ResultState::default(),
        };
        session.finish(&candidate);
        let state = &mut session.state;
        if let Err(e) = (|| {
            let after = snapshot()?;
            after.save(&output.join("after"))?;
            binding.revalidate(&after)
        })() {
            state.uncertain = true;
            state.cleanup_failure = Some(e);
        }
        let release = state.gate_closed
            && !state.quiesced
            && !state.uncertain
            && (state.restored || state.program_intents == 0);
        let report = json!({"mode":"native_w1_cpi_edit_restore", "baseline":candidate.baseline,
            "result":state, "complete":state.restored && release, "release_lock_allowed":release,
            "runtime_cpi_measured":false});
        let mut bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        save(&output.join("session.json"), &bytes)?;
        if release {
            std::fs::remove_dir(&lock).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
