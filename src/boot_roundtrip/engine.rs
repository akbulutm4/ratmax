use super::{Fault, Mode, Reference, connection};
use crate::{
    access_job::{CallKind, Completion, key_frame, read_frame},
    boot_bank,
    boot_roundtrip::connection::DeviceBinding,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
mod pipeline;
mod workflow;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(super) enum Action {
    Connect {
        mode: Mode,
        previous: Option<Box<DeviceBinding>>,
    },
    Feature {
        mode: Mode,
        phase: String,
        kind: CallKind,
        frame: Vec<u8>,
    },
    Observe {
        mode: Mode,
        phase: String,
        seconds: u16,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "reply", content = "value", rename_all = "snake_case")]
pub(super) enum Answer {
    Connected(Box<DeviceBinding>),
    Feature(Completion),
    ResetAttempt {
        acknowledged: bool,
        error: Option<String>,
    },
    Observed,
}

pub(super) trait Link {
    fn perform(&mut self, action: &Action) -> Result<Answer, Fault>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct State {
    pub phase: String,
    pub feature_calls: u32,
    pub marker_program_intents: u8,
    pub reset_intents: u8,
    pub reset_acknowledgments: u8,
    pub reset_errors: Vec<String>,
    pub mode: Option<Mode>,
    pub gate_dirty: bool,
    pub gate_close_requested: bool,
    pub marker_dirty: bool,
    pub identity_verified: bool,
    pub neighbors_verified: bool,
    pub normal_verified: bool,
    pub snapshots_verified: bool,
    pub returned: bool,
    pub complete: bool,
    pub recovered: bool,
    pub uncertain: bool,
    pub release_lock_allowed: bool,
    pub failure: Option<String>,
    pub cleanup_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<super::pipeline::Verification>,
}

pub(super) struct Session<'a, T: Link> {
    reference: &'a Reference,
    link: T,
    output: Option<&'a Path>,
    binding: Option<DeviceBinding>,
    pipeline_plan: Option<&'a super::pipeline::Plan>,
    pipeline_recovery: Option<Mode>,
    pipeline_full_read: bool,
    workflow_main_end: usize,
    pub state: State,
}

impl<'a, T: Link> Session<'a, T> {
    pub fn new(reference: &'a Reference, link: T, output: Option<&'a Path>) -> Self {
        Self {
            reference,
            link,
            output,
            binding: None,
            pipeline_plan: None,
            pipeline_recovery: None,
            pipeline_full_read: false,
            workflow_main_end: 0xe700,
            state: State::default(),
        }
    }

    pub fn execute(mut self) -> (State, T) {
        if let Err(failure) = self.pipeline_run() {
            self.state.failure = Some(failure.message);
            self.state.uncertain |= failure.uncertain;
            if !self.state.uncertain
                && self.state.gate_dirty
                && let Err(cleanup) = self.close_gate()
            {
                self.state.uncertain |= cleanup.uncertain;
                self.state.cleanup_failure = Some(cleanup.message);
            }
        }
        self.state.release_lock_allowed = (self.pipeline_plan.is_none()
            || self.state.complete
            || (self.state.marker_program_intents == 0
                && self.state.pipeline.as_ref().is_some_and(|p| {
                    p.forward_records == 0
                        && p.restore_records == 0
                        && p.configuration_programs == 0
                        && p.runtime_programs == 0
                })))
            && !self.state.uncertain
            && !self.state.gate_dirty
            && !self.state.marker_dirty
            && (self.state.marker_program_intents == 0
                || (self.state.mode == Some(Mode::Normal)
                    && self.state.normal_verified
                    && self.state.snapshots_verified)
                || (matches!(self.state.mode, Some(Mode::Target(_))) && self.state.complete));
        (self.state, self.link)
    }

    fn save(&self, name: &str, data: &[u8]) -> Result<(), Fault> {
        if let Some(output) = self.output {
            super::executor::save(&output.join(name), data).map_err(Fault::uncertain)?;
        }
        Ok(())
    }

    fn connect(&mut self, mode: Mode) -> Result<(), Fault> {
        self.state.phase = format!("connect-{mode:?}");
        let previous = self.binding.clone();
        self.state.mode = None;
        self.state.identity_verified = false;
        self.state.neighbors_verified = false;
        self.state.normal_verified = false;
        let answer = self.link.perform(&Action::Connect {
            mode,
            previous: previous.clone().map(Box::new),
        })?;
        let Answer::Connected(binding) = answer else {
            return Err(Fault::uncertain("connect returned a feature result"));
        };
        connection::validate_connection(mode, &binding, self.reference.baseline.binding())?;
        let inspecting_original_normal = mode == Mode::Normal
            && self.state.marker_dirty
            && self.state.marker_program_intents == 1
            && self.state.reset_intents == 1
            && previous.as_ref().is_some_and(|old| {
                old.product_id() == self.reference.baseline.binding().product_id
            });
        if previous.as_ref() == Some(binding.as_ref()) && !inspecting_original_normal {
            return Err(Fault::uncertain(
                "mode transition reused the previous binding",
            ));
        }
        self.binding = Some(*binding);
        self.state.mode = Some(mode);
        self.state.identity_verified = false;
        self.state.neighbors_verified = false;
        self.state.normal_verified = false;
        Ok(())
    }

    fn exchange(&mut self, phase: &str, kind: CallKind, frame: &[u8]) -> Result<Completion, Fault> {
        if self.state.uncertain
            || self.state.feature_calls >= super::pipeline::MAX_CALLS
            || frame.len() != 64
        {
            return Err(Fault::uncertain(
                "round-trip uncertainty or feature-call bound",
            ));
        }
        let mode = self
            .state
            .mode
            .ok_or_else(|| Fault::uncertain("feature call without a binding"))?;
        self.state.phase = phase.into();
        self.state.feature_calls += 1;
        if kind == CallKind::Set && frame[1] == 0x25 {
            if frame[8..12] != [0; 4] {
                self.state.gate_dirty = true;
                self.state.gate_close_requested = false;
            } else {
                self.state.gate_close_requested = true;
            }
        }
        let answer = self.link.perform(&Action::Feature {
            mode,
            phase: phase.into(),
            kind,
            frame: frame.to_vec(),
        });
        let result = match answer {
            Ok(Answer::ResetAttempt {
                acknowledged,
                error,
            }) if kind == CallKind::Set && frame[1] == 0 => {
                self.state.reset_acknowledgments += u8::from(acknowledged);
                if let Some(error) = error {
                    self.state.reset_errors.push(error);
                }
                Ok(Completion::SetComplete)
            }
            Ok(Answer::Feature(Completion::SetComplete))
                if kind == CallKind::Set && frame[1] != 0 =>
            {
                Ok(Completion::SetComplete)
            }
            Ok(Answer::Feature(Completion::GetComplete(raw))) if kind == CallKind::Get => {
                Ok(Completion::GetComplete(raw))
            }
            Ok(Answer::Feature(Completion::CompletedFailure(message))) => {
                Err(Fault::known(message))
            }
            Ok(Answer::Feature(Completion::Uncertain(message))) => Err(Fault::uncertain(message)),
            Err(failure) => Err(failure),
            _ => Err(Fault::uncertain(
                "feature completion differs from the granted action",
            )),
        };
        if let Err(failure) = &result {
            self.state.uncertain |= failure.uncertain;
        }
        result
    }

    fn set(&mut self, phase: &str, frame: &[u8]) -> Result<(), Fault> {
        self.exchange(phase, CallKind::Set, frame)?;
        Ok(())
    }

    fn pair(&mut self, phase: &str, frame: &[u8]) -> Result<Vec<u8>, Fault> {
        self.set(phase, frame)?;
        match self.exchange(phase, CallKind::Get, frame)? {
            Completion::GetComplete(raw) if raw.len() == 64 => Ok(raw),
            _ => Err(Fault::known("reply must contain exactly 64 bytes")),
        }
    }

    fn memory(&mut self, label: &str, address: u32, seed: u8) -> Result<Vec<u8>, Fault> {
        let mut request = read_frame(2, address, 8);
        request[32..].fill(seed);
        let raw = self.pair(label, &request)?;
        if raw[..32] != request[..32] {
            return Err(Fault::known("addressed reply changed its selector"));
        }
        Ok(raw)
    }

    fn close_gate(&mut self) -> Result<(), Fault> {
        if !self.state.gate_close_requested {
            self.set("close-gate", &key_frame(0))?;
        }
        let request = read_frame(2, 0xfec0, 8);
        if self.pair("verify-closed", &request)? != request {
            return Err(Fault::known(
                "closed gate did not return the exact FEC0 selector echo",
            ));
        }
        self.state.gate_dirty = false;
        Ok(())
    }

    fn reset(&mut self, next: Mode) -> Result<(), Fault> {
        if self.state.gate_dirty
            || !self.state.neighbors_verified
            || self.state.reset_intents >= 4
            || (matches!(next, Mode::Normal | Mode::Target(_)) && self.state.marker_dirty)
        {
            return Err(Fault::known(
                "reset requires a verified marker and closed gate",
            ));
        }
        let mut frame = [0; 64];
        frame[0] = 7;
        self.state.reset_intents += 1;
        self.set("reset", &frame)?;
        self.connect(next)
    }

    fn normal_identity(&mut self) -> Result<(), Fault> {
        let expected = [
            (0x1f, self.reference.baseline.identity.clone()),
            (0x2d, self.reference.baseline.status.clone()),
            (5, self.reference.baseline.layout.clone()),
        ];
        for (opcode, reply) in expected {
            let mut frame = [0; 64];
            frame[..2].copy_from_slice(&[7, opcode]);
            if self.pair("recovery-normal-identity", &frame)? != reply {
                return Err(Fault::known(
                    "normal-mode rollback identity differs from the original",
                ));
            }
        }
        self.state.identity_verified = true;
        Ok(())
    }
}
