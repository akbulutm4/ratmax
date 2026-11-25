use super::{Fault, MAX_FEATURE_CALLS, Mode, Reference, connection};
use crate::{
    access_job::{AccessJob, CallKind, CaptureScope, Completion, Gate, key_frame, read_frame},
    boot_bank,
    boot_roundtrip::connection::DeviceBinding,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
mod backup;
mod entry_return;
mod firmware;
mod pipeline;
mod restore;
mod target_return;
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
    pub firmware: Option<crate::prepared::engine::State>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_verification: Option<firmware::Verification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<backup::Verification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<restore::Verification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_return: Option<entry_return::Verification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_bridge: Option<target_return::Verification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<super::pipeline::Verification>,
}

pub(super) struct Session<'a, T: Link> {
    reference: &'a Reference,
    link: T,
    output: Option<&'a Path>,
    binding: Option<DeviceBinding>,
    initial: Option<Vec<u8>>,
    firmware_plan: Option<&'a crate::prepared::Plan>,
    restore_plan: Option<&'a crate::backup_restore::Plan>,
    restore_from_normal: bool,
    restore_probe: bool,
    entry_return_proof: Option<(&'a super::entry_return::Proof, Mode)>,
    target_bridge: Option<(&'a super::target_return::Proof, Option<Mode>)>,
    normal_backup: bool,
    gate_close_only: bool,
    pipeline_plan: Option<&'a super::pipeline::Plan>,
    pipeline_recovery: Option<Mode>,
    pipeline_full_read: bool,
    workflow_main_end: usize,
    firmware_captures: std::collections::BTreeMap<String, Vec<u8>>,
    pub state: State,
}

impl<'a, T: Link> Session<'a, T> {
    pub fn new(reference: &'a Reference, link: T, output: Option<&'a Path>) -> Self {
        Self {
            reference,
            link,
            output,
            binding: None,
            initial: None,
            firmware_plan: None,
            restore_plan: None,
            restore_from_normal: false,
            restore_probe: false,
            entry_return_proof: None,
            target_bridge: None,
            normal_backup: false,
            gate_close_only: false,
            pipeline_plan: None,
            pipeline_recovery: None,
            pipeline_full_read: false,
            workflow_main_end: 0xe700,
            firmware_captures: std::collections::BTreeMap::new(),
            state: State::default(),
        }
    }

    pub fn execute(mut self) -> (State, T) {
        if let Err(failure) = self.nominal() {
            self.state.failure = Some(failure.message);
            self.state.uncertain |=
                failure.uncertain || (self.gate_close_only && !self.state.identity_verified);
            if !self.state.uncertain
                && let Err(cleanup) = self.cleanup()
            {
                self.state.uncertain |= cleanup.uncertain;
                self.state.cleanup_failure = Some(cleanup.message);
                if !self.state.uncertain
                    && self.state.gate_dirty
                    && let Err(closure) = self.close_gate()
                {
                    self.state.uncertain |= closure.uncertain;
                    self.state.cleanup_failure = Some(format!(
                        "{}. Gate closure failed. {}",
                        self.state
                            .cleanup_failure
                            .as_deref()
                            .unwrap_or("Cleanup failed"),
                        closure.message
                    ));
                }
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
            && (self.entry_return_proof.is_none() || self.state.complete)
            && self
                .target_bridge
                .is_none_or(|(_, cleanup)| cleanup.is_none() || self.state.complete)
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
            || self.state.feature_calls
                >= if self.pipeline_plan.is_some() {
                    super::pipeline::MAX_CALLS
                } else if self.gate_close_only {
                    32
                } else if self.target_bridge.is_some() {
                    super::target_return::MAX_CALLS
                } else if self.entry_return_proof.is_some() {
                    96
                } else if self.normal_backup {
                    10_000
                } else if self.restore_plan.is_some() {
                    if self.restore_from_normal {
                        crate::backup_restore::NORMAL_ENTRY_MAX_FEATURE_CALLS
                    } else {
                        crate::backup_restore::MAX_FEATURE_CALLS
                    }
                } else if self.firmware_plan.is_some() {
                    super::FIRMWARE_MAX_FEATURE_CALLS
                } else {
                    MAX_FEATURE_CALLS
                }
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
                // The syscall has returned. Only passive mode discovery follows this outcome.
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

    fn capture(&mut self, label: &str) -> Result<Vec<u8>, Fault> {
        let mut job =
            AccessJob::with_scope(self.reference.baseline.clone(), CaptureScope::BootBank)?;
        while let Some(step) = job.next_step() {
            job.begin(&step)?;
            let completion = match self.exchange(label, step.kind, &step.frame) {
                Ok(completion) => completion,
                Err(failure) if !failure.uncertain => Completion::CompletedFailure(failure.message),
                Err(failure) => return Err(failure),
            };
            job.finish(step.number, completion, true)?;
        }
        let summary = job.summary();
        if summary.gate == Gate::ClosedObserved {
            self.state.gate_dirty = false;
        }
        for (pass, bytes) in job.images().iter().enumerate() {
            self.save(&format!("{label}.pass{pass}.bin"), bytes)?;
        }
        if !summary.complete {
            return Err(Fault {
                message: summary
                    .primary_failure
                    .unwrap_or_else(|| "normal capture incomplete".into()),
                uncertain: summary.uncertain,
            });
        }
        let packed = job.images()[0].to_vec();
        if !boot_bank::matches_known_bank(&packed[..boot_bank::BANK_BYTES])
            || !boot_bank::compare(&packed)
                .is_some_and(|comparison| comparison.matches_embedded_copy_and_identity)
        {
            return Err(Fault::known(
                "fresh boot bank or identity differs from the supported copy",
            ));
        }
        self.state.normal_verified = true;
        self.state.identity_verified = true;
        self.state.neighbors_verified = true;
        Ok(packed)
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

    fn page(&mut self, label: &str) -> Result<Vec<u8>, Fault> {
        let request = read_frame(2, 0xfec0, 8);
        if self.pair("pre-closed", &request)? != request {
            return Err(Fault::known(
                "page capture requires the closed FEC0 witness",
            ));
        }
        self.set("enable-gate", &key_frame(0x22184952))?;
        let raw = self.memory("open-metadata", 0xfec0, 0)?;
        let metadata = self
            .target_bridge
            .map(|(proof, _)| &proof.page()[..32])
            .unwrap_or(&self.reference.baseline.status[8..40]);
        if raw[32..] != *metadata {
            return Err(Fault::known(
                "page capture metadata differs from the original device",
            ));
        }
        let mut passes = [Vec::new(), Vec::new()];
        for (pass, data) in passes.iter_mut().enumerate() {
            for address in [0xfec0, 0xfee0] {
                let raw = self.memory(label, address, [0xa5, 0x5a][pass])?;
                data.extend_from_slice(&raw[32..]);
            }
            self.save(&format!("{label}.pass{pass}.bin"), data)?;
        }
        self.close_gate()?;
        if passes[0] != passes[1] {
            return Err(Fault::known("identity page passes disagree"));
        }
        let original = self.original_page();
        self.state.neighbors_verified = passes[0][..60] == original[..60];
        if !self.state.neighbors_verified {
            return Err(Fault::known(
                "FEFC program changed neighboring identity bytes",
            ));
        }
        Ok(passes[0].clone())
    }

    fn original_page(&self) -> &[u8] {
        if let Some((proof, _)) = self.target_bridge {
            return proof.page();
        }
        let packed = self.initial.as_deref().unwrap_or(&self.reference.packed);
        &packed[boot_bank::IDENTITY_OFFSET..boot_bank::IDENTITY_OFFSET + 64]
    }

    fn program(&mut self, restore: bool) -> Result<(), Fault> {
        if !self.state.identity_verified
            || !self.state.neighbors_verified
            || self.state.gate_dirty
            || self.state.marker_program_intents >= 2
            || (restore && self.state.marker_program_intents != 1)
        {
            return Err(Fault::known(
                "marker program requires verified identity, neighbors and a closed gate",
            ));
        }
        let mut frame = [0; 64];
        frame[..3].copy_from_slice(&[7, 0x28, 1]);
        if restore {
            frame[8..12].copy_from_slice(&self.original_page()[60..64]);
        }
        self.state.marker_program_intents += 1;
        self.state.marker_dirty = true;
        self.state.normal_verified = false;
        self.state.snapshots_verified = false;
        self.state.neighbors_verified = false;
        self.set(
            if restore {
                "restore-marker"
            } else {
                "entry-marker"
            },
            &frame,
        )
    }

    fn reset(&mut self, next: Mode) -> Result<(), Fault> {
        if self.state.gate_dirty
            || !self.state.neighbors_verified
            || self.state.reset_intents >= if self.pipeline_plan.is_some() { 4 } else { 2 }
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

    fn boot_identity(&mut self) -> Result<(), Fault> {
        let initial = self
            .initial
            .as_deref()
            .ok_or_else(|| Fault::known("missing initial snapshot"))?
            .to_vec();
        let identity = &initial[boot_bank::IDENTITY_OFFSET..boot_bank::SETTINGS_OFFSET];
        for (opcode, expected) in [
            (0x2c, &identity[64..96]),
            (0x2d, &identity[..32]),
            (0x2b, &identity[32..60]),
        ] {
            let mut frame = [0; 64];
            frame[..2].copy_from_slice(&[7, opcode]);
            frame[8..].fill(0xa5);
            let raw = self.pair("boot-identity", &frame)?;
            let mut expected_frame = frame;
            expected_frame[8..8 + expected.len()].copy_from_slice(expected);
            if raw != expected_frame {
                return Err(Fault::known(
                    "boot model or identity block differs from the original device",
                ));
            }
        }
        self.state.identity_verified = true;
        self.state.neighbors_verified = true;
        Ok(())
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

    fn restore(&mut self) -> Result<(), Fault> {
        self.program(true)?;
        let page = self.page("restored-page")?;
        if page != self.original_page() {
            return Err(Fault::known("restored FEFC page differs from the original"));
        }
        self.state.marker_dirty = false;
        Ok(())
    }

    fn verify_return(&mut self, label: &str) -> Result<(), Fault> {
        let returned = self.capture(label)?;
        if Some(returned.as_slice()) != self.initial.as_deref() {
            return Err(Fault::known(
                "returned bank, identity or settings differ from the initial snapshot",
            ));
        }
        self.state.returned = self.state.reset_intents != 0;
        self.state.normal_verified = true;
        self.state.snapshots_verified = true;
        Ok(())
    }

    fn nominal(&mut self) -> Result<(), Fault> {
        if self.pipeline_plan.is_some() {
            return self.pipeline_run();
        }
        if self.target_bridge.is_some() {
            return self.target_bridge_run();
        }
        if self.entry_return_proof.is_some() {
            return self.return_before_records();
        }
        if self.restore_plan.is_some() {
            return self.restore_backup();
        }
        self.connect(Mode::Normal)?;
        if self.gate_close_only {
            self.normal_identity()?;
            self.state.gate_dirty = true;
            self.close_gate()?;
            self.normal_identity()?;
            self.state.normal_verified = true;
            self.state.complete = true;
            return Ok(());
        }
        let initial = self.capture("initial")?;
        if initial[boot_bank::SETTINGS_OFFSET..boot_bank::SETTINGS_OFFSET + 256]
            != self.reference.packed[boot_bank::SETTINGS_OFFSET..boot_bank::SETTINGS_OFFSET + 256]
        {
            return Err(Fault::known(
                "current settings differ from the reviewed reference",
            ));
        }
        self.initial = Some(initial);
        if self.normal_backup {
            return self.backup_normal();
        }
        self.program(false)?;
        let page = self.page("entry-page")?;
        if page[60..] != [0; 4] {
            return Err(Fault::known("entry word was not programmed as requested"));
        }
        self.reset(Mode::Boot)?;
        self.boot_identity()?;
        let page = self.page("boot-entry-page")?;
        if page[60..] != [0; 4] {
            return Err(Fault::known(
                "boot entry marker differs from the normal-mode witness",
            ));
        }
        if self.firmware_plan.is_some() {
            return self.replay_and_return();
        }
        self.restore()?;
        self.reset(Mode::Normal)?;
        self.verify_return("returned")?;
        self.state.complete = true;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Fault> {
        if self.pipeline_plan.is_some() {
            if self.state.gate_dirty {
                self.close_gate()?;
            }
            return Ok(());
        }
        if self.target_bridge.is_some() {
            if self.state.gate_dirty {
                self.close_gate()?;
            }
            return Ok(());
        }
        if self.entry_return_proof.is_some() {
            if self.state.gate_dirty {
                self.close_gate()?;
            }
            return Ok(());
        }
        if self.restore_plan.is_some() {
            // A partial application must remain in boot mode; no marker-only
            // rollback and no reset. A new attempt starts the whole image again.
            if self.state.gate_dirty {
                self.close_gate()?;
            }
            return Ok(());
        }
        if self
            .state
            .firmware
            .as_ref()
            .is_some_and(|state| state.record_intents != 0)
        {
            // Application bytes may have changed. Marker-only rollback is no
            // longer recovery; never program/reset automatically in this case.
            if self.state.gate_dirty {
                self.close_gate()?;
            }
            return Ok(());
        }
        if self.state.gate_dirty {
            self.close_gate()?;
        }
        if !self.state.marker_dirty {
            if self.state.marker_program_intents != 0
                && self.state.mode == Some(Mode::Normal)
                && !self.state.snapshots_verified
            {
                self.verify_return("recovery-returned")?;
                self.state.recovered = true;
            }
            return Ok(());
        }
        if self.state.mode.is_none()
            && self.state.marker_program_intents == 1
            && self.state.reset_intents == 1
            && self
                .binding
                .as_ref()
                .is_some_and(|old| old.product_id() == self.reference.baseline.binding().product_id)
        {
            self.connect(Mode::Normal)?;
            self.normal_identity()?;
        }
        if self.state.identity_verified && self.state.marker_program_intents == 2 {
            let page = self.page("recovery-page");
            let page = match page {
                Ok(page) => page,
                Err(failure) => {
                    if !failure.uncertain && self.state.gate_dirty {
                        self.close_gate()?;
                    }
                    return Err(failure);
                }
            };
            if page != self.original_page() {
                return Err(Fault::known(
                    "recovery read did not verify the restored marker page",
                ));
            }
            self.state.marker_dirty = false;
            if self.state.mode == Some(Mode::Boot) {
                self.reset(Mode::Normal)?;
            }
            self.verify_return("recovery-returned")?;
            self.state.recovered = true;
            return Ok(());
        }
        if self.state.identity_verified
            && !self.state.neighbors_verified
            && self.state.marker_program_intents == 1
            && let Err(failure) = self.page("recovery-page")
        {
            if !failure.uncertain && self.state.gate_dirty {
                self.close_gate()?;
            }
            return Err(failure);
        }
        if !self.state.identity_verified
            || !self.state.neighbors_verified
            || self.state.marker_program_intents != 1
        {
            return Err(Fault::known(
                "marker restoration needs verified identity and intact neighbors",
            ));
        }
        self.restore()?;
        if self.state.mode == Some(Mode::Boot) {
            self.reset(Mode::Normal)?;
        }
        self.verify_return("recovery-returned")?;
        self.state.recovered = true;
        Ok(())
    }
}

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_gate_close(
        reference: &'a Reference,
        link: T,
        output: Option<&'a Path>,
    ) -> Self {
        let mut session = Self::new(reference, link, output);
        session.gate_close_only = true;
        session.state.gate_dirty = true;
        session
    }
}
