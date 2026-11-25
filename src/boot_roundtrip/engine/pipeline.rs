use super::*;
use crate::boot_roundtrip::pipeline::{Plan, Verification};
use std::collections::BTreeMap;

pub(super) type Windows = BTreeMap<usize, Vec<u8>>;

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_pipeline(
        plan: &'a Plan,
        link: T,
        output: Option<&'a Path>,
        recovery: Option<Mode>,
        full_read: bool,
    ) -> Self {
        let mut session = Self::new(&plan.reference, link, output);
        session.pipeline_plan = Some(plan);
        session.pipeline_recovery = recovery;
        session.pipeline_full_read = full_read;
        session.state.pipeline = Some(Verification::default());
        session
    }
    pub(super) fn pipeline_fixed(
        &mut self,
        phase: &str,
        op: u8,
        size: usize,
    ) -> Result<Vec<u8>, Fault> {
        let mut results = Vec::new();
        for seed in [0xa5, 0x5a] {
            let mut frame = [0; 64];
            frame[..2].copy_from_slice(&[7, op]);
            frame[8..].fill(seed);
            let raw = self.pair(phase, &frame)?;
            if raw[..8] != frame[..8] || raw[8 + size..] != frame[8 + size..] {
                return Err(Fault::known("preset fixed-read framing differs"));
            }
            results.push(raw[8..8 + size].to_vec());
        }
        if results[0] != results[1] {
            return Err(Fault::known("preset fixed read echoes or differs"));
        }
        Ok(results.remove(0))
    }
    pub(super) fn pipeline_sample(
        &mut self,
        label: &str,
        expected: &[u8],
        saved_policy: u8,
    ) -> Result<Windows, Fault> {
        self.close_gate()?;
        self.set("preset-open", &key_frame(0x22184952))?;
        let mut result = Windows::new();
        let mut addresses = self.pipeline_plan.unwrap().samples.clone();
        if self.workflow_main_end > 0xe700 {
            addresses.extend((0xe700..self.workflow_main_end).step_by(32));
            addresses.sort_unstable();
            addresses.dedup();
        }
        for at in addresses {
            let mut frame = read_frame(2, at as u32, 8);
            for (seed, want) in frame[32..].iter_mut().zip(&expected[at..at + 32]) {
                *seed = !*want;
            }
            let raw = self.pair(label, &frame)?;
            if raw[..32] != frame[..32] {
                return Err(Fault::known("preset sample selector differs"));
            }
            if saved_policy == 2 && matches!(at, 0xff40 | 0xff60) {
                let other = self.memory(label, at as u32, 0x39)?;
                if raw[32..] != other[32..] {
                    return Err(Fault::known("saved-state sample changed or echoed"));
                }
                if at == 0xff40 && raw[37] > 6 {
                    return Err(Fault::known(
                        "saved profile selector is outside known range",
                    ));
                }
            } else {
                for (i, (&got, &want)) in raw[32..].iter().zip(&expected[at..at + 32]).enumerate() {
                    if saved_policy == 1 && at + i == 0xff45 && got <= 6 {
                        continue;
                    }
                    if got != want {
                        return Err(Fault::known(format!("{label} differs at {:04X}", at + i)));
                    }
                }
            }
            result.insert(at, raw[32..].to_vec());
        }
        self.close_gate()?;
        self.save(
            &format!("{label}.json"),
            &serde_json::to_vec(&result).map_err(|e| Fault::known(e.to_string()))?,
        )?;
        Ok(result)
    }
    pub(super) fn pipeline_bank(
        &mut self,
        label: &str,
        expected: Option<&[u8]>,
    ) -> Result<Vec<u8>, Fault> {
        self.close_gate()?;
        self.set("preset-bank-open", &key_frame(0x22184952))?;
        let mut data = Vec::new();
        for off in (0..boot_bank::BANK_BYTES).step_by(32) {
            let mut frame = read_frame(2, boot_bank::BANK_BASE + off as u32, 8);
            if let Some(want) = expected {
                for (a, b) in frame[32..].iter_mut().zip(&want[off..off + 32]) {
                    *a = !*b;
                }
            } else {
                frame[32..].fill(0xa5);
            }
            let raw = self.pair(label, &frame)?;
            if raw[..32] != frame[..32] {
                return Err(Fault::known("active bank read selector differs"));
            }
            if let Some(want) = expected {
                if raw[32..] != want[off..off + 32] {
                    return Err(Fault::known("active bank differs from selected revision"));
                }
            } else {
                let other = self.memory(label, boot_bank::BANK_BASE + off as u32, 0x5a)?;
                if raw[32..] != other[32..] {
                    return Err(Fault::known("active bank unknown read echoes or changes"));
                }
            }
            data.extend_from_slice(&raw[32..]);
        }
        self.close_gate()?;
        if boot_bank::Revision::from_bank(&data).is_none() {
            return Err(Fault::known("active bank is incomplete or unrecognized"));
        }
        self.save(&format!("{label}.bin"), &data)?;
        Ok(data)
    }
    fn pipeline_observe(&mut self, phase: &str) -> Result<(), Fault> {
        let seconds = self.pipeline_plan.unwrap().request.observation_seconds;
        let mode = self
            .state
            .mode
            .ok_or_else(|| Fault::uncertain("observation has no bound device"))?;
        self.save(
            &format!("{phase}-binding.json"),
            &serde_json::to_vec(self.binding.as_ref().unwrap())
                .map_err(|e| Fault::known(e.to_string()))?,
        )?;
        match self.link.perform(&Action::Observe {
            mode,
            phase: phase.into(),
            seconds,
        })? {
            Answer::Observed => Ok(()),
            _ => Err(Fault::uncertain("invalid observation completion")),
        }
    }
    pub(super) fn pipeline_marker(&mut self) -> Result<(), Fault> {
        if !self.state.identity_verified || self.state.gate_dirty {
            return Err(Fault::known(
                "preset marker needs verified identity and closed gate",
            ));
        }
        self.close_gate()?;
        self.set("preset-marker-before-open", &key_frame(0x22184952))?;
        let mut before = self.memory("preset-marker-before", 0xfee0, 0xa5)?[32..].to_vec();
        if self.memory("preset-marker-before", 0xfee0, 0x5a)?[32..] != before {
            return Err(Fault::known("marker-page baseline echoes or changes"));
        }
        self.close_gate()?;
        let mut frame = [0; 64];
        frame[..3].copy_from_slice(&[7, 0x28, 1]);
        self.state.marker_program_intents += 1;
        self.state.marker_dirty = true;
        self.set("preset-clear-marker", &frame)?;
        self.close_gate()?;
        self.set("preset-marker-open", &key_frame(0x22184952))?;
        let raw = self.memory("preset-marker-check", 0xfee0, 0x58)?;
        before[28..].fill(0);
        if raw[32..] != before {
            return Err(Fault::known("entry marker did not clear"));
        }
        self.close_gate()?;
        self.state.neighbors_verified = true;
        Ok(())
    }
    pub(super) fn pipeline_records(
        &mut self,
        restore: bool,
        expected: &mut [u8],
    ) -> Result<(), Fault> {
        let records = if restore {
            self.pipeline_plan.unwrap().backup.records.clone()
        } else {
            self.pipeline_plan.unwrap().stock.image_records().to_vec()
        };
        for (index, record) in records.iter().enumerate() {
            if index + 1 == records.len() {
                if restore && self.pipeline_full_read {
                    self.state.pipeline.as_mut().unwrap().full_read_started = true;
                    self.close_gate()?;
                    self.set("preset-full-open", &key_frame(0x22184952))?;
                    let mut full = Vec::with_capacity(65536);
                    for (i, want) in expected.chunks_exact(32).enumerate() {
                        let mut frame = read_frame(2, (i * 32) as u32, 8);
                        for (a, b) in frame[32..].iter_mut().zip(want) {
                            *a = !*b;
                        }
                        let raw = self.pair("preset-restore-full-prefix", &frame)?;
                        if raw[..32] != frame[..32] || raw[32..] != *want {
                            return Err(Fault::known(format!(
                                "full restore prefix mismatch at {:04X}",
                                i * 32
                            )));
                        }
                        full.extend_from_slice(&raw[32..]);
                    }
                    self.close_gate()?;
                    self.save("preset-restore-full-prefix.bin", &full)?;
                    self.state
                        .pipeline
                        .as_mut()
                        .unwrap()
                        .full_restore_prefix_verified = true;
                } else {
                    self.pipeline_sample(
                        if restore {
                            "preset-restore-sampled-prefix"
                        } else {
                            "preset-forward-sampled-prefix"
                        },
                        expected,
                        0,
                    )?;
                }
            }
            let phase = if restore {
                "preset-restore-records"
            } else {
                "preset-forward-records"
            };
            if restore {
                self.state.pipeline.as_mut().unwrap().restore_records += 1;
            } else {
                self.state.pipeline.as_mut().unwrap().forward_records += 1;
            }
            let raw = self.pair(phase, &record.local_buffer())?;
            if raw[..32] != record.local_buffer()[..32] || raw[32..] != record.decoded_payload() {
                return Err(Fault::known("preset record decoded acknowledgment differs"));
            }
            let at = record.address().get() as usize;
            expected[at..at + 32].copy_from_slice(&record.decoded_payload());
        }
        Ok(())
    }
    pub(super) fn pipeline_target_information(&mut self) -> Result<(), Fault> {
        let core = match self.state.mode {
            Some(Mode::Target(core)) => core,
            _ => self.pipeline_plan.unwrap().stock.core(),
        };
        for query in [
            crate::queries::NormalQuery::Identity,
            crate::queries::NormalQuery::Status,
        ] {
            let codec = crate::queries::OfflineQueryFrame::new(query, 64)
                .map_err(|e| Fault::known(e.to_string()))?;
            let raw = self.pair("preset-target-information", &codec.request())?;
            let valid = match codec
                .decode(&raw)
                .map_err(|e| Fault::known(e.to_string()))?
            {
                crate::queries::NormalReply::Identity {
                    core: got,
                    version_compare_word,
                    ..
                } => got == core && version_compare_word == 0x34,
                crate::queries::NormalReply::Status {
                    display_version_word,
                    ..
                } => display_version_word == 0x34,
            };
            if !valid {
                return Err(Fault::known("preset returned the wrong Core/version"));
            }
        }
        let frame = crate::readback::descriptor_request();
        let raw = self.pair("preset-layout", &frame)?;
        let bases = crate::readback::RuntimeDescriptorReply::decode(&raw)
            .map_err(|e| Fault::known(e.to_string()))?
            .descriptor()
            .bases();
        if (
            bases.sensitivity,
            bases.main_profile,
            bases.additional_profile,
        ) != (0xe000, 0xe200, 0xfe9c)
        {
            return Err(Fault::known("target configuration bases differ"));
        }
        self.state.identity_verified = true;
        Ok(())
    }
    pub(super) fn pipeline_processing(&mut self, pause: bool) -> Result<(), Fault> {
        let mut frame = [0; 64];
        frame[..2].copy_from_slice(&[7, 0x20]);
        frame[7] = u8::from(pause);
        if self.pair("preset-config-processing", &frame)? != frame {
            return Err(Fault::known("preset processing status differs"));
        }
        Ok(())
    }
    pub(super) fn pipeline_configure(
        &mut self,
        expected: &mut [u8],
        goal: &[u8],
        label: &str,
        sensitivity: bool,
    ) -> Result<(), Fault> {
        let suffix = if label.is_empty() {
            String::new()
        } else {
            format!("-{label}")
        };
        self.pipeline_processing(true)?;
        let main_bytes = if self.state.mode == Some(Mode::Normal) {
            crate::workflow::original_main_bytes(expected, goal)
        } else {
            let bytes = crate::workflow::configured_main_bytes(expected, goal);
            self.workflow_main_end = self.workflow_main_end.max(0xe200 + bytes);
            bytes
        };
        for (base, size) in [(0xe000, 256), (0xe200, main_bytes)] {
            if base == 0xe000 && !sensitivity {
                continue;
            }
            if self.pipeline_plan.unwrap().request.workflow.is_some()
                && expected[base..base + size] == goal[base..base + size]
            {
                continue;
            }
            for off in (0..size).step_by(32) {
                let at = base + off;
                let mut frame = [0; 64];
                frame[..3].copy_from_slice(&[7, 0x2f, 1]);
                frame[24] = 8;
                frame[28..32].copy_from_slice(&(at as u32).to_le_bytes());
                frame[32..].copy_from_slice(&goal[at..at + 32]);
                if off == 0 {
                    frame[32..36].fill(0xff);
                }
                self.state.pipeline.as_mut().unwrap().configuration_programs += 1;
                self.set("preset-config-stage", &frame)?;
                expected[at..at + 32].copy_from_slice(&frame[32..]);
            }
            self.pipeline_sample(
                &format!("preset-config{suffix}-prefix-{base:x}"),
                expected,
                2,
            )?;
            let mut commit = [0; 64];
            commit[..3].copy_from_slice(&[7, 0x2f, 1]);
            commit[24] = 1;
            commit[28..32].copy_from_slice(&(base as u32).to_le_bytes());
            commit[32..36].fill(0xa4);
            self.state.pipeline.as_mut().unwrap().configuration_programs += 1;
            self.set("preset-config-commit", &commit)?;
            expected[base..base + 4].fill(0xa4);
        }
        let settings: &[u8] = &goal[0xe000..0xe100];
        let slot = u16::from_le_bytes(settings[10..12].try_into().unwrap()) as usize;
        if slot > 4 {
            return Err(Fault::known("source sensitivity selector differs"));
        }
        let at = 0x10 + slot * 6;
        let mut apply = [0; 64];
        apply[..2].copy_from_slice(&[7, 0x0d]);
        apply[8..16].copy_from_slice(&[
            settings[8],
            settings[10],
            settings[at - 4],
            settings[at - 2],
            settings[at],
            settings[0x3c],
            settings[at - 3],
            settings[at - 1],
        ]);
        self.state.pipeline.as_mut().unwrap().runtime_programs += 1;
        self.set("preset-config-runtime", &apply)?;
        self.pipeline_processing(false)?;
        self.pipeline_sample(&format!("preset-config{suffix}-returned"), expected, 2)?;
        self.state.pipeline.as_mut().unwrap().configuration_verified = true;
        self.state
            .pipeline
            .as_mut()
            .unwrap()
            .experimental_profile_materialized = true;
        Ok(())
    }
    pub(super) fn pipeline_flash(&mut self, expected: &mut [u8]) -> Result<(), Fault> {
        let plan = self.pipeline_plan.unwrap();
        self.pipeline_marker()?;
        expected[0xfefc..0xff00].fill(0);
        self.reset(Mode::Boot)?;
        let uv = self.pipeline_fixed("preset-unit", 0x29, 8)?;
        if uv != plan.backup.original[0xffd0..0xffd8]
            || crate::prepared::default_identity(u32::from_le_bytes(uv[..4].try_into().unwrap()))
                != u32::from_le_bytes(expected[0xfee0..0xfee4].try_into().unwrap())
        {
            return Err(Fault::known("preset unit identity differs"));
        }
        self.pipeline_records(false, expected)?;
        let block = self.pipeline_fixed("preset-final-block", 0x2b, 28)?;
        if block != expected[0xfee0..0xfefc] {
            return Err(Fault::known("preset final block differs"));
        }
        let mut finalization = [0; 64];
        finalization[..3].copy_from_slice(&[7, 0x2b, 1]);
        finalization[8..36].copy_from_slice(&block);
        finalization[8..12].copy_from_slice(&plan.backup.original[0xfee0..0xfee4]);
        self.set("preset-finalize", &finalization)?;
        expected[0xfee0..0xfee4].copy_from_slice(&plan.backup.original[0xfee0..0xfee4]);
        self.pipeline_sample("preset-forward-programmed", expected, 0)?;
        self.state
            .pipeline
            .as_mut()
            .unwrap()
            .forward_samples_verified = true;
        self.state.marker_dirty = false;
        self.state.neighbors_verified = true;
        self.reset(Mode::Target(plan.stock.core()))?;
        self.pipeline_target_information()?;
        self.pipeline_sample("preset-target-stock", expected, 2)?;
        self.pipeline_bank("preset-target-bank", Some(plan.stock.boot_copy()))?;
        Ok(())
    }
    pub(super) fn pipeline_runtime(
        &mut self,
        label: &str,
    ) -> Result<crate::shooting_runtime::Snapshot, Fault> {
        let mut result = Vec::new();
        for seed in [0xa5, 0x5a] {
            let frame = crate::shooting_runtime::query(seed);
            let raw = self.pair(&format!("preset-runtime-{label}"), &frame)?;
            result.push(
                crate::shooting_runtime::Snapshot::decode(&frame, &raw).map_err(Fault::known)?,
            );
        }
        if result[0] != result[1] {
            return Err(Fault::known("runtime fields changed between seeds"));
        }
        let snapshot = result.remove(0);
        self.save(
            &format!("runtime-{label}.json"),
            &serde_json::to_vec(&snapshot).map_err(|e| Fault::known(e.to_string()))?,
        )?;
        self.state
            .pipeline
            .as_mut()
            .unwrap()
            .runtime_observations
            .push((label.into(), snapshot.clone()));
        Ok(snapshot)
    }
    pub(super) fn pipeline_select_slot(&mut self, label: &str, slot: u8) -> Result<(), Fault> {
        let before = self.pipeline_runtime(&format!("{label}-before"))?;
        let frame = before.select(slot).map_err(Fault::known)?;
        self.state.pipeline.as_mut().unwrap().runtime_programs += 1;
        self.set("preset-config-runtime", &frame)?;
        let after = self.pipeline_runtime(&format!("{label}-after"))?;
        let mut wanted = before.payload;
        wanted[0] = slot;
        if after.payload != wanted {
            return Err(Fault::known("runtime selection or preserved fields differ"));
        }
        Ok(())
    }
    pub(super) fn pipeline_run(&mut self) -> Result<(), Fault> {
        let plan = self.pipeline_plan.unwrap();
        if plan.request.workflow.is_some() && self.pipeline_recovery.is_none() {
            return self.workflow_run();
        }
        let mut expected = plan.backup.original.clone();
        if let Some(mode) = self.pipeline_recovery {
            self.connect(mode)?;
        } else {
            self.connect(Mode::Normal)?;
        }
        if self.pipeline_recovery.is_none() {
            self.normal_identity()?;
            let actual = self.pipeline_sample("preset-original-before", &expected, 1)?;
            for at in [0xff40, 0xff60] {
                expected[at..at + 32].copy_from_slice(&actual[&at]);
            }
            let orig_bank = &plan.backup.original[boot_bank::COPY_BASE as usize
                ..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES];
            self.pipeline_bank("preset-original-bank", Some(orig_bank))?;
            self.state.pipeline.as_mut().unwrap().retry_allowed = true;
            self.pipeline_flash(&mut expected)?;
            if plan.request.shooting_comparison {
                self.pipeline_runtime("stock")?;
            }
            self.pipeline_observe("target-stock")?;
            let goal = plan.configured.clone();
            self.pipeline_configure(&mut expected, &goal, "", true)?;
            if plan.request.shooting_comparison {
                self.pipeline_select_slot("baseline", 0)?;
                self.pipeline_observe("shoot-baseline")?;
                self.pipeline_observe("shoot-selector")?;
                self.pipeline_runtime("after-physical-selector")?;
                self.pipeline_select_slot("selected-left", 1)?;
                self.pipeline_observe("shoot-applied")?;
                self.pipeline_select_slot("direct-neutral", 0)?;
                for (clicks, label, phase) in [
                    (2, "double", "shoot-direct-double"),
                    (3, "triple", "shoot-direct-triple"),
                ] {
                    let goal = plan.direct_profile(clicks).map_err(Fault::known)?;
                    self.pipeline_configure(&mut expected, &goal, label, false)?;
                    self.pipeline_observe(phase)?;
                    self.pipeline_runtime(&format!("after-direct-{label}"))?;
                }
                self.state
                    .pipeline
                    .as_mut()
                    .unwrap()
                    .shooting_comparison_completed = true;
            } else {
                self.pipeline_observe("target-configured")?;
            }
        }
        self.pipeline_restore()
    }
    pub(super) fn pipeline_restore(&mut self) -> Result<(), Fault> {
        let plan = self.pipeline_plan.unwrap();
        if self.state.mode != Some(Mode::Boot) {
            if self.state.mode == Some(Mode::Normal) {
                self.normal_identity()?;
            } else {
                self.pipeline_target_information()?;
            }
            if self.pipeline_recovery.is_some() {
                let bank = if self.state.mode == Some(Mode::Normal) {
                    &plan.backup.original[boot_bank::COPY_BASE as usize
                        ..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES]
                } else {
                    plan.stock.boot_copy()
                };
                self.pipeline_bank("preset-recovery-preentry-bank", Some(bank))?;
            }
            self.close_gate()?;
            self.set("preset-recovery-unit-open", &key_frame(0x22184952))?;
            for at in (0xff00..0xff40)
                .step_by(32)
                .chain((0xff80..0x10000).step_by(32))
            {
                let want = &plan.backup.original[at..at + 32];
                let mut frame = read_frame(2, at as u32, 8);
                for (seed, byte) in frame[32..].iter_mut().zip(want) {
                    *seed = !*byte;
                }
                let raw = self.pair("preset-recovery-unit", &frame)?;
                if raw[..32] != frame[..32] || raw[32..] != *want {
                    return Err(Fault::known("normal recovery belongs to another unit"));
                }
            }
            self.close_gate()?;
            self.pipeline_marker()?;
            self.reset(Mode::Boot)?;
        }
        let uv = self.pipeline_fixed("preset-restore-unit", 0x29, 8)?;
        if uv != plan.backup.original[0xffd0..0xffd8] {
            return Err(Fault::known("restoration unit differs from backup"));
        }
        self.state.identity_verified = true;
        self.state.pipeline.as_mut().unwrap().retry_allowed = false;
        self.pipeline_bank("preset-restore-entry-bank", None)?;
        self.close_gate()?;
        self.set("preset-restore-open", &key_frame(0x22184952))?;
        for at in (0xff00..0xff40)
            .step_by(32)
            .chain((0xff80..0x10000).step_by(32))
        {
            let raw = self.memory("preset-protected", at as u32, 0xa5)?;
            if raw[32..] != plan.backup.original[at..at + 32] {
                return Err(Fault::known("protected unit bytes differ"));
            }
        }
        let last = self.memory("preset-pending-last-block", 0xfee0, 0xa5)?[32..].to_vec();
        if self.memory("preset-pending-last-block", 0xfee0, 0x5a)?[32..] != last {
            return Err(Fault::known("pending last block echoes or changes"));
        }
        self.close_gate()?;
        self.state.pipeline.as_mut().unwrap().retry_allowed = true;
        self.pipeline_marker()?;
        let mut expected = plan.backup.original.clone();
        expected[0xfee0..0xff00].copy_from_slice(&last);
        expected[0xfefc..0xff00].fill(0);
        self.pipeline_records(true, &mut expected)?;
        if expected != plan.backup.original {
            return Err(Fault::known(
                "whole backup stream did not reconstruct original",
            ));
        }
        self.pipeline_sample("preset-restore-programmed", &expected, 0)?;
        self.state.marker_dirty = false;
        self.state.neighbors_verified = true;
        self.reset(Mode::Normal)?;
        self.normal_identity()?;
        self.pipeline_sample("preset-original-returned", &expected, 1)?;
        let orig_bank = &plan.backup.original[boot_bank::COPY_BASE as usize
            ..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES];
        self.pipeline_bank("preset-returned-bank", Some(orig_bank))?;
        if plan.request.workflow.is_some() {
            self.save_current_configuration(&expected, Mode::Normal, None, false, false)?;
        }
        self.state
            .pipeline
            .as_mut()
            .unwrap()
            .original_return_samples_verified = true;
        self.state
            .pipeline
            .as_mut()
            .unwrap()
            .original_boot_bank_verified = true;
        if plan.request.workflow.is_none() {
            self.pipeline_observe("original-restored")?;
        }
        self.state.complete = true;
        self.state.neighbors_verified = true;
        self.state.normal_verified = true;
        self.state.snapshots_verified = true;
        self.state.returned = true;
        Ok(())
    }
}
