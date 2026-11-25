//! In-memory model of the W95 Max CPI-only edit and restoration cycle.
use crate::{
    access_job::{AccessBaseline, BLOCK_BYTES, SETTINGS_BYTES},
    firmware::sha256,
    preview::read_file,
    query_session::load_access_baseline,
    recovery::{self, Comparison},
    settings::{self, CpiEdit, SettingsEdits, WordChange},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SETTINGS: usize = 256;
const PAGE: usize = 64;
const INVALID: [u8; 4] = [0xff; 4];
pub(crate) type Pages = [u8; SETTINGS_BYTES];

pub(crate) struct Candidate {
    pub baseline: AccessBaseline,
    pub original: Pages,
    pub target: Pages,
    pub selected_slot: u8,
    pub requested_cpi: u16,
    pub changes: Vec<WordChange>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    schema_version: u8,
    snapshot: PathBuf,
    information: PathBuf,
    layout: PathBuf,
    headers: PathBuf,
    image: PathBuf,
    response_mask: PathBuf,
    passes: [PathBuf; 2],
    cpi: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Quiesce,
    WriteChunk(u8),
    VerifyStaged,
    CommitMarker,
    VerifyCommitted,
    ApplyRuntime,
    Resume,
    DeferredSave,
    VerifyFinal,
}

const VENDOR_STEPS: [Step; 16] = [
    Step::Quiesce,
    Step::WriteChunk(0),
    Step::WriteChunk(1),
    Step::WriteChunk(2),
    Step::WriteChunk(3),
    Step::WriteChunk(4),
    Step::WriteChunk(5),
    Step::WriteChunk(6),
    Step::WriteChunk(7),
    Step::VerifyStaged,
    Step::CommitMarker,
    Step::VerifyCommitted,
    Step::ApplyRuntime,
    Step::Resume,
    Step::DeferredSave,
    Step::VerifyFinal,
];
const FIRST_PAGE_STEPS: [Step; 10] = [
    Step::Quiesce,
    Step::WriteChunk(0),
    Step::WriteChunk(1),
    Step::VerifyStaged,
    Step::CommitMarker,
    Step::VerifyCommitted,
    Step::ApplyRuntime,
    Step::Resume,
    Step::DeferredSave,
    Step::VerifyFinal,
];
const RUNTIME_RESTORE: [Step; 5] = [
    Step::Quiesce,
    Step::ApplyRuntime,
    Step::Resume,
    Step::DeferredSave,
    Step::VerifyFinal,
];

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", content = "step", rename_all = "snake_case")]
enum Fault {
    InterruptionAfter(Step),
    LostCompletion(Step),
    WriteRejected(Step),
    WriteNoEffect(Step),
    ReadDisagrees(Step),
    ReadUnavailable(Step),
    TornMarker,
    RuntimeApplyNoEffect,
    SavedPageCleared,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Controller {
    ReplaceSuppliedBytes,
    ClearPageBeforeProgram,
    SetBitsOnly,
}

impl Controller {
    fn program(self, pages: &mut Pages, start: usize, data: &[u8]) {
        let end = start + data.len();
        assert!(start / PAGE == (end - 1) / PAGE);
        if matches!(self, Self::ClearPageBeforeProgram) {
            let page = start / PAGE * PAGE;
            pages[page..page + PAGE].fill(0);
        }
        let dst = &mut pages[start..end];
        if matches!(self, Self::SetBitsOnly) {
            for (old, new) in dst.iter_mut().zip(data) {
                *old |= new;
            }
        } else {
            dst.copy_from_slice(data);
        }
    }
}

#[derive(Clone)]
struct Device {
    pages: Pages,
    runtime_fields: [u8; 8],
    quiesced: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "step", rename_all = "snake_case")]
enum Outcome {
    Verified,
    Interrupted(Step),
    CompletionUnknown(Step),
    WriteRejected(Step),
    VerificationFailed(Step),
}

#[derive(Debug, Serialize)]
struct Attempt {
    outcome: Outcome,
    steps_attempted: usize,
    final_snapshot_sha256: String,
    runtime_fields: [u8; 8],
    quiesced: bool,
}

#[derive(Serialize)]
struct InterruptedCase {
    direction: &'static str,
    fault: Fault,
    attempt: Attempt,
    fresh_readback: Comparison,
    restoration: Restoration,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Restoration {
    OriginalVerified,
    SeparateAttempt { steps: Vec<Step>, attempt: Attempt },
    SavedStateDiffers,
}

#[derive(Serialize)]
struct ControllerTrial {
    controller: Controller,
    edit: Attempt,
    restore_from_target: Attempt,
}

#[derive(Serialize)]
struct SequenceReport {
    steps: Vec<Step>,
    edit: Attempt,
    restore: Attempt,
    edit_without_deferred_save: Attempt,
    controller_trials: Vec<ControllerTrial>,
    interruption_cases: Vec<InterruptedCase>,
}

#[derive(Serialize)]
pub struct Report {
    mode: &'static str,
    baseline_sha256: String,
    original_sha256: String,
    target_sha256: String,
    selected_slot: u16,
    requested_cpi: u16,
    changes: Vec<WordChange>,
    vendor_sequence: SequenceReport,
    first_page_sequence: SequenceReport,
}

struct Cycle<'a> {
    baseline: AccessBaseline,
    original: &'a Pages,
    target: &'a Pages,
    word_offset: usize,
}

fn word(data: &Pages, offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

impl Cycle<'_> {
    // Fields copied into report offsets 8–15 by the Windows apply helper.
    fn runtime_fields(&self, pages: &Pages) -> [u8; 8] {
        apply_fields(pages, self.word_offset)
    }

    fn readback(&self, first: &[u8], second: &[u8]) -> Result<recovery::RecoveryReplay, String> {
        recovery::replay(
            self.baseline.clone(),
            self.original,
            self.target,
            [first, second],
        )
    }

    fn verify(
        &self,
        pages: &Pages,
        expected: &Pages,
        step: Step,
        fault: Option<Fault>,
    ) -> Result<bool, String> {
        let mut changed = *pages;
        let second = match fault {
            Some(Fault::ReadDisagrees(at)) if at == step => {
                changed[SETTINGS_BYTES - 1] ^= 1;
                changed.as_slice()
            }
            Some(Fault::ReadUnavailable(at)) if at == step => &[],
            _ => pages.as_slice(),
        };
        Ok(self.readback(pages, second)?.job.complete && pages == expected)
    }

    fn attempt(
        &self,
        device: &mut Device,
        goal: &Pages,
        steps: &[Step],
        controller: Controller,
        deferred_save: bool,
        fault: Option<Fault>,
    ) -> Result<Attempt, String> {
        let mut staged = *goal;
        staged[..4].copy_from_slice(&INVALID);
        let wanted_runtime = self.runtime_fields(goal);
        let mut outcome = Outcome::Verified;
        let mut steps_attempted = 0;
        for &step in steps {
            steps_attempted += 1;
            if matches!(fault, Some(Fault::WriteRejected(at)) if at == step) {
                outcome = Outcome::WriteRejected(step);
                break;
            }
            if !matches!(fault, Some(Fault::WriteNoEffect(at)) if at == step) {
                let valid = match step {
                    Step::Quiesce => {
                        device.quiesced = true;
                        true
                    }
                    Step::WriteChunk(index) => {
                        let start = usize::from(index) * BLOCK_BYTES;
                        controller.program(
                            &mut device.pages,
                            start,
                            &staged[start..start + BLOCK_BYTES],
                        );
                        true
                    }
                    Step::VerifyStaged => self.verify(&device.pages, &staged, step, fault)?,
                    Step::CommitMarker => {
                        let end = if matches!(fault, Some(Fault::TornMarker)) {
                            2
                        } else {
                            4
                        };
                        controller.program(&mut device.pages, 0, &goal[..end]);
                        true
                    }
                    Step::VerifyCommitted => self.verify(&device.pages, goal, step, fault)?,
                    Step::ApplyRuntime => {
                        if !matches!(fault, Some(Fault::RuntimeApplyNoEffect)) {
                            device.runtime_fields = wanted_runtime;
                        }
                        true
                    }
                    Step::Resume => {
                        device.quiesced = false;
                        true
                    }
                    Step::DeferredSave => {
                        if deferred_save {
                            // Model the unchanged saved slot being written back after apply.
                            let first_half = &goal[SETTINGS..SETTINGS + BLOCK_BYTES];
                            let saved_controller = if matches!(fault, Some(Fault::SavedPageCleared))
                            {
                                Controller::ClearPageBeforeProgram
                            } else {
                                controller
                            };
                            saved_controller.program(&mut device.pages, SETTINGS, first_half);
                        }
                        true
                    }
                    Step::VerifyFinal => {
                        self.verify(&device.pages, goal, step, fault)?
                            && device.runtime_fields == wanted_runtime
                            && !device.quiesced
                    }
                };
                if !valid {
                    outcome = Outcome::VerificationFailed(step);
                    break;
                }
            }
            if matches!(fault, Some(Fault::LostCompletion(at)) if at == step) {
                outcome = Outcome::CompletionUnknown(step);
                break;
            }
            if matches!(fault, Some(Fault::InterruptionAfter(at)) if at == step) {
                outcome = Outcome::Interrupted(step);
                break;
            }
        }
        Ok(Attempt {
            outcome,
            steps_attempted,
            final_snapshot_sha256: sha256(&device.pages),
            runtime_fields: device.runtime_fields,
            quiesced: device.quiesced,
        })
    }

    fn interrupted_case(
        &self,
        start: &Device,
        goal: &Pages,
        steps: &[Step],
        direction: &'static str,
        fault: Fault,
    ) -> Result<InterruptedCase, String> {
        let controller = Controller::ReplaceSuppliedBytes;
        let mut device = start.clone();
        let attempt = self.attempt(&mut device, goal, steps, controller, true, Some(fault))?;
        // This is a separate modeled session after a fresh binding and verified readback.
        let fresh = self.readback(&device.pages, &device.pages)?;
        if !fresh.job.complete {
            return Err("fresh simulated diagnosis did not complete".into());
        }
        let restoration = if device.pages[SETTINGS..] != self.original[SETTINGS..] {
            Restoration::SavedStateDiffers
        } else {
            let original_runtime = device.runtime_fields == self.runtime_fields(self.original);
            let restore_steps: &[Step] = if device.pages != *self.original {
                steps
            } else if !original_runtime {
                &RUNTIME_RESTORE
            } else if device.quiesced {
                &[Step::Resume, Step::VerifyFinal]
            } else {
                &[]
            };
            if restore_steps.is_empty() {
                Restoration::OriginalVerified
            } else {
                Restoration::SeparateAttempt {
                    steps: restore_steps.to_vec(),
                    attempt: self.attempt(
                        &mut device,
                        self.original,
                        restore_steps,
                        controller,
                        true,
                        None,
                    )?,
                }
            }
        };
        Ok(InterruptedCase {
            direction,
            fault,
            attempt,
            fresh_readback: fresh.comparison,
            restoration,
        })
    }
}

fn faults(steps: &[Step]) -> Vec<Fault> {
    let mut faults: Vec<_> = steps
        .iter()
        .copied()
        .map(Fault::InterruptionAfter)
        .collect();
    for &step in steps {
        match step {
            Step::WriteChunk(_) | Step::CommitMarker => faults.extend([
                Fault::LostCompletion(step),
                Fault::WriteRejected(step),
                Fault::WriteNoEffect(step),
            ]),
            Step::VerifyStaged | Step::VerifyCommitted | Step::VerifyFinal => {
                faults.extend([Fault::ReadDisagrees(step), Fault::ReadUnavailable(step)]);
            }
            _ => faults.push(Fault::LostCompletion(step)),
        }
    }
    faults.extend([
        Fault::TornMarker,
        Fault::RuntimeApplyNoEffect,
        Fault::SavedPageCleared,
    ]);
    faults
}

pub(crate) fn apply_fields(pages: &Pages, at: usize) -> [u8; 8] {
    [
        pages[8],
        pages[10],
        pages[at - 4],
        pages[at - 2],
        pages[at],
        pages[0x3c],
        pages[at - 3],
        pages[at - 1],
    ]
}

pub(crate) fn load_candidate(path: &Path) -> Result<Candidate, String> {
    let raw = read_file(path, 64 * 1024)?;
    let project: Project =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if project.schema_version != 1 {
        return Err("unsupported settings cycle project schema version".into());
    }
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let baseline = load_access_baseline(
        &root.join(project.snapshot),
        &root.join(project.information),
        &root.join(project.layout),
        &root.join(project.headers),
    )?;
    let image = read_file(&root.join(project.image), 65536)?;
    let mask = read_file(&root.join(project.response_mask), 65536)?;
    let before = settings::preview(&image, &mask, &SettingsEdits::default())?;
    if before.non_echo_bytes != SETTINGS || mask[0xff40..0xff80].iter().any(|&b| b != 1) {
        return Err("settings cycle requires full settings and saved-state coverage".into());
    }
    if image[0xfec0..0xfee0] != baseline.status[8..40] {
        return Err("settings image metadata differs from the saved binding baseline".into());
    }
    let mut original = [0; SETTINGS_BYTES];
    original[..SETTINGS].copy_from_slice(&before.candidate_bytes);
    original[SETTINGS..].copy_from_slice(&image[0xff40..0xff80]);
    let slot = before.selected_slot as u8;
    if original[SETTINGS + 8..SETTINGS + 10] != [0xa4, slot]
        || before.slots[usize::from(slot)].original_words[..2] != [0x40, 0x40]
    {
        return Err(
            "settings cycle requires an active equal-axis slot matching the saved index".into(),
        );
    }
    let preview = settings::preview(
        &image,
        &mask,
        &SettingsEdits {
            cpi: vec![CpiEdit {
                slot,
                cpi: project.cpi,
            }],
            report_rate_hz: None,
        },
    )?;
    let offset = 0x10 + 6 * usize::from(slot);
    let mut target = original;
    target[..SETTINGS].copy_from_slice(&preview.candidate_bytes);
    if word(&original, offset).abs_diff(word(&target, offset)) != 1 {
        return Err("choose a CPI value one encoded step from the current slot".into());
    }
    if target[PAGE..] != original[PAGE..] {
        return Err("CPI candidate changes bytes outside the first settings page".into());
    }
    let [first, second] = project.passes;
    for file in [first, second] {
        if read_file(&root.join(file), SETTINGS_BYTES)? != original {
            return Err(
                "both captured passes must match the complete original settings and saved state"
                    .into(),
            );
        }
    }
    Ok(Candidate {
        baseline,
        original,
        target,
        selected_slot: slot,
        requested_cpi: project.cpi,
        changes: preview.changes,
    })
}

pub fn load(path: &Path) -> Result<Report, String> {
    let candidate = load_candidate(path)?;
    let cycle = Cycle {
        baseline: candidate.baseline,
        original: &candidate.original,
        target: &candidate.target,
        word_offset: 0x10 + 6 * usize::from(candidate.selected_slot),
    };
    Ok(Report {
        mode: "offline_settings_cycle_simulation",
        baseline_sha256: cycle.baseline.fingerprint(),
        original_sha256: sha256(cycle.original),
        target_sha256: sha256(cycle.target),
        selected_slot: candidate.selected_slot.into(),
        requested_cpi: candidate.requested_cpi,
        changes: candidate.changes,
        vendor_sequence: run_sequence(&cycle, &VENDOR_STEPS)?,
        first_page_sequence: run_sequence(&cycle, &FIRST_PAGE_STEPS)?,
    })
}

fn run_sequence(cycle: &Cycle<'_>, steps: &[Step]) -> Result<SequenceReport, String> {
    let start = Device {
        pages: *cycle.original,
        runtime_fields: cycle.runtime_fields(cycle.original),
        quiesced: false,
    };
    let mut edited = start.clone();
    let controller = Controller::ReplaceSuppliedBytes;
    let edit = cycle.attempt(&mut edited, cycle.target, steps, controller, true, None)?;
    if edit.outcome != Outcome::Verified {
        return Err("nominal simulated edit did not verify".into());
    }
    let restore = cycle.attempt(
        &mut edited.clone(),
        cycle.original,
        steps,
        controller,
        true,
        None,
    )?;
    let edit_without_deferred_save = cycle.attempt(
        &mut start.clone(),
        cycle.target,
        steps,
        controller,
        false,
        None,
    )?;
    let mut controller_trials = Vec::new();
    for controller in [Controller::ClearPageBeforeProgram, Controller::SetBitsOnly] {
        controller_trials.push(ControllerTrial {
            controller,
            edit: cycle.attempt(
                &mut start.clone(),
                cycle.target,
                steps,
                controller,
                true,
                None,
            )?,
            restore_from_target: cycle.attempt(
                &mut edited.clone(),
                cycle.original,
                steps,
                controller,
                true,
                None,
            )?,
        });
    }
    let mut interruption_cases = Vec::new();
    for fault in faults(steps) {
        interruption_cases.push(cycle.interrupted_case(
            &start,
            cycle.target,
            steps,
            "edit",
            fault,
        )?);
        interruption_cases.push(cycle.interrupted_case(
            &edited,
            cycle.original,
            steps,
            "restore",
            fault,
        )?);
    }
    Ok(SequenceReport {
        steps: steps.to_vec(),
        edit,
        restore,
        edit_without_deferred_save,
        controller_trials,
        interruption_cases,
    })
}
