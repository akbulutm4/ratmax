//! Bounded inline-profile executor with modeled and disabled native supervision.
use crate::{
    access_job::{AccessBaseline, CallKind, Completion, key_frame, read_frame},
    button_plan::{self, Plan},
    firmware::sha256,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
mod model;
mod native;

const PHYSICAL_BUTTON_RELEASED: bool = false;

pub fn available() -> bool {
    PHYSICAL_BUTTON_RELEASED && crate::query_session::live_available()
}

pub fn run(project: &Path, baseline: &Path, output: &Path) -> Result<serde_json::Value, String> {
    run_observed(project, baseline, output, 0, false)
}

pub fn run_observed(
    project: &Path,
    baseline: &Path,
    output: &Path,
    seconds: u16,
    read_only: bool,
) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical button cycle is disabled in this build".into());
    }
    if seconds > 300 {
        return Err("observation interval exceeds 300 seconds".into());
    }
    native::run(project, baseline, output, seconds, read_only)
}

pub fn restore(session: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical button restoration is disabled in this build".into());
    }
    native::recovery::run(session, output)
}

pub fn worker(source: &Path, proof: Option<&Path>) -> Result<(), String> {
    if !available() {
        return Err("physical button worker is disabled in this build".into());
    }
    native::worker(source, proof)
}

const BASE: usize = 0xe200;
const MAX_CALLS: u32 = 1024;
type Windows = BTreeMap<usize, Vec<u8>>;

trait Link {
    fn validate(&mut self) -> Result<(), String>;
    fn call(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion;
    fn save(&mut self, name: &str, bytes: &[u8]) -> Result<(), String>;
    fn settle(&mut self) -> Result<(), String>;
    fn observe(&mut self, _phase: &str) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    feature_calls: u32,
    program_intents: u16,
    quiesce_requested: bool,
    quiesced: bool,
    gate_closed: bool,
    uncertain: bool,
    backup_saved: bool,
    edited_verified: bool,
    original_restored: bool,
    cleanup_attempted: bool,
    complete: bool,
    release_allowed: bool,
    failure: Option<String>,
    cleanup_failure: Option<String>,
}

struct Session<'a, T> {
    plan: &'a Plan,
    baseline: &'a AccessBaseline,
    reference: Windows,
    original: Windows,
    target: Windows,
    link: T,
    state: State,
}

fn prepared(image: &[u8], plan: &Plan) -> Result<(Windows, Windows), String> {
    if image.len() != 65536
        || !crate::boot_bank::valid_w95max_identity(&image[0xfec0..0xff20])
        || plan.image_sha256 != sha256(image)
        || plan.core != crate::model::Core::One
        || plan.version != 0x28
        || plan.pages.len() > 4
        || plan.pages.first().is_none_or(|p| p.address != BASE)
    {
        return Err(
            "button cycle requires a verified original Core-1/0028 W95 Max saved profile".into(),
        );
    }
    let mut addresses: BTreeSet<_> = plan.preflight_burst_addresses.iter().copied().collect();
    addresses.extend([0xff60, 0xffc0]);
    for page in &plan.pages {
        for at in [page.address - 32, page.address + 64] {
            addresses.insert(at);
        }
    }
    if addresses.len() > 24
        || addresses
            .iter()
            .any(|a| a % 32 != 0 || a + 32 > image.len())
    {
        return Err("button sparse-read extent exceeds its fixed bound".into());
    }
    let original: Windows = addresses
        .iter()
        .map(|at| (*at, image[*at..*at + 32].to_vec()))
        .collect();
    let mut target = original.clone();
    for page in &plan.pages {
        if page.original.len() != 64
            || page.candidate.len() != 64
            || page.original != image[page.address..page.address + 64]
            || sha256(&page.original) != page.original_sha256
            || sha256(&page.candidate) != page.candidate_sha256
        {
            return Err("button page authority changed".into());
        }
        for off in [0, 32] {
            target.insert(page.address + off, page.candidate[off..off + 32].to_vec());
        }
    }
    Ok((original, target))
}

impl<'a, T: Link> Session<'a, T> {
    fn new(
        plan: &'a Plan,
        baseline: &'a AccessBaseline,
        original: Windows,
        target: Windows,
        link: T,
    ) -> Self {
        Self {
            plan,
            baseline,
            reference: original.clone(),
            original,
            target,
            link,
            state: State::default(),
        }
    }
    fn call(
        &mut self,
        phase: &str,
        kind: CallKind,
        frame: &[u8; 64],
    ) -> Result<Option<Vec<u8>>, String> {
        if self.state.uncertain || self.state.feature_calls >= MAX_CALLS {
            return Err("uncertainty or button call limit".into());
        }
        if let Err(error) = self.link.validate() {
            self.state.uncertain = true;
            return Err(error);
        }
        self.state.feature_calls += 1;
        let answer = self.link.call(phase, kind, frame);
        if let Err(error) = self.link.validate() {
            self.state.uncertain = true;
            return Err(error);
        }
        match (kind, answer) {
            (CallKind::Set, Completion::SetComplete) => Ok(None),
            (CallKind::Get, Completion::GetComplete(raw)) if raw.len() == 64 => Ok(Some(raw)),
            (_, Completion::CompletedFailure(error)) => {
                if frame[1] == 0x2f {
                    self.state.uncertain = true;
                }
                Err(error)
            }
            (_, Completion::Uncertain(error)) => {
                self.state.uncertain = true;
                Err(error)
            }
            _ => {
                self.state.uncertain = true;
                Err("button completion type or length differs".into())
            }
        }
    }
    fn pair(&mut self, phase: &str, frame: &[u8; 64]) -> Result<Vec<u8>, String> {
        self.call(phase, CallKind::Set, frame)?;
        self.call(phase, CallKind::Get, frame)?
            .ok_or_else(|| "missing button reply".into())
    }
    fn close(&mut self) -> Result<(), String> {
        self.state.gate_closed = false;
        self.call("close-gate", CallKind::Set, &key_frame(0))?;
        let frame = read_frame(2, 0xfec0, 8);
        if self.pair("closed-witness", &frame)? != frame {
            return Err("button gate closure witness differs".into());
        }
        self.state.gate_closed = true;
        Ok(())
    }
    fn identity(&mut self) -> Result<(), String> {
        for (op, expected) in [
            (0x1f, self.baseline.identity.clone()),
            (0x2d, self.baseline.status.clone()),
            (5, self.baseline.layout.clone()),
        ] {
            let mut frame = [0; 64];
            frame[..2].copy_from_slice(&[7, op]);
            if self.pair("identity", &frame)? != expected {
                return Err("button device identity or layout differs".into());
            }
        }
        Ok(())
    }
    fn capture(
        &mut self,
        label: &str,
        expected: &Windows,
        initial: bool,
        mixed: bool,
    ) -> Result<Windows, String> {
        self.close()?;
        self.state.gate_closed = false;
        self.call("open-gate", CallKind::Set, &key_frame(0x22184952))?;
        let result = (|| {
            let mut captures = Windows::new();
            for (&at, want) in expected {
                let mut frame = read_frame(2, at as u32, 8);
                for (seed, byte) in frame[32..].iter_mut().zip(want) {
                    *seed = !*byte;
                }
                let raw = self.pair(label, &frame)?;
                if raw[..32] != frame[..32] {
                    return Err("button memory header differs".into());
                }
                let bytes = &raw[32..];
                let page = self
                    .plan
                    .pages
                    .iter()
                    .any(|p| (p.address..p.address + 64).contains(&at));
                for (index, (&a, &b)) in bytes.iter().zip(want).enumerate() {
                    if initial && at == 0xff40 && index == 5 && a <= 6 {
                        continue;
                    }
                    if mixed && page {
                        let marker = at == BASE && index < 4;
                        if a == self.original[&at][index]
                            || a == self.target[&at][index]
                            || (marker && a == 0xff)
                        {
                            continue;
                        }
                    }
                    if a != b {
                        return Err(format!("{label} differs at {:04X}", at + index));
                    }
                }
                captures.insert(at, bytes.to_vec());
            }
            Ok(captures)
        })();
        if !self.state.uncertain {
            self.close()?;
        }
        let captures = result?;
        let bytes = serde_json::to_vec(&captures).map_err(|e| e.to_string())?;
        self.link.save(&format!("{label}.json"), &bytes)?;
        Ok(captures)
    }
    fn processing(&mut self, pause: bool) -> Result<(), String> {
        if !self.state.gate_closed {
            return Err("processing change requires known closure".into());
        }
        if pause {
            self.state.quiesce_requested = true;
        }
        let mut frame = [0; 64];
        frame[..2].copy_from_slice(&[7, 0x20]);
        frame[7] = u8::from(pause);
        if self.pair(if pause { "quiesce" } else { "resume" }, &frame)? != frame {
            return Err("processing state/status differs".into());
        }
        self.state.quiesced = pause;
        self.state.quiesce_requested = pause;
        Ok(())
    }
    fn program(&mut self, label: &str, at: usize, data: &[u8]) -> Result<(), String> {
        if !self.state.quiesced
            || !self.state.gate_closed
            || self.state.program_intents >= 40
            || !matches!(data.len(), 4 | 32)
            || !self
                .plan
                .pages
                .iter()
                .any(|p| at >= p.address && at + data.len() <= p.address + 64)
        {
            return Err("button programming bounds or state differ".into());
        }
        let mut frame = [0; 64];
        frame[..3].copy_from_slice(&[7, 0x2f, 1]);
        frame[24] = (data.len() / 4) as u8;
        frame[28..32].copy_from_slice(&(at as u32).to_le_bytes());
        frame[32..32 + data.len()].copy_from_slice(data);
        self.state.program_intents += 1;
        self.call(label, CallKind::Set, &frame)?;
        Ok(())
    }
    fn leg(
        &mut self,
        label: &str,
        start: Windows,
        mut goal: Windows,
        recovery: bool,
    ) -> Result<(), String> {
        self.close()?;
        self.identity()?;
        self.processing(true)?;
        let before = self.capture(&format!("{label}-before"), &start, recovery, recovery)?;
        if recovery {
            // A fresh recovery preserves the currently observed selector; it
            // never programs saved state to recreate an older observation.
            goal.insert(0xff40, before[&0xff40].clone());
            self.original.insert(0xff40, before[&0xff40].clone());
            self.target.insert(0xff40, before[&0xff40].clone());
        }
        let mut staged = goal.clone();
        staged.get_mut(&BASE).unwrap()[..4].fill(0xff);
        // The header is invalid throughout all data changes. Every affected
        // 64-byte page is supplied as two ordinary 32-byte programs.
        for off in [0, 32] {
            self.program(
                &format!("{label}-stage"),
                BASE + off,
                &staged[&(BASE + off)],
            )?;
        }
        let mut invalidated = before;
        for off in [0, 32] {
            invalidated.insert(BASE + off, staged[&(BASE + off)].clone());
        }
        self.capture(&format!("{label}-invalidated"), &invalidated, false, false)?;
        let pages: Vec<_> = self.plan.pages.iter().skip(1).map(|p| p.address).collect();
        for at in pages {
            for off in [0, 32] {
                self.program(&format!("{label}-stage"), at + off, &staged[&(at + off)])?;
            }
        }
        self.capture(&format!("{label}-prefix"), &staged, false, false)?;
        // Durable capture and closed gate both precede the marker grant.
        self.program(&format!("{label}-commit"), BASE, &goal[&BASE][..4])?;
        self.capture(&format!("{label}-committed"), &goal, false, false)?;
        self.processing(false)?;
        self.link.settle()?;
        self.capture(&format!("{label}-returned"), &goal, false, false)?;
        self.identity()?;
        Ok(())
    }
    fn execute(mut self) -> (State, T) {
        let result = (|| {
            self.identity()?;
            let initial = self.capture("preflight", &self.reference.clone(), true, false)?;
            // Freeze observed FF45 once; no program ever targets saved state.
            for source in [&mut self.original, &mut self.target] {
                source.insert(0xff40, initial[&0xff40].clone());
            }
            self.link.save(
                "original-sparse.json",
                &serde_json::to_vec(&self.original).map_err(|e| e.to_string())?,
            )?;
            self.link.save(
                "target-sparse.json",
                &serde_json::to_vec(&self.target).map_err(|e| e.to_string())?,
            )?;
            self.state.backup_saved = true;
            self.link.observe("original")?;
            self.leg("edit", self.original.clone(), self.target.clone(), false)?;
            self.state.edited_verified = true;
            self.link.observe("edited")?;
            self.leg("restore", self.target.clone(), self.original.clone(), false)?;
            self.state.original_restored = true;
            self.link.observe("restored")?;
            self.state.complete = true;
            Ok::<_, String>(())
        })();
        if let Err(error) = result {
            self.state.failure = Some(error);
            if !self.state.uncertain {
                let cleanup = if self.state.program_intents > 0 && self.state.backup_saved {
                    self.state.cleanup_attempted = true;
                    self.leg(
                        "cleanup",
                        self.original.clone(),
                        self.original.clone(),
                        true,
                    )
                    .map(|()| self.state.original_restored = true)
                } else {
                    (self.close()).and_then(|()| {
                        if self.state.quiesce_requested {
                            self.processing(false)
                        } else {
                            Ok(())
                        }
                    })
                };
                if let Err(error) = cleanup {
                    self.state.cleanup_failure = Some(error);
                }
            }
        }
        self.state.release_allowed = !self.state.uncertain
            && self.state.gate_closed
            && !self.state.quiesce_requested
            && (self.state.program_intents == 0 || self.state.original_restored);
        (self.state, self.link)
    }
}

impl<'a, T: Link> Session<'a, T> {
    fn inspect(mut self) -> (State, T) {
        let result = (|| {
            self.identity()?;
            let actual = self.capture("preflight", &self.reference.clone(), true, false)?;
            self.link.save(
                "original-sparse.json",
                &serde_json::to_vec(&actual).map_err(|e| e.to_string())?,
            )?;
            self.identity()?;
            self.state.backup_saved = true;
            self.state.original_restored = true;
            self.state.complete = true;
            Ok::<_, String>(())
        })();
        if let Err(error) = result {
            self.state.failure = Some(error);
            if !self.state.uncertain
                && let Err(error) = self.close()
            {
                self.state.cleanup_failure = Some(error);
            }
        }
        self.state.release_allowed = !self.state.uncertain && self.state.gate_closed;
        (self.state, self.link)
    }

    fn recover(mut self, captured: Option<Windows>, possible_program: bool) -> (State, T) {
        let result = (|| {
            if let Some(captured) = captured {
                native::validate_captured(&self.reference, &captured)?;
                for source in [&mut self.original, &mut self.target] {
                    source.insert(0xff40, captured[&0xff40].clone());
                }
            } else if possible_program {
                return Err("recovery lacks saved original authority".into());
            }
            if possible_program {
                self.state.backup_saved = true;
                self.leg(
                    "recovery",
                    self.original.clone(),
                    self.original.clone(),
                    true,
                )?;
            } else {
                self.identity()?;
                let actual =
                    self.capture("recovery-intact", &self.original.clone(), true, false)?;
                self.original.insert(0xff40, actual[&0xff40].clone());
                self.processing(false)?;
                self.link.settle()?;
                self.capture("recovery-returned", &self.original.clone(), false, false)?;
                self.identity()?;
            }
            self.state.original_restored = true;
            self.state.complete = true;
            Ok::<_, String>(())
        })();
        if let Err(error) = result {
            self.state.failure = Some(error);
            if !self.state.uncertain
                && let Err(error) = self.close()
            {
                self.state.cleanup_failure = Some(error);
            }
        }
        self.state.release_allowed = self.state.complete
            && !self.state.uncertain
            && self.state.gate_closed
            && !self.state.quiesce_requested;
        (self.state, self.link)
    }
}

/// The simulation never opens the native transport.
pub fn simulate(
    project: &Path,
    baseline: &Path,
    output: &Path,
    fault: &str,
) -> Result<serde_json::Value, String> {
    model::run(project, baseline, output, fault)
}
