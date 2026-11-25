//! Offline fixtures and deterministic failure scenarios for the RAM-access job.
use crate::{access_job::*, firmware::sha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessScenario {
    Nominal,
    PreflightChanged,
    AlreadyOpen,
    UnlockCompletedFailure,
    UnlockUncertain,
    HeaderEcho,
    MetadataProbeEcho,
    MetadataProbeChanged,
    FirstReadMalformed,
    ChecksumMismatch,
    MetadataMismatch,
    SecondPassChanged,
    ReadCompletedFailure,
    ReadUncertain,
    BindingChanged,
    OpenBudgetExpired,
    CloseCompletedFailure,
    CloseUncertain,
    CloseStillOpen,
    CloseReplyMalformed,
    PostIdentityChanged,
}
impl AccessScenario {
    pub const ALL: [Self; 21] = [
        Self::Nominal,
        Self::PreflightChanged,
        Self::AlreadyOpen,
        Self::UnlockCompletedFailure,
        Self::UnlockUncertain,
        Self::HeaderEcho,
        Self::MetadataProbeEcho,
        Self::MetadataProbeChanged,
        Self::FirstReadMalformed,
        Self::ChecksumMismatch,
        Self::MetadataMismatch,
        Self::SecondPassChanged,
        Self::ReadCompletedFailure,
        Self::ReadUncertain,
        Self::BindingChanged,
        Self::OpenBudgetExpired,
        Self::CloseCompletedFailure,
        Self::CloseUncertain,
        Self::CloseStillOpen,
        Self::CloseReplyMalformed,
        Self::PostIdentityChanged,
    ];
    pub fn name(self) -> String {
        serde_json::to_value(self)
            .expect("scenario")
            .as_str()
            .expect("name")
            .into()
    }
    pub fn parse(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|v| v.name() == s)
            .ok_or_else(|| "unknown access simulation scenario".into())
    }
}
#[derive(Debug, Serialize)]
pub struct SimulationSummary {
    pub mode: &'static str,
    pub scenario: AccessScenario,
    pub physical_execution_available: bool,
    pub synthetic_image_sha256: String,
    pub result: JobSummary,
}

fn synthetic_settings_block() -> [u8; 256] {
    let mut block = [0u8; 256];
    block[..8].copy_from_slice(&[0xa4, 0xa4, 0xa4, 0xa4, 0x2d, 0x93, 0x80, 0x9d]);
    block[252..256].copy_from_slice(&[0xd3, 0x65, 0x5a, 0x2d]);
    block
}

/// This image is fabricated, including its checksum-collision settings fixture.
/// It is never a device backup, packaged firmware, or executable image.
pub fn synthetic_image(b: &AccessBaseline) -> Vec<u8> {
    let mut image: Vec<u8> = (0..IMAGE_BYTES)
        .map(|i| (i.wrapping_mul(17).wrapping_add(73) & 255) as u8)
        .collect();
    image[..4].copy_from_slice(&0x20000CB0u32.to_le_bytes());
    image[4..8].copy_from_slice(&0x8055u32.to_le_bytes());
    image[0xE000..0xE100].copy_from_slice(&synthetic_settings_block());
    // Metadata is copied from the saved observation only to exercise consistency checks.
    image[0xFEC0..0xFEE0].copy_from_slice(&b.status[8..40]);
    image
}
pub fn completion(
    step: &Step,
    baseline: &AccessBaseline,
    image: &[u8],
    scenario: AccessScenario,
) -> Completion {
    use AccessScenario as S;
    use Phase as P;
    match (scenario, step.phase, step.kind) {
        (S::UnlockUncertain, P::Enable, _) => {
            return Completion::Uncertain("injected uncertain enable".into());
        }
        (S::UnlockCompletedFailure, P::Enable, _) => {
            return Completion::CompletedFailure("injected completed enable failure".into());
        }
        (S::CloseUncertain, P::Close, _) => {
            return Completion::Uncertain("injected uncertain close".into());
        }
        (S::CloseCompletedFailure, P::Close, _) => {
            return Completion::CompletedFailure("injected completed close failure".into());
        }
        (S::ReadUncertain, P::Flash { pass: 0, block: 2 }, CallKind::Get) => {
            return Completion::Uncertain("injected uncertain read".into());
        }
        (S::ReadCompletedFailure, P::Flash { pass: 0, block: 2 }, CallKind::Get) => {
            return Completion::CompletedFailure("injected completed read failure".into());
        }
        _ => (),
    }
    if step.kind == CallKind::Set {
        return Completion::SetComplete;
    }
    let saved = |key: &str| match key {
        "identity" => &baseline.identity,
        "status" => &baseline.status,
        "layout" => &baseline.layout,
        _ => &baseline.header,
    };
    let mut raw = match step.phase {
        P::PreIdentity | P::PostIdentity => saved("identity").clone(),
        P::PreStatus | P::PostStatus => saved("status").clone(),
        P::PreLayout | P::PostLayout => saved("layout").clone(),
        P::PreHeader | P::PostHeader => saved("header").clone(),
        _ => step.frame.clone(),
    };
    match step.phase {
        P::OpenHeader | P::AfterHeader { .. } => {
            raw[32..40].copy_from_slice(&saved("header")[32..40])
        }
        P::OpenMetadata | P::ProbeMetadata => {
            raw[32..64].copy_from_slice(&saved("status")[8..40]);
        }
        P::Flash { block, .. } => {
            let a = usize::from(block) * 32;
            raw[32..64].copy_from_slice(&image[a..a + 32]);
        }
        _ => (),
    }
    match (scenario, step.phase) {
        (S::PreflightChanged, P::PreIdentity) | (S::PostIdentityChanged, P::PostIdentity) => {
            raw[10] ^= 1
        }
        (S::AlreadyOpen, P::PreClosed) | (S::CloseStillOpen, P::VerifyClosed) => {
            raw[32..40].copy_from_slice(&saved("header")[32..40])
        }
        (S::HeaderEcho, P::OpenHeader) => raw[32..40].fill(0),
        (S::MetadataProbeEcho, P::ProbeMetadata) => raw[32..64].fill(0),
        (S::MetadataProbeChanged, P::ProbeMetadata) => raw[32] ^= 1,
        (S::FirstReadMalformed, P::Flash { pass: 0, block: 0 })
        | (S::CloseReplyMalformed, P::VerifyClosed) => {
            raw.pop();
        }
        (
            S::ChecksumMismatch,
            P::Flash {
                pass: 0,
                block: 1792,
            },
        ) => raw[40] ^= 1,
        (
            S::MetadataMismatch,
            P::Flash {
                pass: 0,
                block: 2038,
            },
        ) => raw[32] ^= 1,
        (S::SecondPassChanged, P::Flash { pass: 1, block: 2 }) => raw[40] ^= 1,
        _ => (),
    }
    Completion::GetComplete(raw)
}
pub fn simulate(
    baseline: AccessBaseline,
    scenario: AccessScenario,
) -> Result<(SimulationSummary, AccessJob), String> {
    let image = synthetic_image(&baseline);
    let mut job = AccessJob::new(baseline)?;
    let mut clock = 0u64;
    while job.next_step().is_some() {
        let expire = scenario == AccessScenario::OpenBudgetExpired
            && matches!(job.summary().phase, Phase::Flash { pass: 0, block: 2 });
        clock = if expire {
            clock.max(OPEN_BUDGET_MS + 1)
        } else {
            clock + 1
        };
        job.tick(clock);
        let Some(step) = job.next_step() else {
            break;
        };
        let result = completion(&step, job.baseline(), &image, scenario);
        job.begin(&step)?;
        let binding_matches = !(scenario == AccessScenario::BindingChanged
            && matches!(step.phase, Phase::Flash { pass: 0, block: 2 }));
        job.finish(step.number, result, binding_matches)?;
    }
    Ok((
        SimulationSummary {
            mode: "offline_access_simulation",
            scenario,
            physical_execution_available: false,
            synthetic_image_sha256: sha256(&image),
            result: job.summary(),
        },
        job,
    ))
}
