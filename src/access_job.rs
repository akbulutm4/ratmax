//! Fixed temporary RAM-access lifecycle. Pure state and codecs; no I/O.
//! The installed 0028 header exchange is recorded in CHECKPOINT-R3-ACCESS-PHYSICAL.md.
//! Physical dispatch is separately disabled in access_session.
use crate::{
    firmware::sha256,
    model::Core,
    queries::{NormalQuery, NormalReply, OfflineQueryFrame},
    query_session::Binding,
    readback::RuntimeDescriptorReply,
    sensitivity_block::checksums,
    sensitivity_body::conservative_echo,
};
use serde::{Deserialize, Serialize};

pub const IMAGE_BYTES: usize = 0x10000;
pub const BLOCK_BYTES: usize = 32;
pub const BLOCKS: u16 = (IMAGE_BYTES / BLOCK_BYTES) as u16;
pub const MAX_CALLS: u32 = 8222;
pub const SETTINGS_ADDRESSES: [u32; 10] = [
    0xE000, 0xE020, 0xE040, 0xE060, 0xE080, 0xE0A0, 0xE0C0, 0xE0E0, 0xFF40, 0xFF60,
];
pub const SETTINGS_SEEDS: [u8; 2] = [0xA5, 0x5A];
pub const SETTINGS_BYTES: usize = SETTINGS_ADDRESSES.len() * BLOCK_BYTES;
const METADATA_ADDRESS: u32 = 0xFEC0;
const SETTINGS_BASELINE: &str = "7df9e94043deea8ee8fa7e40fd4e6890b00d987c322fb821a9339d066214cb76";
// The first four windows anchor the settings block. The saved-state page can
// change during normal use, so its bytes must agree between fresh passes.
const SETTINGS_ANCHORS: [&str; 4] = [
    "8ad6601eeb8c688c8ea69bfacce0f0634deb03cca93d1c4fb07430fa79155241",
    "ae386283723d2804d1cfa14d3db86b4d5d9b331146d7239cc29a2d38d0336a18",
    "cfdd0c63ced3467651be3bb86f7531872dbe2efd7bd9f8416114fec48879ebe7",
    "9a00f08dbee51404714fcbbe7b01c1034cb6998fcc86e103b0f796a24dc62935",
];
pub const OPEN_BUDGET_MS: u64 = 120_000;
const MAGIC: u32 = 0x2218_4952;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessBaseline {
    pub(crate) binding: Binding,
    pub(crate) identity: Vec<u8>,
    pub(crate) status: Vec<u8>,
    pub(crate) layout: Vec<u8>,
    pub(crate) header: Vec<u8>,
    pub(crate) source_sha256: Vec<String>,
}
impl AccessBaseline {
    pub(crate) fn new(
        binding: Binding,
        raw: [Vec<u8>; 4],
        sources: Vec<String>,
    ) -> Result<Self, String> {
        let [identity, status, layout, header] = raw;
        let b = Self {
            binding,
            identity,
            status,
            layout,
            header,
            source_sha256: sources,
        };
        b.validate()?;
        Ok(b)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.binding.validate()?;
        if self.source_sha256.len() != 4
            || self
                .source_sha256
                .iter()
                .any(|s| s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err("access baseline requires four saved-source hashes".into());
        }
        match OfflineQueryFrame::new(NormalQuery::Identity, 64)
            .map_err(|e| e.to_string())?
            .decode(&self.identity)
            .map_err(|e| e.to_string())?
        {
            NormalReply::Identity {
                core: Core::One,
                version_compare_word: 0x28,
                ..
            } => (),
            _ => return Err("access job restricted to W95 Max/Core 1/version 0028".into()),
        }
        match OfflineQueryFrame::new(NormalQuery::Status, 64)
            .map_err(|e| e.to_string())?
            .decode(&self.status)
            .map_err(|e| e.to_string())?
        {
            NormalReply::Status {
                display_version_word: 0x28,
                ..
            } => (),
            _ => return Err("access status version must be 0028".into()),
        }
        let d = RuntimeDescriptorReply::decode(&self.layout).map_err(|e| e.to_string())?;
        let bases = d.descriptor().bases();
        if bases.sensitivity != 0xE000
            || bases.main_profile != 0xE200
            || bases.additional_profile != 0xFE9C
        {
            return Err("access job requires the saved E000/E200/FE9C layout".into());
        }
        conservative_echo(&read_frame(0x2F, 0xE000, 2), &self.header).map_err(|e| e.to_string())?;
        if self.header[32..36] != [0xA4; 4] {
            return Err("access baseline requires saved A4 header".into());
        }
        Ok(())
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn fingerprint(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("serializable baseline"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureScope {
    Firmware,
    SettingsPages,
    SettingsRecovery,
    BootBank,
}

impl CaptureScope {
    pub const fn max_calls(self) -> u32 {
        match self {
            Self::Firmware => MAX_CALLS,
            Self::SettingsPages => 64,
            Self::SettingsRecovery => 60,
            Self::BootBank => crate::boot_bank::MAX_CALLS,
        }
    }
    const fn uses_metadata_witness(self) -> bool {
        matches!(self, Self::SettingsRecovery | Self::BootBank)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    PreIdentity,
    PreStatus,
    PreLayout,
    PreHeader,
    PreClosed,
    Enable,
    OpenHeader,
    OpenMetadata,
    ProbeMetadata,
    Flash { pass: u8, block: u16 },
    SettingsPage { pass: u8, block: u8 },
    BootVersion { pass: u8 },
    BootBlock { pass: u8, block: u16 },
    AfterHeader { pass: u8 },
    Close,
    VerifyClosed,
    PostIdentity,
    PostStatus,
    PostLayout,
    PostHeader,
    Done,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Set,
    Get,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub number: u32,
    pub phase: Phase,
    pub kind: CallKind,
    pub frame: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "completion", content = "value", rename_all = "snake_case")]
pub enum Completion {
    SetComplete,
    GetComplete(Vec<u8>),
    CompletedFailure(String),
    Uncertain(String),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    Unmodified,
    MayBeOpen,
    OpenVerified,
    CloseRequested,
    ClosedObserved,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassSummary {
    pub pass: u8,
    pub bytes: usize,
    pub sha256: String,
    pub sensitivity_checksums_match: bool,
    pub metadata_matches: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSummary {
    pub phase: Phase,
    pub calls_granted: u32,
    pub enable_assignments_granted: u8,
    pub close_assignments_granted: u8,
    pub gate: Gate,
    pub open_header_witness: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_metadata_witness: Option<bool>,
    pub primary_failure: Option<String>,
    pub cleanup_failure: Option<String>,
    pub uncertain: bool,
    pub first_pass_bytes: usize,
    pub second_pass_bytes: usize,
    pub passes: Vec<PassSummary>,
    pub two_pass_image_consistent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_seed_settings_pages_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_seed_boot_preflight_match: Option<bool>,
    pub post_normal_verified: bool,
    pub terminal: bool,
    pub complete: bool,
    pub release_lock_allowed: bool,
    pub exact_prior_key_restored: bool,
    pub full_configuration_backup: bool,
}
#[derive(Clone)]
pub struct AccessJob {
    baseline: AccessBaseline,
    scope: CaptureScope,
    phase: Phase,
    get_next: bool,
    pending: Option<Step>,
    calls: u32,
    gate: Gate,
    open_witness: bool,
    enable: u8,
    close: u8,
    primary: Option<String>,
    cleanup: Option<String>,
    uncertain: bool,
    images: [Vec<u8>; 2],
    passes: Vec<PassSummary>,
    consistent: bool,
    post_verified: bool,
    opened_at: Option<u64>,
    last_clock: u64,
    boot_version: Option<[u8; 4]>,
}
pub(crate) fn read_frame(op: u8, address: u32, count: u32) -> [u8; 64] {
    let mut r = [0; 64];
    r[..3].copy_from_slice(&[7, op, 0]);
    r[24..28].copy_from_slice(&count.to_le_bytes());
    r[28..32].copy_from_slice(&address.to_le_bytes());
    r
}
pub(crate) fn key_frame(value: u32) -> [u8; 64] {
    let mut r = [0; 64];
    r[..3].copy_from_slice(&[7, 0x25, 0]);
    r[4..8].copy_from_slice(&MAGIC.to_le_bytes());
    r[8..12].copy_from_slice(&value.to_le_bytes());
    r
}
impl AccessJob {
    pub fn new(baseline: AccessBaseline) -> Result<Self, String> {
        Self::with_scope(baseline, CaptureScope::Firmware)
    }
    pub fn with_scope(baseline: AccessBaseline, scope: CaptureScope) -> Result<Self, String> {
        baseline.validate()?;
        if scope != CaptureScope::Firmware && baseline.fingerprint() != SETTINGS_BASELINE {
            return Err(
                "settings-page readback requires the reviewed installed 0028 baseline".into(),
            );
        }
        Ok(Self {
            baseline,
            scope,
            phase: Phase::PreIdentity,
            get_next: false,
            pending: None,
            calls: 0,
            gate: Gate::Unmodified,
            open_witness: false,
            enable: 0,
            close: 0,
            primary: None,
            cleanup: None,
            uncertain: false,
            images: [Vec::new(), Vec::new()],
            passes: Vec::new(),
            consistent: false,
            post_verified: false,
            opened_at: None,
            last_clock: 0,
            boot_version: None,
        })
    }
    pub fn baseline(&self) -> &AccessBaseline {
        &self.baseline
    }
    pub const fn scope(&self) -> CaptureScope {
        self.scope
    }
    fn stage(&mut self, p: Phase) {
        self.phase = p;
        self.get_next = false;
    }
    fn frame(&self) -> [u8; 64] {
        use Phase::*;
        match self.phase {
            PreIdentity | PostIdentity => OfflineQueryFrame::new(NormalQuery::Identity, 64)
                .expect("fixed")
                .request()
                .try_into()
                .expect("64"),
            PreStatus | PostStatus => OfflineQueryFrame::new(NormalQuery::Status, 64)
                .expect("fixed")
                .request()
                .try_into()
                .expect("64"),
            PreLayout | PostLayout => crate::readback::descriptor_request(),
            PreHeader | PostHeader => read_frame(0x2F, 0xE000, 2),
            Enable => key_frame(MAGIC),
            Close => key_frame(0),
            OpenMetadata | ProbeMetadata => read_frame(2, METADATA_ADDRESS, 8),
            PreClosed | VerifyClosed if self.scope.uses_metadata_witness() => {
                read_frame(2, METADATA_ADDRESS, 8)
            }
            Flash { block, .. } => read_frame(2, u32::from(block) * 32, 8),
            SettingsPage { pass, block } => {
                let mut frame = read_frame(2, SETTINGS_ADDRESSES[usize::from(block)], 8);
                frame[32..].fill(SETTINGS_SEEDS[usize::from(pass)]);
                frame
            }
            BootVersion { pass } => {
                let mut frame = read_frame(2, crate::boot_bank::BANK_BASE + 0xbfc, 1);
                frame[32..].fill(SETTINGS_SEEDS[usize::from(pass)]);
                frame
            }
            BootBlock { pass, block } => {
                let mut frame =
                    read_frame(2, crate::boot_bank::address(block).expect("fixed block"), 8);
                frame[32..].fill(SETTINGS_SEEDS[usize::from(pass)]);
                frame
            }
            _ => read_frame(2, 0xE000, 2),
        }
    }
    /// One immutable next step. Caller journals/fsyncs this before begin/dispatch.
    pub fn next_step(&self) -> Option<Step> {
        if self.phase == Phase::Done || self.pending.is_some() {
            return None;
        }
        Some(Step {
            number: self.calls,
            phase: self.phase,
            kind: if self.get_next {
                CallKind::Get
            } else {
                CallKind::Set
            },
            frame: self.frame().to_vec(),
        })
    }
    /// Mark intent BEFORE dispatch. Even a failed enable call may have taken effect.
    pub fn begin(&mut self, step: &Step) -> Result<(), String> {
        if self.next_step().as_ref() != Some(step) || self.calls >= self.scope.max_calls() {
            self.mark_uncertain("out-of-order, forged or excessive access grant");
            return Err("invalid access grant".into());
        }
        if step.phase == Phase::Enable {
            self.enable += 1;
            self.gate = Gate::MayBeOpen;
            self.opened_at = Some(self.last_clock);
        }
        if step.phase == Phase::Close {
            self.close += 1;
            self.gate = Gate::CloseRequested;
        }
        self.calls += 1;
        self.pending = Some(step.clone());
        Ok(())
    }
    pub fn mark_uncertain(&mut self, reason: impl Into<String>) {
        if self.primary.is_none() {
            self.primary = Some(reason.into());
        }
        self.uncertain = true;
        if !matches!(self.gate, Gate::Unmodified | Gate::ClosedObserved) {
            self.gate = Gate::Unknown;
        }
        self.pending = None;
        self.stage(Phase::Done);
    }
    /// Called between completed calls. Expiry schedules cleanup, never cancels I/O.
    pub fn tick(&mut self, elapsed_ms: u64) {
        if elapsed_ms < self.last_clock {
            self.mark_uncertain("non-monotonic access clock");
            return;
        }
        self.last_clock = elapsed_ms;
        if self.phase == Phase::Enable && self.opened_at.is_none() {
            self.opened_at = Some(elapsed_ms);
        }
        if self.pending.is_none()
            && self.close == 0
            && self.enable != 0
            && self.phase != Phase::Done
            && self
                .opened_at
                .is_some_and(|start| elapsed_ms.saturating_sub(start) >= OPEN_BUDGET_MS)
        {
            self.fail("open-window time budget expired".into());
        }
    }
    fn fail(&mut self, reason: String) {
        if self.primary.is_none() {
            self.primary = Some(reason.clone());
        }
        if self.close != 0 {
            if self.cleanup.is_none() {
                self.cleanup = Some(reason);
            }
            self.stage(Phase::Done);
        } else if self.enable != 0 {
            self.stage(Phase::Close);
        } else {
            self.stage(Phase::Done);
        }
    }
    pub fn finish(
        &mut self,
        number: u32,
        result: Completion,
        binding_matches: bool,
    ) -> Result<(), String> {
        let Some(step) = self.pending.take() else {
            self.mark_uncertain("completion without grant");
            return Err("no pending access call".into());
        };
        if step.number != number {
            self.mark_uncertain("wrong access completion number");
            return Err("wrong access completion number".into());
        }
        if !binding_matches {
            self.mark_uncertain("device binding changed/lost; no cleanup traffic");
            return Ok(());
        }
        match result {
            Completion::Uncertain(e) => {
                self.mark_uncertain(e);
                return Ok(());
            }
            Completion::CompletedFailure(e) => {
                if step.phase == Phase::Close {
                    self.cleanup = Some(e.clone());
                    if self.primary.is_none() {
                        self.primary = Some(e);
                    }
                    self.stage(Phase::VerifyClosed);
                } else {
                    self.fail(e);
                }
                return Ok(());
            }
            Completion::SetComplete if step.kind == CallKind::Set => {
                match step.phase {
                    Phase::Enable => {
                        self.stage(if self.scope.uses_metadata_witness() {
                            Phase::OpenMetadata
                        } else {
                            Phase::OpenHeader
                        });
                    }
                    Phase::Close => self.stage(Phase::VerifyClosed),
                    _ => self.get_next = true,
                }
                return Ok(());
            }
            Completion::GetComplete(raw) if step.kind == CallKind::Get => {
                if let Err(e) = self.consume(&step, &raw) {
                    self.fail(e);
                }
                return Ok(());
            }
            _ => (),
        }
        self.mark_uncertain("worker completion kind differs from granted call");
        Err("worker completion mismatch".into())
    }
    fn consume(&mut self, step: &Step, raw: &[u8]) -> Result<(), String> {
        let expected: [u8; 64] = step.frame.as_slice().try_into().expect("fixed frame");
        if raw.len() != 64 {
            return Err("access reply must contain exactly 64 bytes".into());
        }
        use Phase::*;
        match step.phase {
            PreIdentity | PostIdentity => {
                if raw != self.baseline.identity {
                    return Err("normal identity differs from saved baseline".into());
                }
            }
            PreStatus | PostStatus => {
                if raw != self.baseline.status {
                    return Err("normal status/metadata differs from saved baseline".into());
                }
            }
            PreLayout | PostLayout => {
                if raw != self.baseline.layout {
                    return Err("normal layout differs from saved baseline".into());
                }
            }
            _ => conservative_echo(&expected, raw).map_err(|e| e.to_string())?,
        }
        match step.phase {
            PreHeader | PostHeader => {
                if raw != self.baseline.header {
                    return Err("sensitivity header unavailable/changed".into());
                }
            }
            OpenHeader | AfterHeader { .. } => {
                let mut observed_open = expected;
                observed_open[32..40].copy_from_slice(&self.baseline.header[32..40]);
                if raw != observed_open {
                    return Err("02 header differs from the observed enabled reply".into());
                }
            }
            PreClosed | VerifyClosed => {
                if raw != expected {
                    return Err("expected exact closed-gate selector echo; closure unproven".into());
                }
            }
            ProbeMetadata | OpenMetadata => {
                if step.phase == OpenMetadata && raw[..32] != expected[..32] {
                    return Err("02 metadata reply changed its selector".into());
                }
                if raw[32..64] != self.baseline.status[8..40] {
                    return Err("02 metadata probe differs from the saved 2D payload".into());
                }
            }
            Flash { pass, block } => {
                let offset = usize::from(block) * 32;
                if pass > 1 || block >= BLOCKS || self.images[usize::from(pass)].len() != offset {
                    return Err("invalid flash cursor".into());
                }
                self.images[usize::from(pass)].extend_from_slice(&raw[32..64]);
                if block == 0 {
                    let sp = u32::from_le_bytes(raw[32..36].try_into().expect("4"));
                    let reset = u32::from_le_bytes(raw[36..40].try_into().expect("4"));
                    if !(0x20000000..=0x20002000).contains(&sp)
                        || sp % 8 != 0
                        || reset & 1 == 0
                        || !(0xC1..0x10000).contains(&reset)
                    {
                        return Err(
                            "firmware vector candidates fail the fixed geometry check".into()
                        );
                    }
                }
                if pass == 1 && self.images[0][offset..offset + 32] != raw[32..64] {
                    return Err("firmware passes differ; stop capture and close gate".into());
                }
            }
            SettingsPage { pass, block } => {
                self.record_settings_page(pass, block, &expected, raw)?
            }
            BootVersion { pass } => {
                if raw[..32] != expected[..32] || raw[36..] != expected[36..] {
                    return Err("boot version reply changed bytes outside its DWORD".into());
                }
                let version: [u8; 4] = raw[32..36].try_into().expect("4");
                if pass == 0 {
                    self.boot_version = Some(version);
                } else if self.boot_version != Some(version) {
                    return Err("seeded boot version reads differ".into());
                }
            }
            BootBlock { pass, block } => {
                if raw[..32] != expected[..32] {
                    return Err("boot bank reply changed its selector".into());
                }
                let index = usize::from(pass);
                let offset = usize::from(block) * BLOCK_BYTES;
                crate::boot_bank::validate_block(block, &raw[32..], &self.images[index])?;
                if pass == 1 && self.images[0][offset..offset + BLOCK_BYTES] != raw[32..] {
                    return Err("seeded boot preflight passes differ".into());
                }
                self.images[index].extend_from_slice(&raw[32..]);
                if usize::from(block) + 1 == crate::boot_bank::BANK_BLOCKS
                    && self.boot_version.as_ref().map(|value| value.as_slice())
                        != Some(&raw[60..64])
                {
                    return Err("boot bank version differs from initial DWORD reads".into());
                }
                if self.images[index].len() == crate::boot_bank::PASS_BYTES {
                    let settings = crate::boot_bank::settings(&self.images[index])?;
                    let (sum, weighted) = checksums(&settings[..256])?;
                    if settings[..8] != self.baseline.header[32..40]
                        || settings[4..6] != sum.to_le_bytes()
                        || settings[6..8] != weighted.to_le_bytes()
                    {
                        return Err("boot preflight settings fail saved header or checksums".into());
                    }
                }
            }
            _ => (),
        }
        if step.phase == Phase::VerifyClosed && !self.open_witness {
            return Err(if self.scope.uses_metadata_witness() {
                "closure is unproven without a prior matching 02 metadata read".into()
            } else {
                "closure is unproven without a prior matching 02 header read".into()
            });
        }
        let next = match step.phase {
            PreIdentity => PreStatus,
            PreStatus => PreLayout,
            PreLayout if self.scope.uses_metadata_witness() => PreClosed,
            PreLayout => PreHeader,
            PreHeader => PreClosed,
            PreClosed => Enable,
            OpenHeader | OpenMetadata => {
                self.gate = Gate::OpenVerified;
                self.open_witness = true;
                match self.scope {
                    CaptureScope::Firmware => ProbeMetadata,
                    CaptureScope::SettingsPages | CaptureScope::SettingsRecovery => {
                        SettingsPage { pass: 0, block: 0 }
                    }
                    CaptureScope::BootBank => BootVersion { pass: 0 },
                }
            }
            BootVersion { pass: 0 } => BootVersion { pass: 1 },
            BootVersion { .. } => BootBlock { pass: 0, block: 0 },
            BootBlock { pass, block } => {
                if usize::from(block) + 1 < crate::boot_bank::BLOCKS {
                    BootBlock {
                        pass,
                        block: block + 1,
                    }
                } else if pass == 0 {
                    BootBlock { pass: 1, block: 0 }
                } else {
                    self.consistent = true;
                    Close
                }
            }
            ProbeMetadata => Flash { pass: 0, block: 0 },
            Flash { pass, block } => {
                if block + 1 == BLOCKS {
                    AfterHeader { pass }
                } else {
                    Flash {
                        pass,
                        block: block + 1,
                    }
                }
            }
            AfterHeader { pass } => {
                self.validate_image(pass)?;
                if pass == 0 {
                    Flash { pass: 1, block: 0 }
                } else {
                    self.consistent = true;
                    Close
                }
            }
            SettingsPage { pass, block } => {
                if usize::from(block) + 1 < SETTINGS_ADDRESSES.len() {
                    SettingsPage {
                        pass,
                        block: block + 1,
                    }
                } else if pass == 0 {
                    SettingsPage { pass: 1, block: 0 }
                } else {
                    if self.images[0] != self.images[1] {
                        return Err("seeded recovery passes differ".into());
                    }
                    self.consistent = true;
                    Close
                }
            }
            VerifyClosed => {
                self.gate = Gate::ClosedObserved;
                PostIdentity
            }
            PostIdentity => PostStatus,
            PostStatus => PostLayout,
            PostLayout if !self.scope.uses_metadata_witness() => PostHeader,
            PostLayout | PostHeader => {
                self.post_verified = true;
                Done
            }
            _ => return Err("Get is not valid at this stage".into()),
        };
        self.stage(next);
        Ok(())
    }
    fn record_settings_page(
        &mut self,
        pass: u8,
        block: u8,
        expected: &[u8; 64],
        raw: &[u8],
    ) -> Result<(), String> {
        let pass = usize::from(pass);
        let block = usize::from(block);
        let offset = block * BLOCK_BYTES;
        if pass > 1 || block >= SETTINGS_ADDRESSES.len() || self.images[pass].len() != offset {
            return Err("invalid settings-page cursor".into());
        }
        if raw[..32] != expected[..32] {
            return Err("seeded settings reply changed its selector".into());
        }
        let data = &raw[32..];
        if self.scope == CaptureScope::SettingsRecovery {
            self.images[pass].extend_from_slice(data);
            return Ok(());
        }
        if data == &expected[32..] {
            return Err("seeded settings reply retained all seed bytes".into());
        }
        if let Some(anchor) = SETTINGS_ANCHORS.get(block)
            && sha256(data) != *anchor
        {
            return Err(format!(
                "saved settings data changed at {:04X}",
                SETTINGS_ADDRESSES[block]
            ));
        }
        if pass == 1 && self.images[0][offset..offset + BLOCK_BYTES] != *data {
            return Err(format!(
                "seeded settings passes differ at {:04X}",
                SETTINGS_ADDRESSES[block]
            ));
        }
        self.images[pass].extend_from_slice(data);
        if self.images[pass].len() == SETTINGS_BYTES {
            let settings = &self.images[pass][..256];
            let (sum, weighted) = checksums(settings)?;
            if settings[..8] != self.baseline.header[32..40]
                || settings[4..6] != sum.to_le_bytes()
                || settings[6..8] != weighted.to_le_bytes()
            {
                return Err("seeded settings block fails its saved header or checksums".into());
            }
        }
        Ok(())
    }
    fn validate_image(&mut self, pass: u8) -> Result<(), String> {
        let image = &self.images[usize::from(pass)];
        if image.len() != IMAGE_BYTES {
            return Err("incomplete internal-flash candidate".into());
        }
        let sensitivity = &image[0xE000..0xE100];
        let (sum, weighted) = checksums(sensitivity)?;
        let good_header = sensitivity[..8] == self.baseline.header[32..40];
        let sums = sum == u16::from_le_bytes(sensitivity[4..6].try_into().expect("2"))
            && weighted == u16::from_le_bytes(sensitivity[6..8].try_into().expect("2"));
        let metadata = image[0xFEC0..0xFEE0] == self.baseline.status[8..40];
        self.passes.push(PassSummary {
            pass,
            bytes: image.len(),
            sha256: sha256(image),
            sensitivity_checksums_match: good_header && sums,
            metadata_matches: metadata,
        });
        if !good_header || !sums {
            return Err("captured sensitivity header/checksums disagree".into());
        }
        if !metadata {
            return Err("captured firmware metadata differs from baseline".into());
        }
        Ok(())
    }
    pub fn images(&self) -> [&[u8]; 2] {
        [&self.images[0], &self.images[1]]
    }
    pub fn summary(&self) -> JobSummary {
        let terminal = self.phase == Phase::Done;
        let safe_closed = self.gate == Gate::ClosedObserved && self.post_verified;
        JobSummary {
            phase: self.phase,
            calls_granted: self.calls,
            enable_assignments_granted: self.enable,
            close_assignments_granted: self.close,
            gate: self.gate,
            open_header_witness: !self.scope.uses_metadata_witness() && self.open_witness,
            open_metadata_witness: self
                .scope
                .uses_metadata_witness()
                .then_some(self.open_witness),
            primary_failure: self.primary.clone(),
            cleanup_failure: self.cleanup.clone(),
            uncertain: self.uncertain,
            first_pass_bytes: self.images[0].len(),
            second_pass_bytes: self.images[1].len(),
            passes: self.passes.clone(),
            two_pass_image_consistent: self.scope == CaptureScope::Firmware && self.consistent,
            two_seed_settings_pages_match: matches!(
                self.scope,
                CaptureScope::SettingsPages | CaptureScope::SettingsRecovery
            )
            .then_some(self.consistent),
            two_seed_boot_preflight_match: (self.scope == CaptureScope::BootBank)
                .then_some(self.consistent),
            post_normal_verified: self.post_verified,
            terminal,
            complete: terminal
                && safe_closed
                && self.consistent
                && self.primary.is_none()
                && self.cleanup.is_none()
                && !self.uncertain,
            release_lock_allowed: terminal
                && !self.uncertain
                && (self.gate == Gate::Unmodified || safe_closed),
            exact_prior_key_restored: false,
            full_configuration_backup: false,
        }
    }
}
