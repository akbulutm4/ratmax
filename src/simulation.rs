//! Deterministic memory-only lifecycle tests. Unknown upgrade/finalization
//! semantics are explicit abstract assumptions, never invented report payloads.

use std::str::FromStr;

use serde::Serialize;

use crate::{
    firmware::{self, EncodedRecord, LOCAL_BUFFER_LEN},
    model::Core,
    plan::{Blocker, FirmwarePlan, Stage},
    protocol::{self, DeviceValue, FinalBlock, GENERIC_LOCAL_LEN, ProtocolError, Query},
    transport::{
        Call, ExpectedCall, LocalFeatureTransport, MockTransport, TransportError, TransportFailure,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    Nominal,
    PreflightReadFailed,
    PreflightBadHeader,
    PreflightShortReply,
    PreflightErased,
    RecordSetFailed,
    RecordGetFailed,
    RecordDisconnect,
    RecordRejected,
    RecordShortReply,
    RecordBadReportId,
    FinalBlockReadFailed,
    FinalBlockBadHeader,
    FinalizationFailed,
    ResetFailed,
    ReturnTimeout,
    WrongDevice,
    WrongModel,
    AmbiguousReturn,
    WrongCore,
    WrongVersion,
    WrongBootDevice,
}

impl Scenario {
    pub const ALL: [Self; 22] = [
        Self::Nominal,
        Self::PreflightReadFailed,
        Self::PreflightBadHeader,
        Self::PreflightShortReply,
        Self::PreflightErased,
        Self::RecordSetFailed,
        Self::RecordGetFailed,
        Self::RecordDisconnect,
        Self::RecordRejected,
        Self::RecordShortReply,
        Self::RecordBadReportId,
        Self::FinalBlockReadFailed,
        Self::FinalBlockBadHeader,
        Self::FinalizationFailed,
        Self::ResetFailed,
        Self::ReturnTimeout,
        Self::WrongDevice,
        Self::WrongModel,
        Self::AmbiguousReturn,
        Self::WrongCore,
        Self::WrongVersion,
        Self::WrongBootDevice,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::PreflightReadFailed => "preflight-read-failed",
            Self::PreflightBadHeader => "preflight-bad-header",
            Self::PreflightShortReply => "preflight-short-reply",
            Self::PreflightErased => "preflight-erased",
            Self::RecordSetFailed => "record-set-failed",
            Self::RecordGetFailed => "record-get-failed",
            Self::RecordDisconnect => "record-disconnect",
            Self::RecordRejected => "record-rejected",
            Self::RecordShortReply => "record-short-reply",
            Self::RecordBadReportId => "record-bad-report-id",
            Self::FinalBlockReadFailed => "final-block-read-failed",
            Self::FinalBlockBadHeader => "final-block-bad-header",
            Self::FinalizationFailed => "finalization-failed",
            Self::ResetFailed => "reset-failed",
            Self::ReturnTimeout => "return-timeout",
            Self::WrongDevice => "wrong-device",
            Self::WrongModel => "wrong-model",
            Self::AmbiguousReturn => "ambiguous-return",
            Self::WrongCore => "wrong-core",
            Self::WrongVersion => "wrong-version",
            Self::WrongBootDevice => "wrong-boot-device",
        }
    }

    pub const fn is_record_fault(self) -> bool {
        matches!(
            self,
            Self::RecordSetFailed
                | Self::RecordGetFailed
                | Self::RecordDisconnect
                | Self::RecordRejected
                | Self::RecordShortReply
                | Self::RecordBadReportId
        )
    }
}

impl FromStr for Scenario {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|scenario| scenario.name() == value)
            .ok_or_else(|| format!("unknown simulation scenario {value:?}; see --help"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SimulationConfig {
    scenario: Scenario,
    record_index: usize,
}

impl SimulationConfig {
    pub fn new(scenario: Scenario, record_index: Option<usize>) -> Result<Self, String> {
        if record_index.is_some() && !scenario.is_record_fault() {
            return Err("--record-index applies only to record fault scenarios".into());
        }
        let index = record_index.unwrap_or(firmware::RECORD_COUNT / 2);
        if index >= firmware::RECORD_COUNT {
            return Err(format!(
                "record index must be 0..{}",
                firmware::RECORD_COUNT - 1
            ));
        }
        Ok(Self {
            scenario,
            record_index: index,
        })
    }

    pub const fn nominal() -> Self {
        Self {
            scenario: Scenario::Nominal,
            record_index: firmware::RECORD_COUNT / 2,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobFailure {
    Transport { error: TransportError },
    Protocol { error: ProtocolError },
    FinalizationFailed,
    ReturnTimeout,
    AmbiguousReturn,
    UnitMismatch { expected: String, actual: String },
    ModelMismatch { expected: u16, actual: u16 },
    CoreMismatch { expected: Core, actual: Core },
    VersionMismatch { expected: String, actual: String },
    ScriptIncomplete { remaining: usize },
}

impl From<TransportError> for JobFailure {
    fn from(error: TransportError) -> Self {
        Self::Transport { error }
    }
}
impl From<ProtocolError> for JobFailure {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol { error }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    ErasedDeviceValueNeedsPolicy,
    ConfigurationUnavailable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Blocked { stage: Stage, reason: BlockReason },
    Failed { stage: Stage, reason: JobFailure },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JobEvent {
    Entered { stage: Stage },
    Assumed { stage: Stage, detail: &'static str },
    RecordsAcknowledged { count: usize, total: usize },
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Milestones {
    pub preflight_read: bool,
    pub records_attempted: usize,
    pub records_acknowledged: usize,
    pub last_attempted_record_index: Option<usize>,
    pub record_delivery_uncertain: bool,
    pub final_block_read: bool,
    pub finalization_assumed: bool,
    pub reset_for_normal_accepted_by_mock: bool,
    pub return_matched_in_simulation: bool,
    pub configuration_applied: bool,
    pub firmware_readback_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulatedObservation {
    pub synthetic_unit_id: String,
    pub model_id: u16,
    pub core: Core,
    pub synthetic_version_marker: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficSummary {
    pub set_calls: usize,
    pub get_calls: usize,
    pub unconsumed_script_calls: usize,
    pub record_request_sha256: String,
    pub last_set_buffer: Option<Vec<u8>>,
    pub last_call: Option<Call>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationReport {
    pub schema_version: u32,
    pub mode: &'static str,
    pub plan_sha256: String,
    pub core: Core,
    pub scenario: Scenario,
    pub fault_record_index: Option<usize>,
    pub live_execution_available: bool,
    pub live_blockers: Vec<Blocker>,
    pub assumptions: Vec<&'static str>,
    pub outcome: Outcome,
    pub milestones: Milestones,
    pub return_candidates: Vec<SimulatedObservation>,
    pub events: Vec<JobEvent>,
    pub traffic: TrafficSummary,
    pub retry_count: usize,
}

impl SimulationReport {
    pub fn text(&self) -> String {
        format!(
            "ratmax | SIMULATION ONLY | {}\nPlan SHA-256: {}\nScenario: {}\nOutcome: {:?}\nMock records acknowledged: {}/{} (attempted {})\nFinalization assumed: {}\nReset accepted by mock: {}\nSynthetic return matched: {}\nConfiguration applied: {}\nFirmware readback verified: {}\nRetries: {}\nMock calls: {} Set, {} Get\nRecord request SHA-256: {}\nLive execution: BLOCKED\nUnknown entry/finalization policy is abstract; no guessed payload emitted.\nNo mouse accessed.\n",
            self.core,
            self.plan_sha256,
            self.scenario.name(),
            self.outcome,
            self.milestones.records_acknowledged,
            firmware::RECORD_COUNT,
            self.milestones.records_attempted,
            self.milestones.finalization_assumed,
            self.milestones.reset_for_normal_accepted_by_mock,
            self.milestones.return_matched_in_simulation,
            self.milestones.configuration_applied,
            self.milestones.firmware_readback_verified,
            self.retry_count,
            self.traffic.set_calls,
            self.traffic.get_calls,
            self.traffic.record_request_sha256,
        )
    }
}

const UNIT: &str = "synthetic-unit-a";
const VERSION: &str = "synthetic-version-a";

/// The public entry point constructs a concrete in-memory mock internally.
/// It cannot take a live transport or override the plan's hardware blockers.
pub fn simulate(plan: &FirmwarePlan, config: SimulationConfig) -> SimulationReport {
    let mut transport = MockTransport::new(script(plan, config));
    let mut session = Session {
        plan,
        config,
        transport: &mut transport,
        stage: Stage::EnterUpgrade,
        milestones: Milestones::default(),
        events: Vec::new(),
        candidates: Vec::new(),
    };
    let result = session.run();
    let outcome = match result {
        Ok(reason) => Outcome::Blocked {
            stage: session.stage,
            reason,
        },
        Err(reason) => Outcome::Failed {
            stage: session.stage,
            reason,
        },
    };
    let milestones = session.milestones;
    let events = session.events;
    let return_candidates = session.candidates;
    let mut record_bytes = Vec::new();
    let mut sets = 0;
    let mut gets = 0;
    let mut last_set_buffer = None;
    for call in transport.trace() {
        match call {
            Call::Set { bytes, .. } => {
                sets += 1;
                last_set_buffer = Some(bytes.clone());
                if EncodedRecord::from_local_buffer(bytes).is_ok() {
                    record_bytes.extend_from_slice(bytes);
                }
            }
            Call::Get { .. } => gets += 1,
        }
    }
    SimulationReport {
        schema_version: 1,
        mode: "simulation",
        plan_sha256: plan.id().into(),
        core: plan.inspection().core,
        scenario: config.scenario,
        fault_record_index: config
            .scenario
            .is_record_fault()
            .then_some(config.record_index),
        live_execution_available: false,
        live_blockers: plan.summary().blockers.clone(),
        assumptions: vec![
            "The physical target, baseline and recovery are unestablished; this lifecycle begins with a hypothetical prepared unit.",
            "Upgrade entry is abstract: no 07 28 payload is constructed.",
            "Boot/normal arrivals and unit IDs/version markers are synthetic, not device observations.",
            "If reached, finalization is an abstract result; no final packed value or 07 2B 01 job write is invented.",
            "Generic 72-byte and record 64-byte sizes model local scratch buffers, not measured HID reports.",
            "Timeouts/disconnects are scripted immediately; physical deadlines/cancellation are untested.",
        ],
        outcome,
        milestones,
        return_candidates,
        events,
        traffic: TrafficSummary {
            set_calls: sets,
            get_calls: gets,
            unconsumed_script_calls: transport.remaining(),
            record_request_sha256: firmware::sha256(&record_bytes),
            last_set_buffer,
            last_call: transport.trace().last().cloned(),
        },
        retry_count: 0,
    }
}

struct Session<'a> {
    plan: &'a FirmwarePlan,
    config: SimulationConfig,
    transport: &'a mut MockTransport,
    stage: Stage,
    milestones: Milestones,
    events: Vec<JobEvent>,
    candidates: Vec<SimulatedObservation>,
}

impl Session<'_> {
    fn enter(&mut self, stage: Stage) {
        self.stage = stage;
        self.events.push(JobEvent::Entered { stage });
    }

    fn assume(&mut self, detail: &'static str) {
        self.events.push(JobEvent::Assumed {
            stage: self.stage,
            detail,
        });
    }

    fn query(&mut self, query: Query) -> Result<Vec<u8>, JobFailure> {
        self.transport.set_local(&query.local_request())?;
        let reply = self.transport.get_local(7, GENERIC_LOCAL_LEN)?;
        query.decode_local_reply(&reply)?;
        Ok(reply)
    }

    fn run(&mut self) -> Result<BlockReason, JobFailure> {
        self.enter(Stage::EnterUpgrade);
        self.assume("Hypothetical entry succeeds; unresolved 07 28 bytes are not emitted");
        self.enter(Stage::ResetForBoot);
        self.transport.set_local(&protocol::reset_local_request())?;
        self.enter(Stage::AwaitBoot);
        self.assume(
            "A hypothetical boot interface arrives; physical recognition is not implemented",
        );
        if self.config.scenario == Scenario::WrongBootDevice {
            return Err(JobFailure::UnitMismatch {
                expected: UNIT.into(),
                actual: "synthetic-unit-b".into(),
            });
        }
        self.enter(Stage::ReadDeviceValue);
        let reply = self.query(Query::DeviceValue)?;
        let value = DeviceValue::decode_local_reply(&reply)?;
        self.milestones.preflight_read = true;
        if value.needs_initialization() {
            self.enter(Stage::InitializeDeviceValue);
            return Ok(BlockReason::ErasedDeviceValueNeedsPolicy);
        }
        self.enter(Stage::TransferRecords);
        for (index, record) in self.plan.records().iter().enumerate() {
            self.milestones.records_attempted += 1;
            self.milestones.last_attempted_record_index = Some(index);
            self.milestones.record_delivery_uncertain = true;
            self.transport.set_local(&record.local_buffer())?;
            let reply = self.transport.get_local(7, LOCAL_BUFFER_LEN)?;
            protocol::check_local_record_ack(&reply)?;
            self.milestones.record_delivery_uncertain = false;
            self.milestones.records_acknowledged += 1;
            if self.milestones.records_acknowledged.is_multiple_of(256)
                || index + 1 == self.plan.records().len()
            {
                self.events.push(JobEvent::RecordsAcknowledged {
                    count: self.milestones.records_acknowledged,
                    total: self.plan.records().len(),
                });
            }
        }
        self.enter(Stage::ReadFinalBlock);
        let reply = self.query(Query::FinalBlock)?;
        let _preserved = FinalBlock::decode_local_reply(&reply)?;
        self.milestones.final_block_read = true;
        self.enter(Stage::FinalizeIdentity);
        self.assume("Finalization result is injected abstractly; no packed value or write report exists in this job");
        if self.config.scenario == Scenario::FinalizationFailed {
            return Err(JobFailure::FinalizationFailed);
        }
        self.milestones.finalization_assumed = true;
        self.enter(Stage::ResetForNormal);
        self.transport.set_local(&protocol::reset_local_request())?;
        self.milestones.reset_for_normal_accepted_by_mock = true;
        self.enter(Stage::AwaitNormal);
        if self.config.scenario == Scenario::ReturnTimeout {
            return Err(JobFailure::ReturnTimeout);
        }
        let mut observation = SimulatedObservation {
            synthetic_unit_id: UNIT.into(),
            model_id: 0x578,
            core: self.plan.inspection().core,
            synthetic_version_marker: VERSION.into(),
        };
        match self.config.scenario {
            Scenario::WrongDevice => observation.synthetic_unit_id = "synthetic-unit-b".into(),
            Scenario::WrongModel => observation.model_id = 0x57C,
            Scenario::WrongCore => {
                observation.core = if observation.core == Core::One {
                    Core::Two
                } else {
                    Core::One
                }
            }
            Scenario::WrongVersion => {
                observation.synthetic_version_marker = "synthetic-version-b".into()
            }
            Scenario::AmbiguousReturn => {
                self.candidates.push(observation.clone());
                observation.synthetic_unit_id = "synthetic-unit-b".into();
                self.candidates.push(observation);
                return Err(JobFailure::AmbiguousReturn);
            }
            _ => {}
        }
        self.candidates.push(observation.clone());
        self.enter(Stage::VerifyReturn);
        if observation.synthetic_unit_id != UNIT {
            return Err(JobFailure::UnitMismatch {
                expected: UNIT.into(),
                actual: observation.synthetic_unit_id,
            });
        }
        if observation.model_id != 0x578 {
            return Err(JobFailure::ModelMismatch {
                expected: 0x578,
                actual: observation.model_id,
            });
        }
        if observation.core != self.plan.inspection().core {
            return Err(JobFailure::CoreMismatch {
                expected: self.plan.inspection().core,
                actual: observation.core,
            });
        }
        if observation.synthetic_version_marker != VERSION {
            return Err(JobFailure::VersionMismatch {
                expected: VERSION.into(),
                actual: observation.synthetic_version_marker,
            });
        }
        self.milestones.return_matched_in_simulation = true;
        self.enter(Stage::ApplyConfiguration);
        if self.transport.remaining() != 0 {
            return Err(JobFailure::ScriptIncomplete {
                remaining: self.transport.remaining(),
            });
        }
        Ok(BlockReason::ConfigurationUnavailable)
    }
}

fn script(plan: &FirmwarePlan, config: SimulationConfig) -> Vec<ExpectedCall> {
    let mut calls = vec![ExpectedCall::Set {
        bytes: protocol::reset_local_request().to_vec(),
        outcome: Ok(()),
    }];
    let mut preflight = Query::DeviceValue.local_request().to_vec();
    // Clearly synthetic U,V. Erased U must stop without initializing it.
    preflight[8..12].copy_from_slice(
        &if config.scenario == Scenario::PreflightErased {
            u32::MAX
        } else {
            0x1122_3344_u32
        }
        .to_le_bytes(),
    );
    preflight[12..16].copy_from_slice(&0x5566_7788_u32.to_le_bytes());
    if config.scenario == Scenario::PreflightBadHeader {
        preflight[6] = 1;
    }
    if config.scenario == Scenario::PreflightShortReply {
        preflight.truncate(15);
    }
    let preflight_result = if config.scenario == Scenario::PreflightReadFailed {
        Err(TransportError::new(
            TransportFailure::Timeout,
            "scripted preflight timeout",
        ))
    } else {
        Ok(preflight)
    };
    push_query(&mut calls, Query::DeviceValue, preflight_result);
    for (index, record) in plan.records().iter().enumerate() {
        let fault_here = index == config.record_index;
        let set_result = if fault_here && config.scenario == Scenario::RecordSetFailed {
            Err(TransportError::new(
                TransportFailure::Rejected,
                "scripted Set failure; delivery is treated as uncertain",
            ))
        } else {
            Ok(())
        };
        calls.push(ExpectedCall::Set {
            bytes: record.local_buffer().to_vec(),
            outcome: set_result,
        });
        let mut reply = vec![0; LOCAL_BUFFER_LEN];
        reply[0..2].copy_from_slice(&[7, 1]);
        if fault_here && config.scenario == Scenario::RecordRejected {
            reply[1] = 0;
        }
        if fault_here && config.scenario == Scenario::RecordBadReportId {
            reply[0] = 0;
        }
        if fault_here && config.scenario == Scenario::RecordShortReply {
            reply.truncate(1);
        }
        let outcome = if fault_here
            && matches!(
                config.scenario,
                Scenario::RecordGetFailed | Scenario::RecordDisconnect
            ) {
            let kind = if config.scenario == Scenario::RecordDisconnect {
                TransportFailure::Disconnected
            } else {
                TransportFailure::Timeout
            };
            Err(TransportError::new(
                kind,
                "scripted loss of record acknowledgment",
            ))
        } else {
            Ok(reply)
        };
        calls.push(ExpectedCall::Get {
            report_id: 7,
            length: LOCAL_BUFFER_LEN,
            outcome,
        });
    }
    let mut block = Query::FinalBlock.local_request().to_vec();
    for (index, byte) in block[8..36].iter_mut().enumerate() {
        *byte = index as u8;
    }
    if config.scenario == Scenario::FinalBlockBadHeader {
        block[3] = 1;
    }
    let outcome = if config.scenario == Scenario::FinalBlockReadFailed {
        Err(TransportError::new(
            TransportFailure::Disconnected,
            "scripted final-block read failure",
        ))
    } else {
        Ok(block)
    };
    push_query(&mut calls, Query::FinalBlock, outcome);
    let outcome = if config.scenario == Scenario::ResetFailed {
        Err(TransportError::new(
            TransportFailure::Timeout,
            "scripted final reset failure",
        ))
    } else {
        Ok(())
    };
    calls.push(ExpectedCall::Set {
        bytes: protocol::reset_local_request().to_vec(),
        outcome,
    });
    calls
}

fn push_query(
    calls: &mut Vec<ExpectedCall>,
    query: Query,
    outcome: Result<Vec<u8>, TransportError>,
) {
    calls.push(ExpectedCall::Set {
        bytes: query.local_request().to_vec(),
        outcome: Ok(()),
    });
    calls.push(ExpectedCall::Get {
        report_id: 7,
        length: GENERIC_LOCAL_LEN,
        outcome,
    });
}
