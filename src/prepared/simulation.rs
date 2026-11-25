use super::{
    Plan,
    engine::{Link, Session},
};
use crate::{
    access_job::{CallKind, Completion},
    firmware::{EncodedRecord, digest_hex, sha256},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    Nominal,
    ErasedU,
    IdentityMismatch,
    ReadEcho,
    SnapshotSaveFailed,
    RecordSetFailed,
    RecordGetFailed,
    RecordReplyEcho,
    RecordShortReply,
    RecordBadHeader,
    RecordGetUncertain,
    RecordRejected,
    RecordFalseAck,
    RecordUncertain,
    PreservedHoleChanged,
    FinalBlockReadChanged,
    FinalizationFailed,
    FinalizationUncertain,
    FinalizationNotApplied,
    FinalizationNeighborChanged,
    UvChanged,
    PrefixReadEcho,
    PrefixReadFailed,
    PrefixReadUncertain,
    PrefixHeaderChanged,
    PrefixSaveFailed,
    PrefixHoleChanged,
}

impl Scenario {
    pub const ALL: [Self; 27] = [
        Self::Nominal,
        Self::ErasedU,
        Self::IdentityMismatch,
        Self::ReadEcho,
        Self::SnapshotSaveFailed,
        Self::RecordSetFailed,
        Self::RecordGetFailed,
        Self::RecordReplyEcho,
        Self::RecordShortReply,
        Self::RecordBadHeader,
        Self::RecordGetUncertain,
        Self::RecordRejected,
        Self::RecordFalseAck,
        Self::RecordUncertain,
        Self::PreservedHoleChanged,
        Self::FinalBlockReadChanged,
        Self::FinalizationFailed,
        Self::FinalizationUncertain,
        Self::FinalizationNotApplied,
        Self::FinalizationNeighborChanged,
        Self::UvChanged,
        Self::PrefixReadEcho,
        Self::PrefixReadFailed,
        Self::PrefixReadUncertain,
        Self::PrefixHeaderChanged,
        Self::PrefixSaveFailed,
        Self::PrefixHoleChanged,
    ];
}

/// Synthetic RAM/flash model of the audited commands. It does not model
/// controller erase units, power loss or the target application's startup.
struct Model {
    memory: Vec<u8>,
    pending: Option<[u8; 64]>,
    gate: bool,
    scenario: Scenario,
    fault_record: usize,
    record_sets: usize,
    final_writes: usize,
    saves: Vec<(String, String)>,
    trace: Sha256,
    calls: u32,
    records: Sha256,
    inject_uncertain_call: Option<u32>,
    uncertain_at: Option<u32>,
    prefix_damage: Option<usize>,
}

impl Model {
    fn new(scenario: Scenario, fault_record: usize) -> Self {
        let mut memory: Vec<u8> = (0..65536)
            .map(|i| ((i * 13 + i / 251) % 256) as u8)
            .collect();
        memory[0xfec6..0xfec8].copy_from_slice(&[0x79, 0x05]);
        memory[0xfee0..0xfee4].copy_from_slice(&0x09da_712fu32.to_le_bytes());
        memory[0xfee8..0xfeea].copy_from_slice(&[0x79, 0x05]);
        memory[0xfefc..0xff00].fill(0);
        memory[0xff06..0xff08].copy_from_slice(&[0x79, 0x05]);
        memory[0xffd0..0xffd8].copy_from_slice(&[0xad, 0xf8, 0x34, 0x12, 0, 0, 0, 0]);
        if scenario == Scenario::ErasedU {
            memory[0xffd0..0xffd4].fill(0xff);
        }
        if scenario == Scenario::IdentityMismatch {
            memory[0xffd0] ^= 1;
        }
        Self {
            memory,
            pending: None,
            gate: false,
            scenario,
            fault_record,
            record_sets: 0,
            final_writes: 0,
            saves: Vec::new(),
            trace: Sha256::new(),
            calls: 0,
            records: Sha256::new(),
            inject_uncertain_call: None,
            uncertain_at: None,
            prefix_damage: None,
        }
    }
}

impl Link for Model {
    fn call(&mut self, phase: &str, kind: CallKind, request: &[u8; 64]) -> Completion {
        self.calls += 1;
        assert!(
            self.uncertain_at.is_none(),
            "traffic followed uncertain call"
        );
        self.trace
            .update([if kind == CallKind::Set { 0 } else { 1 }]);
        self.trace.update(request);
        if self.inject_uncertain_call == Some(self.calls) {
            self.uncertain_at = Some(self.calls);
            return Completion::Uncertain("injected call uncertainty".into());
        }
        if kind == CallKind::Get {
            let Some(mut reply) = self.pending.take() else {
                panic!("Get without Set");
            };
            if phase == "prefix" && self.gate && request[28..32] == 0x6000_u32.to_le_bytes() {
                match self.scenario {
                    Scenario::PrefixReadEcho => reply = *request,
                    Scenario::PrefixReadFailed => {
                        return Completion::CompletedFailure("prefix read failed".into());
                    }
                    Scenario::PrefixReadUncertain => {
                        self.uncertain_at = Some(self.calls);
                        return Completion::Uncertain("prefix read uncertain".into());
                    }
                    Scenario::PrefixHeaderChanged => reply[3] ^= 1,
                    _ => (),
                }
            }
            if phase == "records" && self.record_sets - 1 == self.fault_record {
                match self.scenario {
                    Scenario::RecordGetFailed => {
                        return Completion::CompletedFailure("record Get failed".into());
                    }
                    Scenario::RecordRejected => reply[1] = 0,
                    Scenario::RecordReplyEcho => reply = *request,
                    Scenario::RecordShortReply => {
                        return Completion::GetComplete(reply[..63].to_vec());
                    }
                    Scenario::RecordBadHeader => reply[3] ^= 1,
                    Scenario::RecordGetUncertain => {
                        self.uncertain_at = Some(self.calls);
                        return Completion::Uncertain("record Get uncertain".into());
                    }
                    _ => (),
                }
            }
            return Completion::GetComplete(reply.to_vec());
        }
        assert_eq!(request[0], 7);
        let mut reply = *request;
        match request[1] {
            1 => {
                let index = self.record_sets;
                if index == 1691 {
                    assert!(!self.gate);
                    assert!(
                        self.saves.iter().any(|(name, hash)| {
                            name == "prefix-verified.bin" && *hash == sha256(&self.memory)
                        }),
                        "last record preceded durable verified prefix"
                    );
                }
                self.record_sets += 1;
                self.records.update(request);
                if index == self.fault_record {
                    if self.scenario == Scenario::RecordSetFailed {
                        return Completion::CompletedFailure("record Set failed".into());
                    }
                    if self.scenario == Scenario::RecordUncertain {
                        self.uncertain_at = Some(self.calls);
                        return Completion::Uncertain("record Set uncertain".into());
                    }
                }
                let record = EncodedRecord::from_local_buffer(request).unwrap();
                let address = record.address().get() as usize;
                let plain = record.decoded_payload();
                self.memory[address..address + 32].copy_from_slice(&plain);
                // Receiver decodes the shared Feature buffer in place.
                reply[32..64].copy_from_slice(&plain);
                if index == self.fault_record && self.scenario == Scenario::RecordFalseAck {
                    self.memory[address] ^= 1;
                }
                if index == 1691 && self.scenario == Scenario::PreservedHoleChanged {
                    self.memory[0x6000] ^= 1;
                }
                if index == 846 && self.scenario == Scenario::PrefixHoleChanged {
                    self.memory[0x6000] ^= 1;
                }
            }
            2 => {
                assert_eq!(u32::from_le_bytes(request[24..28].try_into().unwrap()), 8);
                let address = u32::from_le_bytes(request[28..32].try_into().unwrap()) as usize;
                assert!(address.is_multiple_of(32) && address + 32 <= 65536);
                if self.gate && self.scenario != Scenario::ReadEcho {
                    reply[32..].copy_from_slice(&self.memory[address..address + 32]);
                }
            }
            0x25 => {
                assert_eq!(&request[4..8], &0x2218_4952_u32.to_le_bytes());
                self.gate = request[8..12] == 0x2218_4952_u32.to_le_bytes();
                if phase == "prefix"
                    && self.gate
                    && let Some(address) = self.prefix_damage
                {
                    self.memory[address] ^= 1;
                }
                return Completion::SetComplete;
            }
            0x29 => {
                assert_eq!(request[2], 0, "U/V writes are outside this job");
                reply[8..16].copy_from_slice(&self.memory[0xffd0..0xffd8]);
                if phase == "final-page" && self.scenario == Scenario::UvChanged {
                    reply[8] ^= 1;
                }
            }
            0x2b if request[2] == 0 => {
                reply[8..36].copy_from_slice(&self.memory[0xfee0..0xfefc]);
                if phase == "final-block-read" && self.scenario == Scenario::FinalBlockReadChanged {
                    reply[12] ^= 1;
                }
            }
            0x2b if request[2] == 1 => {
                self.final_writes += 1;
                if self.scenario == Scenario::FinalizationFailed {
                    return Completion::CompletedFailure("finalization Set failed".into());
                }
                if self.scenario == Scenario::FinalizationUncertain {
                    self.uncertain_at = Some(self.calls);
                    return Completion::Uncertain("finalization Set uncertain".into());
                }
                if self.scenario != Scenario::FinalizationNotApplied {
                    self.memory[0xfee0..0xfefc].copy_from_slice(&request[8..36]);
                }
                if self.scenario == Scenario::FinalizationNeighborChanged {
                    self.memory[0xfefc] ^= 1;
                }
                return Completion::SetComplete;
            }
            _ => panic!("out-of-scope request"),
        }
        self.pending = Some(reply);
        Completion::SetComplete
    }

    fn persist(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        if self.scenario == Scenario::SnapshotSaveFailed && name == "before.pass1.bin" {
            return Err("snapshot persistence failed".into());
        }
        if self.scenario == Scenario::PrefixSaveFailed && name == "prefix-verified.bin" {
            return Err("prefix persistence failed".into());
        }
        self.saves.push((name.into(), sha256(bytes)));
        Ok(())
    }
}

pub(super) fn run(plan: &Plan, scenario: Scenario) -> serde_json::Value {
    let (state, model) = Session::new(plan, Model::new(scenario, 846)).execute();
    serde_json::json!({
        "mode":"offline_prepared_replay_simulation", "scenario":scenario,
        "assumptions":["synthetic initial flash", "programming overwrites requested bytes only", "no application startup or controller erase emulation"],
        "physical_execution_available":false, "whole_pipeline_complete":false,
        "state":state, "saved_artifacts":model.saves,
        "trace_sha256":digest_hex(&model.trace.finalize()),
        "record_stream_sha256":digest_hex(&model.records.finalize()),
        "feature_calls":model.calls,
    })
}
