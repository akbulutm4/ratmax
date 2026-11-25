//! Local scratch-buffer transport contract and deterministic in-memory mock.
//! Native adapters stay private to the restricted workers. CLI simulations use
//! only local data and this mock; temporary-access execution is separately disabled.

use std::{collections::VecDeque, fmt};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    Rejected,
    Timeout,
    Disconnected,
    ScriptMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransportError {
    pub kind: TransportFailure,
    pub detail: String,
}

impl TransportError {
    pub fn new(kind: TransportFailure, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for TransportError {}

pub trait LocalFeatureTransport {
    fn set_local(&mut self, bytes: &[u8]) -> Result<(), TransportError>;
    fn get_local(&mut self, report_id: u8, length: usize) -> Result<Vec<u8>, TransportError>;
}

#[derive(Debug, Clone)]
pub enum ExpectedCall {
    Set {
        bytes: Vec<u8>,
        outcome: Result<(), TransportError>,
    },
    Get {
        report_id: u8,
        length: usize,
        outcome: Result<Vec<u8>, TransportError>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum Call {
    Set {
        bytes: Vec<u8>,
        error: Option<TransportError>,
    },
    Get {
        report_id: u8,
        length: usize,
        reply: Option<Vec<u8>>,
        error: Option<TransportError>,
    },
}

#[derive(Debug)]
pub struct MockTransport {
    script: VecDeque<ExpectedCall>,
    trace: Vec<Call>,
}

impl MockTransport {
    pub fn new(script: Vec<ExpectedCall>) -> Self {
        Self {
            script: script.into(),
            trace: Vec::new(),
        }
    }
    pub fn trace(&self) -> &[Call] {
        &self.trace
    }
    pub fn remaining(&self) -> usize {
        self.script.len()
    }

    fn mismatch(detail: &'static str) -> TransportError {
        TransportError::new(TransportFailure::ScriptMismatch, detail)
    }
}

impl LocalFeatureTransport for MockTransport {
    fn set_local(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let result = match self.script.pop_front() {
            Some(ExpectedCall::Set {
                bytes: expected,
                outcome,
            }) if expected == bytes => outcome,
            _ => Err(Self::mismatch(
                "unexpected Set, wrong order, or different request bytes",
            )),
        };
        self.trace.push(Call::Set {
            bytes: bytes.to_vec(),
            error: result.clone().err(),
        });
        result
    }

    fn get_local(&mut self, report_id: u8, length: usize) -> Result<Vec<u8>, TransportError> {
        let result = match self.script.pop_front() {
            Some(ExpectedCall::Get {
                report_id: expected_id,
                length: expected_len,
                outcome,
            }) if expected_id == report_id && expected_len == length => outcome,
            _ => Err(Self::mismatch(
                "unexpected Get, wrong order, report ID, or requested length",
            )),
        };
        self.trace.push(Call::Get {
            report_id,
            length,
            reply: result.clone().ok(),
            error: result.clone().err(),
        });
        result
    }
}
