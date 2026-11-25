use super::{FLASH_BYTES, MAX_FEATURE_CALLS, Plan, default_identity};
use crate::{
    access_job::{CallKind, Completion, key_frame, read_frame},
    firmware::sha256,
    protocol,
};
use serde::{Deserialize, Serialize};

/// The composed adapter must bind a verified boot handle, durably save
/// captures/intents, and enforce an independent deadline around each call.
pub(crate) trait Link {
    fn call(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion;
    fn persist(&mut self, name: &str, bytes: &[u8]) -> Result<(), String>;
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct State {
    pub phase: String,
    pub feature_calls: u32,
    pub record_intents: usize,
    pub records_acknowledged: usize,
    pub finalization_intents: u8,
    pub gate_dirty: bool,
    pub uncertain: bool,
    pub baseline_saved: bool,
    #[serde(default)]
    pub prefix_verified: bool,
    pub replay_verified: bool,
    pub identity_finalized: bool,
    pub ready_for_reset: bool,
    pub failure: Option<String>,
    pub cleanup_failure: Option<String>,
    pub initial_sha256: Option<String>,
    #[serde(default)]
    pub prefix_sha256: Option<String>,
    pub replay_sha256: Option<String>,
    pub finalized_page_sha256: Option<String>,
}

pub(crate) struct Session<'a, T: Link> {
    plan: &'a Plan,
    link: T,
    state: State,
}

impl<'a, T: Link> Session<'a, T> {
    pub fn new(plan: &'a Plan, link: T) -> Self {
        Self {
            plan,
            link,
            state: State::default(),
        }
    }

    pub fn execute(mut self) -> (State, T) {
        if let Err(error) = self.nominal() {
            self.state.failure = Some(error);
            if self.state.gate_dirty
                && !self.state.uncertain
                && let Err(error) = self.close_gate()
            {
                self.state.cleanup_failure = Some(error);
            }
        }
        (self.state, self.link)
    }

    fn call(
        &mut self,
        kind: CallKind,
        frame: &[u8; 64],
        mutating: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        if self.state.uncertain || self.state.feature_calls >= MAX_FEATURE_CALLS {
            return Err("uncertain operation or feature-call bound reached".into());
        }
        self.state.feature_calls += 1;
        let result = self.link.call(&self.state.phase, kind, frame);
        match (kind, result) {
            (CallKind::Set, Completion::SetComplete) => Ok(None),
            (CallKind::Get, Completion::GetComplete(reply)) if reply.len() == 64 => Ok(Some(reply)),
            (_, Completion::Uncertain(error)) => {
                self.state.uncertain = true;
                Err(error)
            }
            (_, Completion::CompletedFailure(error)) => {
                self.state.uncertain |= mutating;
                Err(error)
            }
            _ => {
                self.state.uncertain |= mutating;
                Err("invalid completion kind or Feature length".into())
            }
        }
    }

    fn exchange(&mut self, request: [u8; 64], mutating: bool) -> Result<Vec<u8>, String> {
        self.call(CallKind::Set, &request, mutating)?;
        self.call(CallKind::Get, &request, false)?
            .ok_or("missing reply".into())
    }

    fn fixed_read(&mut self, op: u8, length: usize) -> Result<Vec<u8>, String> {
        let mut passes = Vec::new();
        for seed in [0xa5, 0x5a] {
            let mut request = [0; 64];
            request[..2].copy_from_slice(&[7, op]);
            request[8..].fill(seed);
            let reply = self.exchange(request, false)?;
            if reply[..8] != request[..8] || reply[8 + length..] != request[8 + length..] {
                return Err("fixed-read header or tail mismatch".into());
            }
            passes.push(reply[8..8 + length].to_vec());
        }
        if passes[0] != passes[1] {
            return Err("fixed read disagrees between seeds or echoed selector".into());
        }
        Ok(passes.remove(0))
    }

    fn block(&mut self, address: u32, seed: u8, closed: bool) -> Result<Vec<u8>, String> {
        let mut request = read_frame(2, address, 8);
        request[32..].fill(seed);
        let reply = self.exchange(request, false)?;
        if reply[..32] != request[..32] || (closed && reply != request) {
            return Err("read02 header or closed-gate witness mismatch".into());
        }
        Ok(reply[32..].to_vec())
    }

    fn witness_closed(&mut self) -> Result<(), String> {
        for seed in [0xa5, 0x5a] {
            self.block(0xfec0, seed, true)?;
        }
        Ok(())
    }

    fn close_gate(&mut self) -> Result<(), String> {
        self.call(CallKind::Set, &key_frame(0), true)?;
        self.witness_closed()?;
        self.state.gate_dirty = false;
        Ok(())
    }

    fn open_gate(&mut self) -> Result<(), String> {
        self.witness_closed()?;
        self.state.gate_dirty = true;
        self.call(CallKind::Set, &key_frame(0x2218_4952), true)?;
        Ok(())
    }

    fn capture(&mut self, name: &str) -> Result<Vec<u8>, String> {
        self.state.phase = name.into();
        self.open_gate()?;
        let mut passes = Vec::new();
        for (pass, seed) in [0xa5, 0x5a].into_iter().enumerate() {
            let mut bytes = Vec::with_capacity(FLASH_BYTES);
            for address in (0..FLASH_BYTES).step_by(32) {
                bytes.extend(self.block(address as u32, seed, false)?);
            }
            self.link
                .persist(&format!("{name}.pass{pass}.bin"), &bytes)?;
            passes.push(bytes);
        }
        self.close_gate()?;
        if passes[0] != passes[1] {
            return Err("full flash passes disagree or contain selector echoes".into());
        }
        Ok(passes.remove(0))
    }

    fn verify_prefix(&mut self, expected: &[u8]) -> Result<(), String> {
        self.state.phase = "prefix".into();
        if expected[0xfefc..0xff00] != [0; 4] {
            return Err("startup marker changed before the final record".into());
        }
        self.open_gate()?;
        let mut actual = Vec::with_capacity(FLASH_BYTES);
        for (index, bytes) in expected.chunks_exact(32).enumerate() {
            let mut request = read_frame(2, (index * 32) as u32, 8);
            // Every expected byte differs from its request seed, including zeros.
            // A selector echo therefore cannot pass this known-data comparison.
            for (seed, expected) in request[32..].iter_mut().zip(bytes) {
                *seed = !expected;
            }
            let reply = self.exchange(request, false)?;
            if reply[..32] != request[..32] || reply[32..] != *bytes {
                return Err(format!(
                    "prefix verification mismatch at {:04X}",
                    index * 32
                ));
            }
            actual.extend_from_slice(&reply[32..]);
        }
        self.close_gate()?;
        // The native coordinator persists and syncs this capture before it can
        // grant the final marker-bearing Set proposed by the worker.
        self.link.persist("prefix-verified.bin", &actual)?;
        self.state.prefix_sha256 = Some(sha256(&actual));
        self.state.prefix_verified = true;
        Ok(())
    }

    fn nominal(&mut self) -> Result<(), String> {
        self.state.phase = "device-value".into();
        let uv = self.fixed_read(0x29, 8)?;
        let u = u32::from_le_bytes(uv[..4].try_into().unwrap());
        if u == u32::MAX {
            return Err("erased U requires a separate identity initialization policy".into());
        }
        let original = self.capture("before")?;
        let identity = u32::from_le_bytes(original[0xfee0..0xfee4].try_into().unwrap());
        if identity != 0x09da_712f
            || default_identity(u) != identity
            || original[0xfec6..0xfec8] != [0x79, 0x05]
            || original[0xfee8..0xfeea] != [0x79, 0x05]
            || original[0xfefc..0xff00] != [0; 4]
            || original[0xff06..0xff08] != [0x79, 0x05]
            || original[0xffd0..0xffd8] != uv
        {
            return Err("fresh boot snapshot identity, U/V or entry marker mismatch".into());
        }
        self.state.baseline_saved = true;
        self.state.initial_sha256 = Some(sha256(&original));

        let mut expected = original;
        for (index, record) in self.plan.image.records().records().iter().enumerate() {
            if index == crate::firmware::RECORD_COUNT - 1 {
                self.verify_prefix(&expected)?;
            }
            self.state.phase = "records".into();
            // Durable grant precedes the irreversible Set in a native adapter.
            self.state.record_intents += 1;
            let reply = self.exchange(record.local_buffer(), true)?;
            protocol::check_local_record_ack(&reply).map_err(|e| e.to_string())?;
            if reply[..32] != record.local_buffer()[..32] || reply[32..] != record.decoded_payload()
            {
                return Err("record receiver did not return the expected decoded buffer".into());
            }
            self.state.records_acknowledged += 1;
            let address = record.address().get() as usize;
            expected[address..address + 32].copy_from_slice(&record.decoded_payload());
        }
        let replay = self.capture("replay")?;
        if replay != expected {
            let offset = replay
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .unwrap();
            return Err(format!(
                "replay or preserved-hole verification mismatch at {offset:04X}"
            ));
        }
        self.state.replay_verified = true;
        self.state.replay_sha256 = Some(sha256(&replay));

        self.state.phase = "final-block-read".into();
        let mut final_block = self.fixed_read(0x2b, 28)?;
        if final_block != replay[0xfee0..0xfefc] {
            return Err("post-replay final block differs from verified flash".into());
        }
        final_block[..4].copy_from_slice(&identity.to_le_bytes());
        let mut write = [0; 64];
        write[..3].copy_from_slice(&[7, 0x2b, 1]);
        write[8..36].copy_from_slice(&final_block);
        self.state.phase = "finalization".into();
        self.state.finalization_intents += 1;
        self.call(CallKind::Set, &write, true)?;
        if self.fixed_read(0x2b, 28)? != final_block {
            return Err("finalization readback mismatch".into());
        }
        expected[0xfee0..0xfefc].copy_from_slice(&final_block);

        self.state.phase = "final-page".into();
        self.open_gate()?;
        let mut page = Vec::new();
        for seed in [0xa5, 0x5a] {
            let mut bytes = self.block(0xfec0, seed, false)?;
            bytes.extend(self.block(0xfee0, seed, false)?);
            if bytes != expected[0xfec0..0xff00] {
                return Err("finalization changed FEC0 page neighbors or marker".into());
            }
            page = bytes;
        }
        self.close_gate()?;
        if self.fixed_read(0x29, 8)? != uv {
            return Err("device U/V changed during replay/finalization".into());
        }
        self.link.persist("finalized-page.bin", &page)?;
        self.state.finalized_page_sha256 = Some(sha256(&page));
        self.state.identity_finalized = true;
        self.state.ready_for_reset = true;
        self.state.phase = "ready-for-supervised-reset".into();
        Ok(())
    }
}
