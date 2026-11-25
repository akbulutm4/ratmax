//! Bounded R3 closure experiment: 256 sensitivity candidates, no arbitrary
//! address/count interface, no state change, writer, or restoration API.
use crate::{
    firmware,
    readback::{ByteSpan, RuntimeDescriptorReply},
    sensitivity_body::conservative_echo,
};
use serde::Serialize;

pub const BODY_CHUNKS: u8 = 31;
pub const PASSES: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PassCapture {
    pub pass: u8,
    pub candidate_bytes: Vec<u8>,
    pub candidate_sha256: String,
    pub stored_additive: u16,
    pub stored_weighted: u16,
    pub computed_additive: u16,
    pub computed_weighted: u16,
    pub checksum_matches: bool,
    pub body_all_zero: bool,
    pub selector_equal_body_replies: u8,
    pub identical_to_first_pass: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockCapture {
    pub base: u32,
    pub read_command: u8,
    pub memory02_header_checked: bool,
    pub layout_reply_sha256: String,
    pub initial_header_checked: bool,
    pub current_pass: u8,
    pub current_body_chunks: u8,
    pub represented_bytes_in_current_pass: usize,
    pub passes: Vec<PassCapture>,
    pub two_passes_match_and_checksums_match: bool,
    pub terminal: bool,
    pub failure: Option<String>,
    pub protocol_authentication_established: bool,
    pub restoration_supported: bool,
}

/// Only cursor-driven requests inside the fixed host settings extent. Never
/// fills absent bytes into a purported completed pass.
#[derive(Debug, Clone)]
pub struct BlockCollector {
    base: u32,
    layout_sha: String,
    header: [u8; 8],
    header_checked: bool,
    pass: u8,
    chunk: u8,
    bytes: Vec<u8>,
    equal_replies: u8,
    passes: Vec<PassCapture>,
    terminal: bool,
    failure: Option<String>,
    memory02: bool,
    memory_header_checked: bool,
}
impl BlockCollector {
    pub fn new(layout: &RuntimeDescriptorReply, header: &[u8]) -> Result<Self, String> {
        let header: [u8; 8] = header
            .try_into()
            .map_err(|_| "exact eight-byte settings header required")?;
        let base = layout.descriptor().bases().sensitivity;
        ByteSpan::new(base, 256).map_err(|e| e.to_string())?;
        Ok(Self {
            base,
            layout_sha: layout.reply_sha256().into(),
            header,
            header_checked: false,
            pass: 0,
            chunk: 0,
            bytes: Vec::new(),
            equal_replies: 0,
            passes: Vec::new(),
            terminal: false,
            failure: None,
            memory02: false,
            memory_header_checked: false,
        })
    }
    pub fn new_memory02(layout: &RuntimeDescriptorReply, header: &[u8]) -> Result<Self, String> {
        let mut collector = Self::new(layout, header)?;
        if collector.base != 0xE000 || header[..4] != [0xA4; 4] {
            return Err("02 readback requires the observed E000/A4 sensitivity baseline".into());
        }
        collector.memory02 = true;
        Ok(collector)
    }
    pub fn is_memory02(&self) -> bool {
        self.memory02
    }
    fn frame(&self, offset: u32) -> [u8; 64] {
        let mut r = [0; 64];
        r[..3].copy_from_slice(&[7, if self.memory02 { 2 } else { 47 }, 0]);
        r[24..28].copy_from_slice(&2u32.to_le_bytes());
        r[28..32].copy_from_slice(&(self.base + offset).to_le_bytes());
        r
    }
    pub fn initial_header(&mut self, raw: &[u8]) -> Result<(), String> {
        if self.terminal || self.header_checked {
            return Err("initial block header already consumed/terminal".into());
        }
        let mut request = self.frame(0);
        request[1] = 0x2F; // Both modes first require the already measured header reader.
        conservative_echo(&request, raw).map_err(|e| e.to_string())?;
        if raw[32..40] != self.header {
            return Err("initial sensitivity header changed".into());
        }
        self.header_checked = true;
        self.bytes = self.header.to_vec();
        Ok(())
    }
    pub fn memory_header_request(&self) -> Result<[u8; 64], String> {
        if !self.memory02 || !self.header_checked || self.memory_header_checked || self.terminal {
            return Err("02 header requires fresh 2F header and an unconsumed read gate".into());
        }
        Ok(self.frame(0))
    }
    pub fn record_memory_header(&mut self, raw: &[u8]) -> Result<(), String> {
        let request = self.memory_header_request()?;
        if let Err(e) = conservative_echo(&request, raw) {
            return self.fail(e.to_string());
        }
        if raw == request || raw[32..40] != self.header {
            return self
                .fail("02 header unavailable or changed; stop without unlock or fallback".into());
        }
        self.memory_header_checked = true;
        Ok(())
    }
    fn cursor(&self, pass: u8, chunk: u8) -> Result<(), String> {
        if self.terminal
            || !self.header_checked
            || (self.memory02 && !self.memory_header_checked)
            || pass >= PASSES
            || chunk >= BODY_CHUNKS
            || pass != self.pass
            || chunk != self.chunk
        {
            return Err("out-of-order/out-of-range/terminal settings block step".into());
        }
        Ok(())
    }
    pub fn chunk_request(&self, pass: u8, chunk: u8) -> Result<[u8; 64], String> {
        self.cursor(pass, chunk)?;
        Ok(self.frame(8 + 8 * u32::from(chunk)))
    }
    pub fn record_chunk(&mut self, pass: u8, chunk: u8, raw: &[u8]) -> Result<(), String> {
        let request = self.chunk_request(pass, chunk)?;
        if let Err(e) = conservative_echo(&request, raw) {
            return self.fail(e.to_string());
        }
        self.equal_replies += u8::from(raw == request);
        self.bytes.extend_from_slice(&raw[32..40]);
        self.chunk += 1;
        Ok(())
    }
    pub fn after_header_request(&self, pass: u8) -> Result<[u8; 64], String> {
        if self.terminal
            || !self.header_checked
            || pass != self.pass
            || pass >= PASSES
            || self.chunk != BODY_CHUNKS
            || self.bytes.len() != 256
        {
            return Err("full pass required before final header".into());
        }
        Ok(self.frame(0))
    }
    pub fn record_after_header(&mut self, pass: u8, raw: &[u8]) -> Result<(), String> {
        let request = self.after_header_request(pass)?;
        if let Err(e) = conservative_echo(&request, raw) {
            return self.fail(e.to_string());
        }
        if raw[32..40] != self.header {
            return self.fail("sensitivity header changed during block capture".into());
        }
        let (sum, weighted) = checksums(&self.bytes)?;
        let stored_additive = u16::from_le_bytes([self.header[4], self.header[5]]);
        let stored_weighted = u16::from_le_bytes([self.header[6], self.header[7]]);
        let matches = sum == stored_additive && weighted == stored_weighted;
        let identical = self
            .passes
            .first()
            .map(|first| first.candidate_bytes == self.bytes);
        self.passes.push(PassCapture {
            pass,
            candidate_bytes: self.bytes.clone(),
            candidate_sha256: firmware::sha256(&self.bytes),
            stored_additive,
            stored_weighted,
            computed_additive: sum,
            computed_weighted: weighted,
            checksum_matches: matches,
            body_all_zero: !self.bytes[8..].iter().any(|b| *b != 0),
            selector_equal_body_replies: self.equal_replies,
            identical_to_first_pass: identical,
        });
        if !matches {
            return self.fail(format!("sensitivity checksum mismatch: stored {stored_additive:04X}/{stored_weighted:04X}, computed {sum:04X}/{weighted:04X}; no further reads"));
        }
        if identical == Some(false) {
            return self.fail("two sensitivity captures differ; no further reads".into());
        }
        self.pass += 1;
        if self.pass == PASSES {
            self.terminal = true;
        } else {
            self.chunk = 0;
            self.bytes = self.header.to_vec();
            self.equal_replies = 0;
        }
        Ok(())
    }
    fn fail(&mut self, message: String) -> Result<(), String> {
        self.terminal = true;
        self.failure = Some(message.clone());
        Err(message)
    }
    pub fn snapshot(&self) -> BlockCapture {
        BlockCapture {
            base: self.base,
            read_command: if self.memory02 { 2 } else { 47 },
            memory02_header_checked: self.memory_header_checked,
            layout_reply_sha256: self.layout_sha.clone(),
            initial_header_checked: self.header_checked,
            current_pass: self.pass,
            current_body_chunks: self.chunk,
            represented_bytes_in_current_pass: self.bytes.len(),
            passes: self.passes.clone(),
            two_passes_match_and_checksums_match: self.pass == PASSES && self.failure.is_none(),
            terminal: self.terminal,
            failure: self.failure.clone(),
            protocol_authentication_established: false,
            restoration_supported: false,
        }
    }
}
pub fn checksums(bytes: &[u8]) -> Result<(u16, u16), String> {
    if bytes.len() != 256 {
        return Err("checksums require exactly 256 represented bytes".into());
    }
    let mut s = 0u16;
    let mut w = 0u16;
    for i in 4..128 {
        let word = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
        s = s.wrapping_add(word);
        w = w.wrapping_add((i as u16).wrapping_mul(word));
    }
    Ok((s, w))
}
