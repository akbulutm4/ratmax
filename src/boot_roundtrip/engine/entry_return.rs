use super::*;
use crate::boot_roundtrip::entry_return::Proof;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::boot_roundtrip) struct Verification {
    pub proof_sha256: String,
    pub unit_verified: bool,
    pub page_verified: bool,
    pub marker_restored: bool,
    pub complete: bool,
}

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_entry_return(
        reference: &'a Reference,
        proof: &'a Proof,
        mode: Mode,
        link: T,
        output: Option<&'a Path>,
    ) -> Self {
        let mut session = Self::new(reference, link, output);
        session.entry_return_proof = Some((proof, mode));
        session.state.entry_return = Some(Verification {
            proof_sha256: proof.fingerprint.clone(),
            ..Verification::default()
        });
        session.state.marker_dirty = true;
        session
    }
    fn return_closed(&mut self) -> Result<(), Fault> {
        self.state.gate_dirty = true;
        self.state.gate_close_requested = false;
        self.close_gate()
    }
    fn return_page(&mut self) -> Result<Vec<u8>, Fault> {
        self.set("entry-return-open", &key_frame(0x22184952))?;
        let mut passes = Vec::new();
        for seed in [0xa5, 0x5a] {
            let mut data = self.memory("entry-return-page", 0xfec0, seed)?[32..].to_vec();
            data.extend_from_slice(&self.memory("entry-return-page", 0xfee0, seed)?[32..]);
            passes.push(data);
        }
        self.close_gate()?;
        if passes[0] != passes[1] {
            return Err(Fault::known("entry-return page disagrees"));
        }
        Ok(passes.remove(0))
    }
    pub(super) fn return_before_records(&mut self) -> Result<(), Fault> {
        let (proof, mode) = self
            .entry_return_proof
            .ok_or_else(|| Fault::known("missing pre-record proof"))?;
        if !matches!(mode, Mode::Boot | Mode::Normal) {
            return Err(Fault::known("unsupported pre-record return mode"));
        }
        self.connect(mode)?;
        if mode == Mode::Boot {
            for seed in [0xa5, 0x5a] {
                let mut frame = [0; 64];
                frame[..2].copy_from_slice(&[7, 0x29]);
                frame[8..].fill(seed);
                let raw = self.pair("entry-return-unit", &frame)?;
                if raw[..8] != frame[..8] || raw[8..16] != proof.uv || raw[16..] != frame[16..] {
                    return Err(Fault::known("entry-return unit mismatch"));
                }
            }
        } else {
            self.normal_identity()?;
        }
        self.return_closed()?;
        if mode == Mode::Normal {
            self.set("entry-return-open", &key_frame(0x22184952))?;
            for seed in [0xa5, 0x5a] {
                if self.memory("entry-return-unit", 0xffc0, seed)?[32..] != proof.protected_block {
                    return Err(Fault::known("normal entry-return unit mismatch"));
                }
            }
            self.close_gate()?;
        }
        self.state.entry_return.as_mut().unwrap().unit_verified = true;
        let before = self.return_page()?;
        if before[..60] != proof.page[..60]
            || (before[60..] != [0; 4] && before[60..] != proof.page[60..])
        {
            return Err(Fault::known("entry-return page or marker is unsupported"));
        }
        self.save("entry-return-before.bin", &before)?;
        if before != proof.page {
            let mut frame = [0; 64];
            frame[..3].copy_from_slice(&[7, 0x28, 1]);
            frame[8..12].copy_from_slice(&proof.page[60..]);
            self.state.marker_program_intents += 1;
            self.set("entry-return-marker", &frame).map_err(|mut e| {
                e.uncertain = true;
                e
            })?;
            let restored = self.return_page()?;
            if restored != proof.page {
                return Err(Fault::known("entry-return marker/page did not restore"));
            }
            self.save("entry-return-restored.bin", &restored)?;
            self.state.entry_return.as_mut().unwrap().marker_restored = true;
        }
        self.state.entry_return.as_mut().unwrap().page_verified = true;
        self.state.marker_dirty = false;
        self.state.neighbors_verified = true;
        if mode == Mode::Boot {
            self.reset(Mode::Normal)?;
        }
        self.normal_identity()?;
        for seed in [0xa5, 0x5a] {
            let mut frame = read_frame(2, 0xfec0, 8);
            frame[32..].fill(seed);
            if self.pair("entry-return-normal-closed", &frame)? != frame {
                return Err(Fault::known("normal return gate is not closed"));
            }
        }
        self.state.normal_verified = true;
        self.state.snapshots_verified = true;
        self.state.returned = true;
        self.state.recovered = true;
        self.state.complete = true;
        self.state.entry_return.as_mut().unwrap().complete = true;
        Ok(())
    }
}
