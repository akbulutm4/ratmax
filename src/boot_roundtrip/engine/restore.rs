use super::*;
use crate::{
    backup_restore,
    firmware::{EncodedRecord, sha256},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::boot_roundtrip) struct Verification {
    pub retry_allowed: bool,
    #[serde(default)]
    pub boot_probe_verified: bool,
    #[serde(default)]
    pub boot_readback_verified: bool,
    pub record_intents: usize,
    pub records_acknowledged: usize,
    pub prefix_verified: bool,
    pub programmed_image_verified: bool,
    pub protected_bytes_verified: bool,
    pub restored_image_sha256: Option<String>,
    pub prefix_sha256: Option<String>,
    pub entry_bank_sha256: Option<String>,
    pub returned_bank_sha256: Option<String>,
    #[serde(default)]
    pub normal_selector_observations: Vec<NormalObservation>,
    #[serde(default)]
    pub returned_normal_image_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::boot_roundtrip) struct NormalObservation {
    pub phase: String,
    pub ff45: [u8; 2],
    pub image_sha256: [String; 2],
}

fn equal_normal_views(a: &[u8], b: &[u8]) -> bool {
    // FF45 varied during two physical normal-mode passes with zero host
    // program/reset requests. Retain its observations; this exception never
    // applies to boot-mode or programmed-image comparisons.
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .enumerate()
            .all(|(i, (a, b))| i == 0xff45 || a == b)
}

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_restore_entry(
        reference: &'a Reference,
        plan: &'a backup_restore::Plan,
        link: T,
        output: Option<&'a Path>,
        from_normal: bool,
    ) -> Self {
        let mut session = Self::new(reference, link, output);
        session.restore_plan = Some(plan);
        session.restore_from_normal = from_normal;
        session.state.restore = Some(Verification::default());
        session.state.marker_dirty = true;
        session
    }

    pub(in crate::boot_roundtrip) fn new_readback(
        reference: &'a Reference,
        plan: &'a backup_restore::Plan,
        link: T,
        output: Option<&'a Path>,
    ) -> Self {
        let mut session = Self::new_restore_entry(reference, plan, link, output, true);
        session.restore_probe = true;
        session
    }

    fn restore_fixed(&mut self, phase: &str, opcode: u8, size: usize) -> Result<Vec<u8>, Fault> {
        let mut passes = Vec::new();
        for seed in [0xa5, 0x5a] {
            let mut frame = [0; 64];
            frame[..2].copy_from_slice(&[7, opcode]);
            frame[8..].fill(seed);
            let reply = self.pair(phase, &frame)?;
            if reply[..8] != frame[..8] || reply[8 + size..] != frame[8 + size..] {
                return Err(Fault::known("restore fixed-read header/tail differs"));
            }
            passes.push(reply[8..8 + size].to_vec());
        }
        if passes[0] != passes[1] {
            return Err(Fault::known("restore fixed read disagrees or echoes"));
        }
        Ok(passes.remove(0))
    }

    fn restore_open(&mut self) -> Result<(), Fault> {
        let frame = read_frame(2, 0xfec0, 8);
        if self.pair("restore-closed-witness", &frame)? != frame {
            return Err(Fault::known("restore requires a closed gate"));
        }
        self.set("restore-enable", &key_frame(0x22184952))
    }

    fn restore_capture(&mut self, label: &str, bank: bool) -> Result<Vec<u8>, Fault> {
        self.restore_open()?;
        let mut passes = Vec::new();
        for (pass, seed) in [0xa5, 0x5a].into_iter().enumerate() {
            let mut bytes =
                Vec::with_capacity(65536 + if bank { boot_bank::BANK_BYTES } else { 0 });
            for address in (0..65536).step_by(32) {
                bytes.extend_from_slice(&self.memory(label, address, seed)?[32..]);
            }
            if bank {
                for offset in (0..boot_bank::BANK_BYTES).step_by(32) {
                    bytes.extend_from_slice(
                        &self.memory(label, boot_bank::BANK_BASE + offset as u32, seed)?[32..],
                    );
                }
            }
            self.save(&format!("{label}.pass{pass}.bin"), &bytes)?;
            passes.push(bytes);
        }
        self.close_gate()?;
        let normal = self.state.mode == Some(Mode::Normal);
        if (normal && !equal_normal_views(&passes[0], &passes[1]))
            || (!normal && passes[0] != passes[1])
        {
            return Err(Fault::known("restore captures disagree or echo selectors"));
        }
        if normal {
            self.state
                .restore
                .as_mut()
                .unwrap()
                .normal_selector_observations
                .push(NormalObservation {
                    phase: label.into(),
                    ff45: [passes[0][0xff45], passes[1][0xff45]],
                    image_sha256: [sha256(&passes[0][..65536]), sha256(&passes[1][..65536])],
                });
        }
        Ok(passes.remove(0))
    }

    fn restore_prefix(&mut self, expected: &[u8]) -> Result<(), Fault> {
        self.restore_open()?;
        let mut actual = Vec::with_capacity(65536);
        for (block, bytes) in expected.chunks_exact(32).enumerate() {
            let mut frame = read_frame(2, (block * 32) as u32, 8);
            for (seed, byte) in frame[32..].iter_mut().zip(bytes) {
                *seed = !byte;
            }
            let reply = self.pair("restore-prefix", &frame)?;
            if reply[..32] != frame[..32] || reply[32..] != *bytes {
                return Err(Fault::known(format!(
                    "restore prefix mismatch at {:04X}",
                    block * 32
                )));
            }
            actual.extend_from_slice(&reply[32..]);
        }
        self.close_gate()?;
        self.save("restore-prefix-verified.bin", &actual)?;
        let state = self.state.restore.as_mut().expect("restore state");
        state.prefix_sha256 = Some(sha256(&actual));
        state.prefix_verified = true;
        Ok(())
    }

    fn restore_record(&mut self, record: &EncodedRecord) -> Result<(), Fault> {
        if self.restore_probe {
            return Err(Fault::known(
                "boot readback cannot program firmware records",
            ));
        }
        self.state.restore.as_mut().unwrap().record_intents += 1;
        let frame = record.local_buffer();
        // A program syscall failure has an uncertain device outcome even when
        // its host call returned; no in-place retry or cleanup write follows it.
        if let Err(mut fault) = self.set("restore-records", &frame) {
            fault.uncertain = true;
            self.state.uncertain = true;
            return Err(fault);
        }
        let reply = match self.exchange("restore-records", CallKind::Get, &frame)? {
            Completion::GetComplete(reply) if reply.len() == 64 => reply,
            _ => return Err(Fault::known("restore record reply length differs")),
        };
        if reply[..32] != frame[..32] || reply[32..] != record.decoded_payload() {
            return Err(Fault::known(
                "restore record acknowledgement/decoded buffer differs",
            ));
        }
        self.state.restore.as_mut().unwrap().records_acknowledged += 1;
        Ok(())
    }

    pub(super) fn restore_backup(&mut self) -> Result<(), Fault> {
        let plan = self
            .restore_plan
            .ok_or_else(|| Fault::known("missing original backup"))?;
        if self.restore_from_normal {
            self.connect(Mode::Normal)?;
            self.normal_identity()?;
            let normal = self.restore_capture("restore-normal-before", true)?;
            if !equal_normal_views(&normal[..65536], &plan.original)
                || normal[65536..] != *plan.embedded_boot_bank()
            {
                return Err(Fault::known(
                    "normal image or bank differs from the original backup; no entry program allowed",
                ));
            }
            self.state.identity_verified = true;
            self.state.neighbors_verified = true;
            self.program(false)?;
            let page = self.page("restore-entry-page")?;
            if page[60..] != [0; 4] {
                return Err(Fault::known("normal-to-boot marker did not clear"));
            }
            self.reset(Mode::Boot)?;
        } else {
            self.connect(Mode::Boot)?;
        }
        let uv = self.restore_fixed("restore-unit", 0x29, 8)?;
        if uv != plan.original[0xffd0..0xffd8] {
            return Err(Fault::known(
                "restore U/V do not identify the backed-up unit",
            ));
        }
        self.state.identity_verified = true;
        self.state.restore.as_mut().unwrap().retry_allowed = true;
        // A failed preceding attempt may have left this known RAM gate open.
        self.state.gate_dirty = true;
        // A closure request on a prior normal-mode handle cannot establish the
        // key state of this fresh boot binding.
        self.state.gate_close_requested = false;
        self.close_gate()?;
        if self.restore_probe {
            // Read the previously failed address first, before a long sweep.
            self.restore_open()?;
            for (pass, seed) in [0xa5, 0x5a].into_iter().enumerate() {
                let raw = self.memory("boot-readback-0500", 0x500, seed)?;
                if raw[32..] != plan.original[0x500..0x520] {
                    return Err(Fault::known("boot 0500 probe differs from original"));
                }
                self.save(&format!("boot-readback-0500.pass{pass}.bin"), &raw)?;
            }
            self.close_gate()?;
            self.state.restore.as_mut().unwrap().boot_probe_verified = true;
        }
        let before = self.restore_capture("restore-before", true)?;
        if self.restore_probe {
            let mut expected = plan.original.clone();
            expected[0xfefc..0xff00].fill(0);
            // The normal application may have advanced FF45 before entering
            // boot. Both complete boot captures still require exact equality.
            expected[0xff45] = before[0xff45];
            if before[..65536] != expected
                || before[65536..] != *plan.embedded_boot_bank()
            {
                return Err(Fault::known("boot readback image or bank differs"));
            }
            self.state.restore.as_mut().unwrap().boot_readback_verified = true;
            // Completion here means capture only. The outer coordinator must
            // still prove zero records and run fresh-session entry return.
            return Ok(());
        }
        let bank = &before[65536..];
        let bank_sha = sha256(bank);
        if boot_bank::Revision::from_bank(bank).is_none() {
            self.state.restore.as_mut().unwrap().retry_allowed = false;
            return Err(Fault::known(
                "restore active loader is not a recognized complete bank",
            ));
        }
        self.state.restore.as_mut().unwrap().entry_bank_sha256 = Some(bank_sha);
        for range in [0xff00..0xff40, 0xff80..0x10000] {
            if before[range.clone()] != plan.original[range] {
                self.state.restore.as_mut().unwrap().retry_allowed = false;
                return Err(Fault::known(
                    "restore protected unit bytes differ from original backup",
                ));
            }
        }
        self.state
            .restore
            .as_mut()
            .unwrap()
            .protected_bytes_verified = true;

        // Clear and verify FEFC before touching any application bytes, even if
        // a previous attempt had already committed its final record.
        let mut clear = [0; 64];
        clear[..3].copy_from_slice(&[7, 0x28, 1]);
        self.state.marker_program_intents += 1;
        self.set("restore-clear-marker", &clear).map_err(|mut e| {
            e.uncertain = true;
            e
        })?;
        let mut expected = before[..65536].to_vec();
        expected[0xfefc..0xff00].fill(0);
        self.restore_open()?;
        for seed in [0xa5, 0x5a] {
            let mut page = self.memory("restore-marker-page", 0xfec0, seed)?[32..].to_vec();
            page.extend_from_slice(&self.memory("restore-marker-page", 0xfee0, seed)?[32..]);
            if page != expected[0xfec0..0xff00] {
                return Err(Fault::known("restore marker/page verification differs"));
            }
        }
        self.close_gate()?;
        for (index, record) in plan.records.iter().enumerate() {
            if index == plan.records.len() - 1 {
                self.restore_prefix(&expected)?;
            }
            self.restore_record(record)?;
            let at = record.address().get() as usize;
            expected[at..at + 32].copy_from_slice(&record.decoded_payload());
        }
        if expected != plan.original {
            return Err(Fault::known(
                "restore sequence does not reconstruct original image",
            ));
        }
        let programmed = self.restore_capture("restore-programmed", false)?;
        if programmed != plan.original {
            return Err(Fault::known("restored flash differs from original backup"));
        }
        self.state
            .restore
            .as_mut()
            .unwrap()
            .programmed_image_verified = true;
        self.state.restore.as_mut().unwrap().restored_image_sha256 = Some(sha256(&programmed));
        self.state.marker_dirty = false;
        self.state.neighbors_verified = true;
        self.reset(Mode::Normal)?;
        self.normal_identity()?;
        let returned = self.restore_capture("restore-returned", true)?;
        if !equal_normal_views(&returned[..65536], &plan.original)
            || returned[65536..] != *plan.embedded_boot_bank()
        {
            return Err(Fault::known(
                "returned backup image or revision-2 active bank differs",
            ));
        }
        let state = self.state.restore.as_mut().unwrap();
        state.returned_normal_image_sha256 = Some(sha256(&returned[..65536]));
        state.returned_bank_sha256 = Some(sha256(&returned[65536..]));
        self.state.normal_verified = true;
        self.state.snapshots_verified = true;
        self.state.returned = true;
        self.state.recovered = true;
        self.state.complete = true;
        Ok(())
    }
}
