use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::boot_roundtrip) struct Verification {
    pub core: crate::model::Core,
    pub proof_sha256: String,
    pub entry_ready: bool,
    pub target_returned: bool,
    pub fresh_image_verified: bool,
}

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_target_bridge(
        reference: &'a Reference,
        proof: &'a super::super::target_return::Proof,
        cleanup: Option<Mode>,
        link: T,
        output: Option<&'a Path>,
    ) -> Self {
        let mut session = Self::new(reference, link, output);
        session.target_bridge = Some((proof, cleanup));
        session.state.marker_dirty = cleanup.is_some();
        session.state.target_bridge = Some(Verification {
            core: proof.core,
            proof_sha256: proof.fingerprint.clone(),
            entry_ready: false,
            target_returned: false,
            fresh_image_verified: false,
        });
        session
    }
    fn target_information(&mut self) -> Result<(), Fault> {
        let proof = self.target_bridge.unwrap().0;
        for (query, expected) in [
            (crate::queries::NormalQuery::Identity, &proof.identity),
            (crate::queries::NormalQuery::Status, &proof.status),
        ] {
            let codec = crate::queries::OfflineQueryFrame::new(query, 64)
                .map_err(|e| Fault::known(e.to_string()))?;
            let raw = self.pair("target-bridge-information", &codec.request())?;
            super::super::target_return::validate_reply(proof.core, query, &raw)?;
            if &raw != expected {
                return Err(Fault::known(
                    "fresh target information differs from forward result",
                ));
            }
        }
        self.state.identity_verified = true;
        Ok(())
    }
    fn target_capture(&mut self, label: &str, cleared: bool) -> Result<(), Fault> {
        self.state.gate_close_requested = false;
        self.state.gate_dirty = true;
        self.close_gate()?;
        self.set("target-bridge-open", &key_frame(0x22184952))?;
        let proof = self.target_bridge.unwrap().0;
        for (pass, seed) in [0xa5, 0x5a].into_iter().enumerate() {
            let mut image = Vec::with_capacity(68608);
            for address in (0..65536u32)
                .step_by(32)
                .chain((0..3072u32).step_by(32).map(|at| boot_bank::BANK_BASE + at))
            {
                image.extend_from_slice(&self.memory(label, address, seed)?[32..]);
            }
            if !proof.matches(&image, cleared) {
                return Err(Fault::known(
                    "fresh target image, unit or active bank differs",
                ));
            }
            self.save(&format!("{label}.pass{pass}.bin"), &image)?;
        }
        self.close_gate()?;
        self.state.neighbors_verified = true;
        self.state
            .target_bridge
            .as_mut()
            .unwrap()
            .fresh_image_verified = true;
        Ok(())
    }
    fn target_boot_witness(&mut self) -> Result<(), Fault> {
        if !matches!(self.binding,Some(DeviceBinding::Usb(ref b)) if b.boot_revision==boot_bank::Revision::Prepared3)
        {
            return Err(Fault::known(
                "target bridge requires the exact revision-3 USB loader",
            ));
        }
        let proof = self.target_bridge.unwrap().0;
        for seed in [0xa5, 0x5a] {
            let mut frame = [0; 64];
            frame[..2].copy_from_slice(&[7, 0x29]);
            frame[8..].fill(seed);
            let raw = self.pair("target-bridge-unit", &frame)?;
            if raw[..8] != frame[..8]
                || raw[8..16] != proof.image[0xffd0..0xffd8]
                || raw[16..] != frame[16..]
            {
                return Err(Fault::known("target bridge boot unit differs"));
            }
        }
        self.state.gate_close_requested = false;
        self.state.gate_dirty = true;
        self.close_gate()?;
        self.set("target-bridge-open", &key_frame(0x22184952))?;
        for seed in [0xa5, 0x5a] {
            let mut bank = Vec::with_capacity(3072);
            for at in (0..3072u32).step_by(32) {
                bank.extend_from_slice(
                    &self.memory("target-bridge-bank", boot_bank::BANK_BASE + at, seed)?[32..],
                );
            }
            if !boot_bank::matches_prepared_bank(&bank) {
                return Err(Fault::known("target bridge active bank differs"));
            }
        }
        self.close_gate()?;
        self.state.identity_verified = true;
        Ok(())
    }
    pub(super) fn target_bridge_run(&mut self) -> Result<(), Fault> {
        let (proof, cleanup) = self
            .target_bridge
            .ok_or_else(|| Fault::known("missing target-return proof"))?;
        let target = Mode::Target(proof.core);
        self.connect(cleanup.unwrap_or(target))?;
        if cleanup.is_none() {
            self.target_information()?;
            self.target_capture("target-entry-before", false)?;
            self.program(false)?;
            if self.page("target-entry-page")?[60..] != [0; 4] {
                return Err(Fault::known("target entry marker did not clear"));
            }
            self.reset(Mode::Boot)?;
            self.target_boot_witness()?;
            let page = self.page("target-entry-boot-page")?;
            if page[60..] != [0; 4] {
                return Err(Fault::known("boot-3 entry marker differs"));
            }
            self.state.target_bridge.as_mut().unwrap().entry_ready = true;
            self.state.complete = true;
            return Ok(());
        }
        if cleanup == Some(Mode::Boot) {
            self.target_boot_witness()?;
        } else {
            if cleanup != Some(target) {
                return Err(Fault::known("unsupported target cleanup mode"));
            }
            self.target_information()?;
            self.state.gate_close_requested = false;
            self.state.gate_dirty = true;
            self.close_gate()?;
            self.set("target-return-unit-open", &key_frame(0x22184952))?;
            for seed in [0xa5, 0x5a] {
                if self.memory("target-return-unit", 0xffc0, seed)?[32..]
                    != proof.image[0xffc0..0xffe0]
                {
                    return Err(Fault::known("target cleanup normal unit differs"));
                }
            }
            self.close_gate()?;
        }
        let page = self.page("target-return-before")?;
        if page[..60] != proof.page()[..60]
            || (page[60..] != [0; 4] && page[60..] != proof.page()[60..])
        {
            return Err(Fault::known("target cleanup page or marker differs"));
        }
        self.save("target-return-before.bin", &page)?;
        // Verify the entire still-intact target before allowing marker-only
        // cleanup, independently of what the retained journal claims.
        self.target_capture("target-return-preflight", page[60..] == [0; 4])?;
        if page != proof.page() {
            let mut frame = [0; 64];
            frame[..3].copy_from_slice(&[7, 0x28, 1]);
            frame[8..12].copy_from_slice(&proof.page()[60..]);
            self.state.marker_program_intents += 1;
            self.state.marker_dirty = true;
            self.set("target-return-marker", &frame).map_err(|mut e| {
                e.uncertain = true;
                e
            })?;
        }
        let restored = self.page("target-return-page")?;
        if restored != proof.page() {
            return Err(Fault::known("target cleanup marker verification differs"));
        }
        self.save("target-return-restored.bin", &restored)?;
        self.state.marker_dirty = false;
        self.state.neighbors_verified = true;
        if cleanup == Some(Mode::Boot) {
            self.reset(target)?;
        }
        self.target_information()?;
        self.target_capture("target-return-after", false)?;
        self.state.normal_verified = true;
        self.state.snapshots_verified = true;
        self.state.returned = true;
        self.state.recovered = true;
        self.state.complete = true;
        self.state.target_bridge.as_mut().unwrap().target_returned = true;
        Ok(())
    }
}
