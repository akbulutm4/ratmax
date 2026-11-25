use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::boot_roundtrip) struct Verification {
    pub bytes: usize,
    pub sha256: String,
    pub passes_equal: bool,
    pub matches_fresh_identity_settings_and_embedded_bank: bool,
}

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_backup(
        reference: &'a Reference,
        link: T,
        output: Option<&'a Path>,
    ) -> Self {
        let mut session = Self::new(reference, link, output);
        session.normal_backup = true;
        session
    }
    pub(super) fn backup_normal(&mut self) -> Result<(), Fault> {
        if self.state.mode != Some(Mode::Normal) {
            return Err(Fault::known(
                "backup requires the verified normal interface",
            ));
        }
        let request = read_frame(2, 0xfec0, 8);
        if self.pair("backup-pre-closed", &request)? != request {
            return Err(Fault::known("backup requires a closed gate"));
        }
        self.set("backup-enable", &key_frame(0x22184952))?;
        if self.memory("backup-open-witness", 0xfec0, 0)?[32..]
            != self.reference.baseline.status[8..40]
        {
            return Err(Fault::known(
                "backup RAM gate did not expose verified metadata",
            ));
        }
        let mut passes = Vec::new();
        for (pass, seed) in [0xa5, 0x5a].into_iter().enumerate() {
            let mut image = Vec::with_capacity(65536);
            for address in (0..65536).step_by(32) {
                image.extend_from_slice(&self.memory("normal-image", address, seed)?[32..]);
            }
            self.save(&format!("normal-image.pass{pass}.bin"), &image)?;
            passes.push(image);
        }
        self.close_gate()?;
        if passes[0] != passes[1] {
            return Err(Fault::known(
                "backup passes disagree or contain selector echoes",
            ));
        }
        let image = &passes[0];
        let initial = self
            .initial
            .as_deref()
            .ok_or_else(|| Fault::known("backup has no initial capture"))?;
        if image[0xfec0..0xff20] != initial[boot_bank::IDENTITY_OFFSET..boot_bank::SETTINGS_OFFSET]
            || image[0xe000..0xe100]
                != initial[boot_bank::SETTINGS_OFFSET..boot_bank::SETTINGS_OFFSET + 256]
            || image[0xff40..0xff80] != initial[boot_bank::SETTINGS_OFFSET + 256..]
            || !boot_bank::matches_known_bank(
                &image[boot_bank::COPY_BASE as usize
                    ..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES],
            )
        {
            return Err(Fault::known(
                "full backup differs from the fresh metadata/settings or embedded boot bank",
            ));
        }
        self.verify_return("backup-post")?;
        self.state.backup = Some(Verification {
            bytes: 65536,
            sha256: crate::firmware::sha256(image),
            passes_equal: true,
            matches_fresh_identity_settings_and_embedded_bank: true,
        });
        self.state.complete = true;
        Ok(())
    }
}
