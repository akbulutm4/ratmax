use super::*;
use crate::{
    firmware::sha256,
    prepared,
    queries::{NormalQuery, NormalReply, OfflineQueryFrame},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::boot_roundtrip) struct Verification {
    pub core: crate::model::Core,
    pub version: u16,
    pub active_bank_sha256: String,
    pub returned_flash_sha256: String,
    pub immutable_image_bytes_verified: usize,
    pub preserved_hole_bytes_verified: usize,
    pub configuration_changes_after_startup: Vec<(u32, u32)>,
    pub configuration_changed_bytes: usize,
    pub configuration_change_ranges_truncated: bool,
    pub configuration_semantics_verified: bool,
    #[serde(default)]
    pub saved_state_pass_sha256: [String; 2],
}

struct Adapter<'s, 'a, T: Link>(&'s mut Session<'a, T>);
impl<T: Link> prepared::engine::Link for Adapter<'_, '_, T> {
    fn call(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion {
        match self.0.exchange(&format!("firmware-{phase}"), kind, frame) {
            Ok(completion) => completion,
            Err(fault) if fault.uncertain => Completion::Uncertain(fault.message),
            Err(fault) => Completion::CompletedFailure(fault.message),
        }
    }
    fn persist(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        if let Err(fault) = self.0.save(&format!("firmware-{name}"), bytes) {
            self.0.state.uncertain = true;
            return Err(fault.message);
        }
        self.0.firmware_captures.insert(name.into(), bytes.to_vec());
        Ok(())
    }
}

impl<'a, T: Link> Session<'a, T> {
    pub(in crate::boot_roundtrip) fn new_firmware(
        reference: &'a Reference,
        plan: &'a prepared::Plan,
        link: T,
        output: Option<&'a Path>,
    ) -> Self {
        let mut session = Self::new(reference, link, output);
        session.firmware_plan = Some(plan);
        session
    }

    pub(super) fn replay_and_return(&mut self) -> Result<(), Fault> {
        let plan = self
            .firmware_plan
            .ok_or_else(|| Fault::known("missing prepared plan"))?;
        if plan.summary().target_normal_descriptor_sha256
            != connection::target_descriptor(plan.core())
        {
            return Err(Fault::known(
                "selected target descriptor differs from the pinned connection policy",
            ));
        }
        let (replay, _) = prepared::engine::Session::new(plan, Adapter(self)).execute();
        self.state.uncertain |= replay.uncertain;
        self.state.gate_dirty = replay.gate_dirty;
        let ready = replay.ready_for_reset;
        let error = replay.failure.clone();
        self.state.firmware = Some(replay);
        if !ready {
            return Err(Fault {
                message: error.unwrap_or_else(|| "prepared replay did not verify".into()),
                uncertain: self.state.uncertain,
            });
        }
        self.state.marker_dirty = false;
        self.state.neighbors_verified = true;
        self.reset(Mode::Target(plan.core()))?;
        self.verify_target()?;
        self.state.returned = true;
        self.state.normal_verified = true;
        self.state.snapshots_verified = true;
        self.state.complete = true;
        Ok(())
    }

    fn verify_target(&mut self) -> Result<(), Fault> {
        let plan = self
            .firmware_plan
            .ok_or_else(|| Fault::known("missing target"))?;
        for query in [NormalQuery::Identity, NormalQuery::Status] {
            let codec =
                OfflineQueryFrame::new(query, 64).map_err(|e| Fault::known(e.to_string()))?;
            let raw = self.pair("target-information", &codec.request())?;
            let valid = match codec
                .decode(&raw)
                .map_err(|e| Fault::known(e.to_string()))?
            {
                NormalReply::Identity {
                    core,
                    version_compare_word,
                    ..
                } => core == plan.core() && version_compare_word == 0x34,
                NormalReply::Status {
                    display_version_word,
                    ..
                } => display_version_word == 0x34,
            };
            if !valid {
                return Err(Fault::known(
                    "returned model/Core/version differs from the selected image",
                ));
            }
            self.save(&format!("target-{:02x}.reply.bin", query.opcode()), &raw)?;
        }
        let request = read_frame(2, 0xfec0, 8);
        if self.pair("target-pre-closed", &request)? != request {
            return Err(Fault::known("target RAM gate is not closed"));
        }
        self.set("target-enable-gate", &key_frame(0x22184952))?;
        let addresses: Vec<_> = (0..65536u32)
            .step_by(32)
            .chain(
                (0..3072u32)
                    .step_by(32)
                    .map(|off| boot_bank::BANK_BASE + off),
            )
            .collect();
        let mut passes = Vec::new();
        for (pass, seed) in [0xa5, 0x5a].into_iter().enumerate() {
            let mut bytes = Vec::with_capacity(65536 + 3072);
            for address in &addresses {
                bytes.extend_from_slice(&self.memory("target-readback", *address, seed)?[32..]);
            }
            self.save(&format!("target-readback.pass{pass}.bin"), &bytes)?;
            passes.push(bytes);
        }
        self.close_gate()?;
        if passes[0]
            .iter()
            .zip(&passes[1])
            .enumerate()
            .any(|(i, (a, b))| !(0xff40..0xff80).contains(&i) && a != b)
        {
            return Err(Fault::known("target readback disagrees between seeds"));
        }
        let returned = &passes[0][..65536];
        let bank = &passes[0][65536..];
        if bank != plan.boot_copy() {
            return Err(Fault::known(
                "target startup did not install the selected revision-3 boot bank",
            ));
        }
        let before = self
            .firmware_captures
            .get("before.pass0.bin")
            .ok_or_else(|| Fault::known("missing fresh before-image capture"))?;
        let replay = self
            .firmware_captures
            .get("replay.pass0.bin")
            .ok_or_else(|| Fault::known("missing verified replay capture"))?;
        let page = self
            .firmware_captures
            .get("finalized-page.bin")
            .ok_or_else(|| Fault::known("missing verified finalized page"))?;
        let mut changes = Vec::new();
        let mut changed_bytes = 0;
        let mut truncated = false;
        let mut immutable = 0;
        let mut holes = 0;
        for address in 0..65536 {
            // Audited autonomous normal-image writers target FF40/FF60.
            // Stock settings, profile bytes and compiled defaults are verified
            // exactly; only saved-state writes are reported observationally.
            if (0xff40..0xff80).contains(&address) {
                if returned[address] != replay[address] {
                    changed_bytes += 1;
                    if let Some((_, end)) = changes.last_mut()
                        && *end == address as u32
                    {
                        *end += 1;
                    } else if changes.len() < 64 {
                        changes.push((address as u32, address as u32 + 1));
                    } else {
                        truncated = true;
                    }
                }
                continue;
            }
            let expected = if (0xfec0..0xff00).contains(&address) {
                page[address - 0xfec0]
            } else {
                replay[address]
            };
            if returned[address] != expected {
                return Err(Fault::known(format!(
                    "target startup changed a protected byte at {address:04X}"
                )));
            }
            if plan.covered[address] {
                immutable += 1;
            } else {
                if returned[address] != before[address] {
                    return Err(Fault::known("target changed a preserved hole"));
                }
                holes += 1;
            }
        }
        self.state.target_verification = Some(Verification {
            core: plan.core(),
            version: 0x34,
            active_bank_sha256: sha256(bank),
            returned_flash_sha256: sha256(returned),
            immutable_image_bytes_verified: immutable,
            preserved_hole_bytes_verified: holes,
            configuration_changes_after_startup: changes,
            configuration_changed_bytes: changed_bytes,
            configuration_change_ranges_truncated: truncated,
            configuration_semantics_verified: false,
            saved_state_pass_sha256: [
                sha256(&passes[0][0xff40..0xff80]),
                sha256(&passes[1][0xff40..0xff80]),
            ],
        });
        Ok(())
    }
}
