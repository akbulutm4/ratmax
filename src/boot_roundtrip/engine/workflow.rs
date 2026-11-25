use super::*;
use crate::workflow::{self, Operation};
use std::collections::BTreeMap;

impl<'a, T: Link> Session<'a, T> {
    fn workflow_capture(
        &mut self,
        expected: &[u8],
        canonical: &[u8],
        mode: Mode,
    ) -> Result<(Vec<u8>, Vec<u8>), Fault> {
        self.close_gate()?;
        self.set("workflow-preflight-open", &key_frame(0x22184952))?;
        let mut current = expected.to_vec();
        let mut samples = BTreeMap::new();
        for at in self.pipeline_plan.unwrap().samples.clone() {
            let mutable = (0xe000..0xe100).contains(&at)
                || (0xe200..0xe700).contains(&at)
                || matches!(at, 0xff40 | 0xff60);
            let mut frame = read_frame(2, at as u32, 8);
            for (seed, want) in frame[32..].iter_mut().zip(&expected[at..at + 32]) {
                *seed = if mutable { 0xa5 } else { !*want };
            }
            let raw = self.pair("workflow-preflight", &frame)?;
            if raw[..32] != frame[..32] {
                return Err(Fault::known("workflow preflight selector differs"));
            }
            if mutable {
                let other = self.memory("workflow-preflight", at as u32, 0x5a)?;
                if raw[32..] != other[32..] {
                    return Err(Fault::known("workflow preflight changes or echoes"));
                }
                if at == 0xff40 && raw[37] > 6 {
                    return Err(Fault::known("saved profile selector is outside 0..6"));
                }
            } else if raw[32..] != expected[at..at + 32] {
                return Err(Fault::known(format!(
                    "workflow unit/code sample differs at {at:04X}"
                )));
            }
            current[at..at + 32].copy_from_slice(&raw[32..]);
            samples.insert(at, raw[32..].to_vec());
        }
        if mode != Mode::Normal && current[0xe200..0xe204] == [0xa4; 4] {
            let ext_pages = workflow::extended_profile_pages(&current).map_err(Fault::known)?;
            let ext_end = 0xe700 + 64 * ext_pages;
            self.workflow_main_end = self.workflow_main_end.max(ext_end);
            for at in (0xe700..ext_end).step_by(32) {
                let mut frame = read_frame(2, at as u32, 8);
                frame[32..].fill(0xa5);
                let raw = self.pair("workflow-preflight", &frame)?;
                if raw[..32] != frame[..32] {
                    return Err(Fault::known("workflow extended preflight selector differs"));
                }
                let other = self.memory("workflow-preflight", at as u32, 0x5a)?;
                if raw[32..] != other[32..] {
                    return Err(Fault::known(
                        "workflow extended preflight changes or echoes",
                    ));
                }
                current[at..at + 32].copy_from_slice(&raw[32..]);
                samples.insert(at, raw[32..].to_vec());
            }
        }
        self.close_gate()?;
        self.save(
            "workflow-before.json",
            &serde_json::to_vec(&samples).map_err(|e| Fault::known(e.to_string()))?,
        )?;
        let mut owned = current.clone();
        for (start, end) in [(0xe000, 0xe100), (0xe200, self.workflow_main_end)] {
            if current[start..start + 4] != [0xa4; 4] {
                if mode == Mode::Normal || current[start..end] != expected[start..end] {
                    return Err(Fault::known("unrecognized invalid settings/profile block"));
                }
                owned[start..end].copy_from_slice(&canonical[start..end]);
            }
        }
        workflow::validate_owned(
            &owned,
            canonical,
            &self.pipeline_plan.unwrap().backup.original,
            mode,
        )
        .map_err(Fault::known)?;
        Ok((current, owned))
    }
    pub(super) fn save_current_configuration(
        &self,
        image: &[u8],
        mode: Mode,
        shooting_slot: Option<u8>,
        sensitivity_default: bool,
        profile_default: bool,
    ) -> Result<(), Fault> {
        let value = workflow::current_configuration(
            image,
            mode,
            shooting_slot,
            sensitivity_default,
            profile_default,
        )
        .map_err(Fault::known)?;
        self.save(
            "workflow-current.json",
            &serde_json::to_vec_pretty(&value).map_err(|e| Fault::known(e.to_string()))?,
        )
    }
    pub(super) fn workflow_run(&mut self) -> Result<(), Fault> {
        let plan = self.pipeline_plan.unwrap();
        let settings = plan.request.workflow.as_ref().unwrap();
        let mode = settings.entry;
        self.connect(mode)?;
        if mode == Mode::Normal {
            self.normal_identity()?;
        } else {
            self.pipeline_target_information()?;
        }
        let (source, canonical) = plan.images(mode).map_err(Fault::known)?;
        let (mut current, owned) = self.workflow_capture(&source, &canonical, mode)?;
        let bank = &source[boot_bank::COPY_BASE as usize
            ..boot_bank::COPY_BASE as usize + boot_bank::BANK_BYTES];
        self.pipeline_bank("workflow-before-bank", Some(bank))?;
        if settings.operation == Operation::Inspect {
            let shooting_slot = if workflow::shooting_supported(mode) {
                Some(self.pipeline_runtime("workflow-inspect")?.selected_slot)
            } else {
                None
            };
            self.save_current_configuration(
                &owned,
                mode,
                shooting_slot,
                current[0xe000..0xe004] != [0xa4; 4],
                current[0xe200..0xe204] != [0xa4; 4],
            )?;
            self.state.pipeline.as_mut().unwrap().inspected = true;
            self.state.complete = true;
            self.state.normal_verified = true;
            self.state.snapshots_verified = true;
            return Ok(());
        }
        if settings.button_macro.is_some()
            && crate::program::internal::current(&owned, mode)
                .map_err(Fault::known)?
                .is_some()
        {
            return Err(Fault::known(
                "remove the shooting program before editing a button macro",
            ));
        }
        if settings.custom_shooting.is_some() && crate::macros::storage::present(&owned) {
            return Err(Fault::known(
                "remove the button macro before editing a shooting program",
            ));
        }
        if settings.operation == Operation::Flash
            && (crate::macros::storage::present(&owned)
                || crate::program::internal::current(&owned, mode)
                    .map_err(Fault::known)?
                    .is_some()
                || crate::lighting::decode_persistent(&owned, mode)
                    .map_err(Fault::known)?
                    .is_some())
        {
            return Err(Fault::known(
                "remove the custom program or permanent lighting before changing Core",
            ));
        }
        self.set("workflow-before-entry", &key_frame(0))?;
        self.state.pipeline.as_mut().unwrap().retry_allowed = true;
        let previous_slot = if workflow::shooting_supported(mode) {
            Some(self.pipeline_runtime("workflow-start")?.selected_slot)
        } else {
            None
        };
        let goal = if settings.operation == Operation::Flash {
            self.pipeline_flash(&mut current)?;
            let mut base = plan.configured.clone();
            base[0xe000..0xe100].copy_from_slice(&owned[0xe000..0xe100]);
            workflow::configure(
                base,
                &plan.configured,
                Mode::Target(plan.request.core),
                settings,
            )
            .map_err(Fault::known)?
        } else {
            workflow::configure(owned, &canonical, mode, settings).map_err(Fault::known)?
        };
        self.save("workflow-candidate.json",&serde_json::to_vec(&serde_json::json!({"settings":settings,"expected_application_sha256":crate::firmware::sha256(&goal),"synthesized_expected_image_not_a_device_backup":true})).map_err(|e|Fault::known(e.to_string()))?)?;
        self.pipeline_configure(&mut current, &goal, "workflow", true)?;
        if let Some(edit) = &settings.custom_lighting
            && self.state.mode != Some(Mode::Normal)
        {
            if let crate::lighting::PersistentEdit::Install {
                brightness: Some(level),
                ..
            } = edit
            {
                self.set(
                    "workflow-lighting-brightness",
                    &crate::lighting::brightness_set_frame(*level),
                )?;
            }
            // Exit any live RAM preview and reset the flash lighting state machine so the
            // newly written internal-flash RGB stream activates immediately without replugging.
            self.set(
                "workflow-lighting-reload",
                &crate::lighting::preview_enable_frame(false),
            )?;
        }
        if self.state.mode.is_some_and(workflow::shooting_supported) {
            self.pipeline_select_slot(
                "workflow-initial",
                settings
                    .shooting_slot
                    .unwrap_or(if settings.operation == Operation::Flash {
                        0
                    } else {
                        previous_slot.unwrap_or(0)
                    }),
            )?;
        }
        if self.state.mode == Some(Mode::Normal) {
            self.normal_identity()?;
        } else {
            self.pipeline_target_information()?;
        }
        self.pipeline_sample("workflow-kept", &current, 2)?;
        if settings.restore_after {
            return self.pipeline_restore();
        }
        let mode = self
            .state
            .mode
            .ok_or_else(|| Fault::known("configuration returned without mode"))?;
        let shooting_slot = self
            .state
            .pipeline
            .as_ref()
            .unwrap()
            .runtime_observations
            .last()
            .map(|(_, s)| s.selected_slot);
        self.save_current_configuration(&current, mode, shooting_slot, false, false)?;
        self.state
            .pipeline
            .as_mut()
            .unwrap()
            .desired_configuration_kept = true;
        self.state.normal_verified = true;
        self.state.neighbors_verified = true;
        self.state.snapshots_verified = true;
        self.state.complete = true;
        Ok(())
    }
}
