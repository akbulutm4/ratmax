use super::{
    Fault, Mode, Reference,
    engine::{Action, Answer, Link, Session},
};
use crate::{
    access_job::{CallKind, Completion, SETTINGS_ADDRESSES},
    boot_bank,
    firmware::sha256,
    query_session::Binding,
};
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub enum Scenario {
    Nominal,
    EntryNeighborDamage,
    BootWrongModel,
    BootReadEcho,
    RestoreNotApplied,
    ReturnMissing,
    SettingsChanged,
    UncertainEntry,
    UncertainRestore,
    WrongPort,
    BadDescriptor,
    EntryNotApplied,
    ResetAckLost,
    ResetNotApplied,
}

#[derive(Serialize)]
pub(super) struct Record {
    pub action: Action,
    pub result: Result<Answer, Fault>,
}

pub(super) struct Model {
    reference: Reference,
    scenario: Scenario,
    mode: Mode,
    generation: u32,
    gate: u32,
    memory: Vec<u8>,
    reply: Vec<u8>,
    pub records: Vec<Record>,
    pub inject: Option<(usize, bool)>,
    active_bank: Vec<u8>,
    target: Option<crate::model::Core>,
    target_bank: Vec<u8>,
    pub firmware_fault: Option<&'static str>,
    shooting_runtime: [u8; 12],
    budget_root: Option<std::path::PathBuf>,
}

impl Model {
    pub fn new(reference: &Reference, scenario: Scenario) -> Self {
        let mut memory = vec![0; 65536];
        memory[0xffd0..0xffd8].copy_from_slice(&[0xad, 0xf8, 0x34, 0x12, 0, 0, 0, 0]);
        let orig_bank = &reference.packed[..boot_bank::BANK_BYTES];
        memory[0x3c60..0x4860].copy_from_slice(orig_bank);
        memory[0xfec0..0xff20].copy_from_slice(
            &reference.packed[boot_bank::IDENTITY_OFFSET..boot_bank::SETTINGS_OFFSET],
        );
        for (block, address) in SETTINGS_ADDRESSES.into_iter().enumerate() {
            memory[address as usize..address as usize + 32].copy_from_slice(
                &reference.packed[boot_bank::SETTINGS_OFFSET + block * 32
                    ..boot_bank::SETTINGS_OFFSET + (block + 1) * 32],
            );
        }
        Self {
            reference: reference.clone(),
            scenario,
            mode: Mode::Normal,
            generation: 0,
            gate: 0,
            memory,
            reply: vec![0; 64],
            records: Vec::new(),
            inject: None,
            active_bank: orig_bank.to_vec(),
            target: None,
            target_bank: Vec::new(),
            firmware_fault: None,
            shooting_runtime: [0; 12],
            budget_root: None,
        }
    }

    pub fn for_firmware(reference: &Reference, plan: &crate::prepared::Plan) -> Self {
        let mut model = Self::new(reference, Scenario::Nominal);
        model.target = Some(plan.core());
        model.target_bank = plan.boot_copy().to_vec();
        model
    }

    pub fn for_firmware_backup(
        reference: &Reference,
        plan: &crate::prepared::Plan,
        backup: &crate::backup_restore::Plan,
    ) -> Self {
        let mut model = Self::for_firmware(reference, plan);
        model.memory.clone_from(&backup.original);
        model
    }
    pub fn for_workflow(plan: &super::pipeline::Plan) -> Result<Self, String> {
        let mut model = Self::for_firmware_backup(&plan.reference, &plan.stock, &plan.backup);
        let settings = plan.request.workflow.as_ref().ok_or("missing workflow")?;
        model.mode = settings.entry;
        model.memory = plan.images(settings.entry)?.0;
        if let Some(entry) = &settings.model_entry {
            model.memory = crate::preview::read_file(&entry.join("model-state.bin"), 65536)?;
            let report: serde_json::Value = serde_json::from_slice(&crate::preview::read_file(
                &entry.join("cycle.json"),
                1_048_576,
            )?)
            .map_err(|e| e.to_string())?;
            model.shooting_runtime = serde_json::from_value(report["model_runtime"].clone())
                .map_err(|e| e.to_string())?;
        }
        if matches!(settings.entry, Mode::Target(_)) {
            model.active_bank = plan.stock.boot_copy().to_vec();
            model.generation = 1;
        }
        Ok(model)
    }

    pub fn for_restore(reference: &Reference, plan: &crate::backup_restore::Plan) -> Self {
        let mut model = Self::new(reference, Scenario::Nominal);
        model.memory.clone_from(&plan.original);
        model.memory[0x100] ^= 0x55;
        model.memory[0x6000] ^= 0x55;
        model.memory[0xe000] ^= 0x55;
        model.memory[0xff45] ^= 0x55;
        model.memory[0xfefc..0xff00].fill(0);
        model.mode = Mode::Boot;
        model.generation = 1;
        model
    }

    fn binding(&self) -> Binding {
        let mut binding = self.reference.baseline.binding().clone();
        if self.generation == 0 {
            return binding;
        }
        binding.usb_device_number += self.generation;
        binding.node = format!("hidraw{}", 20 + self.generation);
        binding.major_minor = format!("243:{}", 20 + self.generation);
        if self.mode == Mode::Boot {
            binding.product_id = 0xd023;
            binding.usb_release_bcd = boot_bank::Revision::from_bank(&self.active_bank)
                .unwrap_or_default()
                .usb_release();
            binding.usb_interface_number = 0;
            binding.manufacturer.clear();
            binding.product.clear();
            binding.serial = None;
            binding.descriptor_bytes = 24;
            binding.descriptor_sha256 = sha256(&boot_bank::BOOT_HID_REPORT_DESCRIPTOR);
        }
        if let Mode::Target(core) = self.mode {
            binding.usb_release_bcd = 0x34;
            binding.descriptor_bytes = 180;
            binding.descriptor_sha256 = super::connection::target_descriptor(core).into();
            binding.manufacturer = "A4TECH  ".into();
            binding.product = "Bloody W95 Max     ".into();
            binding.serial = Some("A000000000  ".into());
            if self.firmware_fault == Some("wrong-return-descriptor") {
                binding.descriptor_sha256 = "0".repeat(64);
            }
        }
        binding.usb_interface_path = format!(
            "{}/1-5:1.{}",
            binding.usb_parent, binding.usb_interface_number
        );
        binding.hid_sysfs_path = format!(
            "{}/0003:09DA:{:04X}.{:04X}",
            binding.usb_interface_path,
            binding.product_id,
            0xf000 + self.generation
        );
        binding
    }

    fn perform_inner(&mut self, action: &Action) -> Result<Answer, Fault> {
        if let Some((index, uncertain)) = self.inject
            && index == self.records.len()
        {
            return Err(if uncertain {
                Fault::uncertain("injected uncertain action")
            } else {
                Fault::known("injected completed action failure")
            });
        }
        match action {
            Action::Observe { .. } => Ok(Answer::Observed),
            Action::Connect { mode, .. } => {
                if *mode != self.mode {
                    return Err(Fault::known("expected mode did not appear"));
                }
                if self.scenario == Scenario::ReturnMissing && self.generation == 2 {
                    return Err(Fault::known("normal return timed out"));
                }
                if matches!(mode, Mode::Target(_)) && self.firmware_fault == Some("return-missing")
                {
                    return Err(Fault::known("target normal return missing"));
                }
                let mut binding = self.binding();
                if self.mode == Mode::Boot {
                    if self.scenario == Scenario::WrongPort {
                        binding.usb_parent.push_str("-other");
                    }
                    if self.scenario == Scenario::BadDescriptor {
                        binding.descriptor_sha256 = "0".repeat(64);
                    }
                }
                let binding = if self.mode == Mode::Boot {
                    super::connection::DeviceBinding::Usb(super::boot_usb::Binding::modeled(
                        &binding,
                    )?)
                } else {
                    binding.into()
                };
                Ok(Answer::Connected(Box::new(binding)))
            }
            Action::Feature {
                mode,
                kind,
                phase,
                frame,
            } => {
                if *mode != self.mode {
                    return Err(Fault::uncertain("feature call used a departed mode"));
                }
                if *kind == CallKind::Get {
                    if phase == "normal-image" && self.firmware_fault == Some("backup-short") {
                        return Ok(Answer::Feature(Completion::GetComplete(vec![7; 63])));
                    }
                    if phase == "normal-image" && self.firmware_fault == Some("backup-uncertain") {
                        return Err(Fault::uncertain("backup read uncertain"));
                    }
                    if matches!(phase.as_str(), "firmware-records" | "restore-records")
                        && self.firmware_fault == Some("record-get-failed")
                    {
                        return Ok(Answer::Feature(Completion::CompletedFailure(
                            "record Get failed".into(),
                        )));
                    }
                    if matches!(phase.as_str(), "firmware-prefix" | "restore-prefix")
                        && self.gate == 0x22184952
                        && frame[28..32] == 0x6000_u32.to_le_bytes()
                    {
                        match self.firmware_fault {
                            Some("prefix-read-failed") => {
                                return Ok(Answer::Feature(Completion::CompletedFailure(
                                    "prefix read failed".into(),
                                )));
                            }
                            Some("prefix-read-uncertain") => {
                                return Err(Fault::uncertain("prefix read uncertain"));
                            }
                            Some("prefix-read-echo") => {
                                return Ok(Answer::Feature(Completion::GetComplete(frame.clone())));
                            }
                            _ => (),
                        }
                    }
                    return Ok(Answer::Feature(Completion::GetComplete(self.reply.clone())));
                }
                if phase == "preset-restore-full-prefix"
                    && frame[28..32] == [0; 4]
                    && let Some(root) = &self.budget_root
                {
                    super::executor::save_json(&root.join("full-read-used.json"),&serde_json::json!({"native":false,"consumed_before_first_full_read_grant":true})).map_err(Fault::uncertain)?;
                }
                self.reply = frame.clone();
                match frame[1] {
                    1 if self.mode == Mode::Boot => {
                        if self.firmware_fault == Some("uncertain-record") {
                            return Err(Fault::uncertain("record program uncertain"));
                        }
                        let record = crate::firmware::EncodedRecord::from_local_buffer(frame)
                            .map_err(|e| Fault::known(e.to_string()))?;
                        let at = record.address().get() as usize;
                        let plain = record.decoded_payload();
                        self.memory[at..at + 32].copy_from_slice(&plain);
                        self.reply[32..].copy_from_slice(&plain);
                        if self.firmware_fault == Some("record-false-ack") && at == 0 {
                            self.memory[at] ^= 1;
                        }
                    }
                    0x29 if self.mode == Mode::Boot => {
                        self.reply[8..16].copy_from_slice(&self.memory[0xffd0..0xffd8])
                    }
                    0x1f if matches!(self.mode, Mode::Target(_)) => {
                        self.reply.clone_from(&self.reference.baseline.identity);
                        let Mode::Target(current) = self.mode else {
                            unreachable!()
                        };
                        let core = current.firmware_index().get();
                        self.reply[10..12]
                            .copy_from_slice(&(0x578u16 | u16::from(core)).to_le_bytes());
                        self.reply[12..14].copy_from_slice(&0x34u16.to_le_bytes());
                        if self.firmware_fault == Some("wrong-return-core") {
                            self.reply[10] ^= 1;
                        }
                        if self.firmware_fault == Some("wrong-return-version") {
                            self.reply[12] ^= 1;
                        }
                    }
                    0x2d if matches!(self.mode, Mode::Target(_)) => {
                        self.reply[8..40].copy_from_slice(&self.memory[0xfec0..0xfee0])
                    }
                    0x1f if self.mode == Mode::Normal => {
                        self.reply.clone_from(&self.reference.baseline.identity)
                    }
                    5 if matches!(self.mode, Mode::Normal | Mode::Target(_)) => {
                        self.reply.clone_from(&self.reference.baseline.layout)
                    }
                    0x2d if self.mode == Mode::Normal => {
                        self.reply.clone_from(&self.reference.baseline.status)
                    }
                    0x25 => self.gate = u32::from_le_bytes(frame[8..12].try_into().expect("4")),
                    0x20 | 0x0d => (),
                    0x03 if frame[2] == 6 && frame[3] == 0 && frame[8] == 0 => (),
                    0x11 if frame[4] == 0x80 && frame[8] <= 3 => (),
                    0x0e if matches!(self.mode, Mode::Target(_)) => {
                        for index in [0, 1, 2, 3, 5, 6, 7, 9, 10, 11] {
                            if frame[2] == 0x80 {
                                self.shooting_runtime[index] = frame[index + 8];
                            }
                            self.reply[index + 8] = self.shooting_runtime[index];
                        }
                    }
                    0x2f if frame[2] == 1
                        && matches!(self.mode, Mode::Normal | Mode::Target(_)) =>
                    {
                        let at = u32::from_le_bytes(frame[28..32].try_into().unwrap()) as usize;
                        let len =
                            u32::from_le_bytes(frame[24..28].try_into().unwrap()) as usize * 4;
                        assert!(at >= 0xe000 && at + len <= 0xfe80 && matches!(len, 4 | 32));
                        self.memory[at..at + len].copy_from_slice(&frame[32..32 + len]);
                    }
                    2 if self.gate == 0x22184952 => {
                        if self.mode != Mode::Boot || self.scenario != Scenario::BootReadEcho {
                            let address = u32::from_le_bytes(frame[28..32].try_into().expect("4"));
                            if phase == "target-readback" && frame[32] == 0x5a && address == 0 {
                                if self.firmware_fault == Some("target-saved-state-between-passes")
                                {
                                    self.memory[0xff45] ^= 1;
                                }
                                if self.firmware_fault == Some("target-protected-between-passes") {
                                    self.memory[0xff80] ^= 1;
                                }
                            }
                            let bytes = u32::from_le_bytes(frame[24..28].try_into().expect("4"))
                                as usize
                                * 4;
                            let data = if address >= boot_bank::BANK_BASE {
                                &self.active_bank[(address - boot_bank::BANK_BASE) as usize..]
                                    [..bytes]
                            } else {
                                &self.memory[address as usize..address as usize + bytes]
                            };
                            self.reply[32..32 + bytes].copy_from_slice(data);
                            if self.mode == Mode::Normal
                                && address == 0xff40
                                && self.firmware_fault == Some("normal-selector-changes")
                            {
                                self.reply[37] ^= if frame[32] == 0xa5 { 2 } else { 3 };
                            }

                            if phase == "normal-image" && self.firmware_fault == Some("backup-echo")
                            {
                                self.reply[32..].copy_from_slice(&frame[32..]);
                            }
                            if phase == "normal-image"
                                && self.firmware_fault == Some("backup-pass-changed")
                                && frame[32] == 0x5a
                            {
                                self.reply[32] ^= 1;
                            }
                        }
                    }
                    0x28 => {
                        let restore = phase == "restore-marker";
                        if !((restore && self.scenario == Scenario::RestoreNotApplied)
                            || (!restore && self.scenario == Scenario::EntryNotApplied))
                        {
                            self.memory[0xfefc..0xff00].copy_from_slice(&frame[8..12]);
                        }
                        if !restore && self.scenario == Scenario::EntryNeighborDamage {
                            self.memory[0xfee4] ^= 1;
                        }
                        if (!restore && self.scenario == Scenario::UncertainEntry)
                            || (restore && self.scenario == Scenario::UncertainRestore)
                        {
                            return Err(Fault::uncertain("injected uncertain marker programming"));
                        }
                    }
                    0 => {
                        if self.scenario == Scenario::ResetNotApplied && self.generation == 0 {
                            return Ok(Answer::ResetAttempt {
                                acknowledged: false,
                                error: Some("injected reset rejection".into()),
                            });
                        }
                        self.generation += 1;
                        self.mode = if self.memory[0xfefc..0xff00] == [0xa4; 4] {
                            if let Some(core) = self.target
                                && self.memory[0xfec4..0xfec6] == [0x34, 0]
                            {
                                self.active_bank.clone_from(&self.target_bank);
                                if self.firmware_fault == Some("boot-update-incomplete") {
                                    self.active_bank[0x200] ^= 1;
                                }
                                if self.firmware_fault == Some("startup-code-damage") {
                                    self.memory[0x100] ^= 1;
                                }
                                if self.firmware_fault == Some("startup-hole-damage") {
                                    self.memory[0x6000] ^= 1;
                                }
                                if self.firmware_fault == Some("startup-config-change") {
                                    self.memory[0xff45] ^= 1;
                                }
                                Mode::Target(core)
                            } else {
                                if boot_bank::matches_original_bank(&self.memory[0x3c60..0x4860]) {
                                    self.active_bank = self.memory[0x3c60..0x4860].to_vec();
                                }
                                Mode::Normal
                            }
                        } else {
                            Mode::Boot
                        };
                        self.gate = 0;
                        if self.generation == 2 && self.scenario == Scenario::SettingsChanged {
                            self.memory[0xff45] ^= 1;
                        }
                        let lost = self.scenario == Scenario::ResetAckLost;
                        return Ok(Answer::ResetAttempt {
                            acknowledged: !lost,
                            error: lost
                                .then(|| "injected disconnect before reset acknowledgment".into()),
                        });
                    }
                    0x2b..=0x2d if self.mode == Mode::Boot => {
                        if frame[1] == 0x2b && frame[2] == 1 {
                            self.memory[0xfee0..0xfefc].copy_from_slice(&frame[8..36]);
                            return Ok(Answer::Feature(Completion::SetComplete));
                        }
                        let (start, len) = match frame[1] {
                            0x2c => (0xff00, 32),
                            0x2d => (0xfec0, 32),
                            _ => (0xfee0, 28),
                        };
                        self.reply[8..8 + len].copy_from_slice(&self.memory[start..start + len]);
                        if frame[1] == 0x2c && self.scenario == Scenario::BootWrongModel {
                            self.reply[14] ^= 1;
                        }
                    }
                    2 => (),
                    _ => return Err(Fault::uncertain("model received an unsupported opcode")),
                }
                Ok(Answer::Feature(Completion::SetComplete))
            }
        }
    }
}

impl Link for Model {
    fn perform(&mut self, action: &Action) -> Result<Answer, Fault> {
        let result = self.perform_inner(action);
        self.records.push(Record {
            action: action.clone(),
            result: result.clone(),
        });
        result
    }
}

pub(super) fn run_workflow_model(
    plan: &super::pipeline::Plan,
    output: &Path,
    recovery: bool,
    root: &Path,
) -> Result<serde_json::Value, String> {
    let mut model = if recovery {
        let mut model = Model::for_restore(&plan.reference, &plan.backup);
        model.active_bank = plan.stock.boot_copy().to_vec();
        model
    } else {
        Model::for_workflow(plan)?
    };
    model.budget_root = Some(root.into());
    let (state, model) = Session::new_pipeline(
        plan,
        model,
        Some(output),
        recovery.then_some(Mode::Boot),
        !root.join("full-read-used.json").exists(),
    )
    .execute();
    write_model(plan, output, &state, &model)
}
fn write_model(
    plan: &super::pipeline::Plan,
    output: &Path,
    state: &super::engine::State,
    model: &Model,
) -> Result<serde_json::Value, String> {
    let mut journal = Vec::new();
    for row in &model.records {
        serde_json::to_writer(&mut journal, row).map_err(|e| e.to_string())?;
        journal.push(b'\n');
    }
    super::executor::save(&output.join("model-journal.jsonl"), &journal)?;
    super::executor::save(&output.join("model-state.bin"), &model.memory)?;
    let value = serde_json::json!({"mode":"offline_bounded_preset_cycle","result":state,"device_operations":0,"model_state_sha256":crate::firmware::sha256(&model.memory),"model_runtime":model.shooting_runtime,"model_final_application_equals_original":model.memory==plan.backup.original,"model_final_bank_equals_original":boot_bank::matches_original_bank(&model.active_bank),"physical_button_semantics_simulated":false});
    super::executor::save_json(&output.join("model-result.json"), &value)?;
    Ok(value)
}
pub(super) fn run_pipeline(
    plan: &super::pipeline::Plan,
    output: &Path,
) -> Result<serde_json::Value, String> {
    let model = if plan.request.workflow.is_some() {
        Model::for_workflow(plan)?
    } else {
        Model::for_firmware_backup(&plan.reference, &plan.stock, &plan.backup)
    };
    let (state, model) = Session::new_pipeline(plan, model, Some(output), None, true).execute();
    let mut journal = Vec::new();
    for row in &model.records {
        serde_json::to_writer(&mut journal, row).map_err(|e| e.to_string())?;
        journal.push(b'\n');
    }
    super::executor::save(&output.join("model-journal.jsonl"), &journal)?;
    let value = serde_json::json!({"mode":"offline_bounded_preset_cycle","result":state,"device_operations":0,"model_final_application_equals_original":model.memory==plan.backup.original,"model_final_bank_equals_original":boot_bank::matches_original_bank(&model.active_bank),"physical_button_semantics_simulated":false});
    super::executor::save_json(&output.join("model-result.json"), &value)?;
    Ok(value)
}
