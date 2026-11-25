use super::*;
use crate::access_session::create_output;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    None,
    NoEffect,
    LostProgram,
    NeighborDamage,
    EchoPrefix,
    SaveOriginal,
    SavePrefix,
    BindingAfterProgram,
    SavedStateDrift,
    ProgramRejected,
}
impl Fault {
    fn parse(name: &str) -> Result<Self, String> {
        Ok(match name {
            "none" => Self::None,
            "no-effect" => Self::NoEffect,
            "lost-program" => Self::LostProgram,
            "neighbor-damage" => Self::NeighborDamage,
            "echo-prefix" => Self::EchoPrefix,
            "save-original" => Self::SaveOriginal,
            "save-prefix" => Self::SavePrefix,
            "binding-after-program" => Self::BindingAfterProgram,
            "saved-state-drift" => Self::SavedStateDrift,
            "program-rejected" => Self::ProgramRejected,
            _ => return Err("unknown button-cycle fault".into()),
        })
    }
}

struct Model {
    image: Vec<u8>,
    baseline: AccessBaseline,
    last: Vec<u8>,
    gate: bool,
    paused: bool,
    programs: u16,
    program_fault_at: u16,
    get_fault_at: Option<u32>,
    gets: u32,
    fault: Fault,
    fired: bool,
    invalid_binding: bool,
    output: Option<std::path::PathBuf>,
    journal: Vec<serde_json::Value>,
    snapshots: BTreeMap<String, Vec<u8>>,
}
impl Model {
    fn new(image: Vec<u8>, baseline: AccessBaseline, fault: Fault) -> Self {
        Self {
            image,
            baseline,
            last: Vec::new(),
            gate: false,
            paused: false,
            programs: 0,
            program_fault_at: 1,
            get_fault_at: None,
            gets: 0,
            fault,
            fired: false,
            invalid_binding: false,
            output: None,
            journal: Vec::new(),
            snapshots: BTreeMap::new(),
        }
    }
    fn fire(&mut self, fault: Fault) -> bool {
        if !self.fired && self.fault == fault {
            self.fired = true;
            true
        } else {
            false
        }
    }
    fn exchange(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion {
        assert_eq!(frame[0], 7);
        if kind == CallKind::Set {
            self.last = frame.to_vec();
            match frame[1] {
                0x25 => {
                    assert_eq!(frame[4..8], 0x22184952u32.to_le_bytes());
                    self.gate = frame[8..12] != [0; 4];
                }
                0x20 => {
                    assert!(!self.gate);
                    self.paused = frame[7] == 1;
                    if !self.paused && self.fire(Fault::SavedStateDrift) {
                        self.image[0xff46] ^= 1;
                    }
                }
                0x2f => {
                    assert!(self.paused && !self.gate);
                    assert_eq!(frame[2], 1);
                    let at = u32::from_le_bytes(frame[28..32].try_into().unwrap()) as usize;
                    let len = usize::from(frame[24]) * 4;
                    assert!(at >= 0xe200 && at + len <= 0xfe9c && matches!(len, 4 | 32));
                    self.programs += 1;
                    let ready = self.programs == self.program_fault_at;
                    if ready && self.fire(Fault::ProgramRejected) {
                        return Completion::CompletedFailure(
                            "modeled programming rejection".into(),
                        );
                    }
                    if ready && self.fire(Fault::NoEffect) {
                        return Completion::SetComplete;
                    }
                    self.image[at..at + len].copy_from_slice(&frame[32..32 + len]);
                    if ready && self.fire(Fault::NeighborDamage) {
                        self.image[0xe1ff] ^= 1;
                    }
                    if ready && self.fire(Fault::BindingAfterProgram) {
                        self.invalid_binding = true;
                    }
                    if ready && self.fire(Fault::LostProgram) {
                        return Completion::Uncertain("modeled lost programming completion".into());
                    }
                }
                2 | 5 | 0x1f | 0x2d => {}
                _ => panic!("ungranted opcode in button model"),
            }
            return Completion::SetComplete;
        }
        assert_eq!(self.last, frame);
        let mut raw = frame.to_vec();
        match frame[1] {
            2 if self.gate => {
                assert_eq!(frame[24..28], 8u32.to_le_bytes());
                let at = u32::from_le_bytes(frame[28..32].try_into().unwrap()) as usize;
                if phase.ends_with("-prefix") && self.fire(Fault::EchoPrefix) {
                    return Completion::GetComplete(raw);
                }
                raw[32..].copy_from_slice(&self.image[at..at + 32]);
            }
            2 | 0x20 => {}
            0x1f => raw = self.baseline.identity.clone(),
            0x2d => raw = self.baseline.status.clone(),
            5 => raw = self.baseline.layout.clone(),
            _ => panic!("ungranted get in button model"),
        }
        Completion::GetComplete(raw)
    }
}
impl Link for Model {
    fn validate(&mut self) -> Result<(), String> {
        if self.invalid_binding {
            Err("modeled binding changed".into())
        } else {
            Ok(())
        }
    }
    fn call(&mut self, phase: &str, kind: CallKind, frame: &[u8; 64]) -> Completion {
        let mut answer = self.exchange(phase, kind, frame);
        if kind == CallKind::Get {
            self.gets += 1;
            if self.get_fault_at == Some(self.gets) {
                answer = Completion::Uncertain("modeled lost read completion".into());
            }
        }
        self.journal.push(serde_json::json!({"kind":"feature","phase":phase,"direction":kind,"frame":frame.to_vec(),"completion":answer}));
        answer
    }
    fn save(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let failure = (name == "original-sparse.json" && self.fire(Fault::SaveOriginal))
            || (name.ends_with("-prefix.json") && self.fire(Fault::SavePrefix));
        let result = (|| {
            if failure {
                return Err("modeled durable save failure".into());
            }
            if let Some(output) = &self.output {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output.join(name))
                    .and_then(|mut file| {
                        file.write_all(bytes)?;
                        file.sync_all()
                    })
                    .map_err(|e| e.to_string())?;
                std::fs::File::open(output)
                    .and_then(|f| f.sync_all())
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        self.journal.push(serde_json::json!({"kind":"save","name":name,"sha256":sha256(bytes),"bytes":bytes.len(),"completed":result.is_ok(),"error":result.as_ref().err()}));
        if result.is_ok() {
            self.snapshots.insert(name.into(), bytes.to_vec());
        }
        result
    }
    fn settle(&mut self) -> Result<(), String> {
        self.journal
            .push(serde_json::json!({"kind":"settle","modeled":true}));
        Ok(())
    }
}

pub(super) fn run(
    project: &Path,
    baseline: &Path,
    output: &Path,
    fault: &str,
) -> Result<serde_json::Value, String> {
    let fault = Fault::parse(fault)?;
    let (image, plan) = button_plan::load_image_and_plan(project)?;
    let reference = crate::boot_roundtrip::load(baseline)?;
    let (original, target) = prepared(&image, &plan)?;
    let output = create_output(output)?;
    let mut model = Model::new(image.clone(), reference.baseline.clone(), fault);
    model.output = Some(output.clone());
    let (state, model) =
        Session::new(&plan, &reference.baseline, original, target, model).execute();
    let report = serde_json::json!({"mode":"offline_button_edit_restore_model","physical_execution_available":false,
        "device_calls":0,"full_device_reads":0,"burst_bytes":32,"sparse_windows":prepared(&image,&plan)?.0.len(),
        "fault":format!("{fault:?}"),"fault_fired":model.fired,"result":state,
        "modeled_application_equals_original":model.image==image,"modeled_gate_closed":!model.gate,
        "modeled_processing_resumed":!model.paused,"configuration_behavior_physically_qualified":false,
        "native_worker_and_coordinator_implemented":true,"native_worker_used":false,"full_backup_resume_supported":false});
    let journal = model
        .journal
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect::<String>();
    std::fs::write(output.join("journal.jsonl"), journal).map_err(|e| e.to_string())?;
    std::fs::write(
        output.join("cycle.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(report)
}
