use super::*;
use crate::preview::read_file;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    schema: u8,
    native: bool,
    files: BTreeMap<String, String>,
    #[serde(default)]
    observation_seconds: u16,
    #[serde(default)]
    read_only: bool,
}

pub(super) struct Source {
    pub directory: PathBuf,
    pub fingerprint: String,
    pub native: bool,
    pub image: Vec<u8>,
    pub plan: Plan,
    pub baseline: AccessBaseline,
    pub binding: Binding,
    pub original: Windows,
    pub target: Windows,
    pub observation_seconds: u16,
    pub read_only: bool,
}

pub(super) fn same_device(binding: &Binding, original: &Binding) -> Result<(), String> {
    binding.validate()?;
    if binding.vendor_id != original.vendor_id
        || binding.product_id != original.product_id
        || binding.usb_parent != original.usb_parent
        || binding.usb_bus_number != original.usb_bus_number
        || binding.usb_interface_number != original.usb_interface_number
        || binding.usb_release_bcd != original.usb_release_bcd
        || binding.descriptor_bytes != original.descriptor_bytes
        || binding.descriptor_sha256 != original.descriptor_sha256
        || binding.manufacturer != original.manufacturer
        || binding.product != original.product
        || binding.serial != original.serial
        || binding.hid_unique != original.hid_unique
    {
        return Err("button binding differs from original normal identity or port".into());
    }
    Ok(())
}

impl Source {
    pub fn freeze_options(
        project: &Path,
        baseline: &AccessBaseline,
        binding: &Binding,
        directory: &Path,
        native: bool,
        observation_seconds: u16,
        read_only: bool,
    ) -> Result<Self, String> {
        if observation_seconds > 300 {
            return Err("observation interval exceeds 300 seconds".into());
        }
        let (image, plan) = button_plan::load_image_and_plan(project)?;
        prepared(&image, &plan)?;
        same_device(binding, baseline.binding())?;
        fs::create_dir(directory).map_err(|e| e.to_string())?;
        let mut project: serde_json::Value =
            serde_json::from_slice(&read_file(project, 65536)?).map_err(|e| e.to_string())?;
        project["image"] = "image.bin".into();
        save_json(&directory.join("project.json"), &project)?;
        save(&directory.join("image.bin"), &image)?;
        save_json(&directory.join("baseline.json"), baseline)?;
        save_json(&directory.join("binding.json"), binding)?;
        let mut files = BTreeMap::new();
        for name in ["project.json", "image.bin", "baseline.json", "binding.json"] {
            files.insert(
                name.into(),
                sha256(&read_file(&directory.join(name), 1_048_576)?),
            );
        }
        save_json(
            &directory.join("authority.json"),
            &Certificate {
                schema: 1,
                native,
                files,
                observation_seconds,
                read_only,
            },
        )?;
        Self::load(directory, native)
    }
    pub fn load(directory: &Path, native_required: bool) -> Result<Self, String> {
        let raw = read_file(&directory.join("authority.json"), 65536)?;
        let certificate: Certificate = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let names: BTreeSet<_> = certificate.files.keys().map(String::as_str).collect();
        if certificate.schema != 1
            || certificate.observation_seconds > 300
            || (native_required && !certificate.native)
            || names
                != BTreeSet::from(["project.json", "image.bin", "baseline.json", "binding.json"])
        {
            return Err("button authority provenance or file set differs".into());
        }
        for (name, want) in &certificate.files {
            if sha256(&read_file(&directory.join(name), 1_048_576)?) != *want {
                return Err("button authority file changed".into());
            }
        }
        let project: serde_json::Value =
            serde_json::from_slice(&read_file(&directory.join("project.json"), 65536)?)
                .map_err(|e| e.to_string())?;
        if project["image"] != "image.bin" {
            return Err("frozen button source path differs".into());
        }
        let (image, plan) = button_plan::load_image_and_plan(&directory.join("project.json"))?;
        let (original, target) = prepared(&image, &plan)?;
        let baseline: AccessBaseline =
            serde_json::from_slice(&read_file(&directory.join("baseline.json"), 1_048_576)?)
                .map_err(|e| e.to_string())?;
        baseline.validate()?;
        let binding: Binding =
            serde_json::from_slice(&read_file(&directory.join("binding.json"), 65536)?)
                .map_err(|e| e.to_string())?;
        same_device(&binding, baseline.binding())?;
        Ok(Self {
            directory: directory.into(),
            fingerprint: sha256(&raw),
            native: certificate.native,
            image,
            plan,
            baseline,
            binding,
            original,
            target,
            observation_seconds: certificate.observation_seconds,
            read_only: certificate.read_only,
        })
    }
    pub fn validate_action(&self, action: &Action, binding: &Binding) -> Result<(), String> {
        match action {
            Action::Bind { binding: proposed } if proposed.as_ref() == binding => {
                same_device(binding, self.baseline.binding())
            }
            Action::Settle { milliseconds: 500 } => Ok(()),
            Action::Observe { phase }
                if !self.read_only
                    && matches!(phase.as_str(), "original" | "edited" | "restored") =>
            {
                Ok(())
            }
            Action::Save { name, bytes } if safe_name(name) && bytes.len() <= 16384 => Ok(()),
            Action::Feature { frame, kind, .. } if frame.len() == 64 => {
                if frame[0] != 7 {
                    return Err("button report ID differs".into());
                }
                let op = frame[1];
                let mut expected = vec![0; 64];
                expected[..2].copy_from_slice(&[7, op]);
                match op {
                    5 | 0x1f | 0x2d => {}
                    0x20 if !self.read_only && frame[7] <= 1 => expected[7] = frame[7],
                    0x25 => {
                        expected = key_frame(u32::from_le_bytes(frame[8..12].try_into().unwrap()))
                            .to_vec();
                        if frame[8..12] != [0; 4] && frame[8..12] != 0x22184952u32.to_le_bytes() {
                            return Err("button gate value differs".into());
                        }
                    }
                    2 => {
                        let at = u32::from_le_bytes(frame[28..32].try_into().unwrap()) as usize;
                        if !self.original.contains_key(&at) {
                            return Err("button read outside sparse scope".into());
                        }
                        expected = read_frame(2, at as u32, 8).to_vec();
                        expected[32..].copy_from_slice(&frame[32..]);
                    }
                    0x2f if !self.read_only && *kind == CallKind::Set => {
                        let at = u32::from_le_bytes(frame[28..32].try_into().unwrap()) as usize;
                        let len =
                            u32::from_le_bytes(frame[24..28].try_into().unwrap()) as usize * 4;
                        if !matches!(len, 4 | 32)
                            || !self
                                .plan
                                .pages
                                .iter()
                                .any(|p| at >= p.address && at + len <= p.address + 64)
                        {
                            return Err("button program outside frozen pages".into());
                        }
                        let original = &self.image[at..at + len];
                        let page = self
                            .plan
                            .pages
                            .iter()
                            .find(|p| at >= p.address && at + len <= p.address + 64)
                            .unwrap();
                        let target = &page.candidate[at - page.address..at - page.address + len];
                        let mut staged_original = original.to_vec();
                        let mut staged_target = target.to_vec();
                        if at == BASE {
                            staged_original[..4].fill(0xff);
                            staged_target[..4].fill(0xff);
                        }
                        let data = &frame[32..32 + len];
                        if len == 4 {
                            if at != BASE || data != original {
                                return Err("button marker differs".into());
                            }
                        } else if data != original
                            && data != target
                            && data != staged_original
                            && data != staged_target
                        {
                            return Err(
                                "button program payload differs from frozen candidate".into()
                            );
                        }
                        expected[2] = 1;
                        expected[24] = (len / 4) as u8;
                        expected[28..32].copy_from_slice(&(at as u32).to_le_bytes());
                        expected[32..32 + len].copy_from_slice(data);
                    }
                    _ => return Err("button opcode is outside frozen scope".into()),
                }
                if frame != &expected {
                    return Err("button frame layout differs".into());
                }
                Ok(())
            }
            _ => Err("button action is outside frozen scope".into()),
        }
    }
}

pub(super) fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        && !name.starts_with('.')
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    pub source_sha256: String,
    pub native: bool,
    pub binding: Binding,
    pub reports: Vec<(PathBuf, String, String)>,
    pub captured: Option<Windows>,
    pub possible_program: bool,
}

impl Proof {
    pub fn make(source: &Source, attempts: &[PathBuf], binding: Binding) -> Result<Self, String> {
        same_device(&binding, source.baseline.binding())?;
        if attempts.is_empty() || attempts.len() > 64 {
            return Err("button recovery chain bound".into());
        }
        let mut reports = Vec::new();
        let mut captured = None;
        let mut possible_program = false;
        for path in attempts {
            let raw = read_file(&path.join("session.json"), 1_048_576)?;
            let report: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let pid = report["worker_pid"]
                .as_u64()
                .ok_or("missing previous button worker")?;
            if pid == 0
                || pid > u32::MAX as u64
                || Path::new("/proc").join(pid.to_string()).exists()
                || report["worker_reaped"] != true
                || report["source_sha256"] != source.fingerprint
                || report["native"] != source.native
                || !matches!(
                    report["mode"].as_str(),
                    Some("native_button_cycle" | "native_button_recovery")
                )
            {
                return Err(
                    "button recovery requires an absent, reaped, same-source worker".into(),
                );
            }
            let journal = read_file(&path.join("journal.jsonl"), 16 * 1024 * 1024)?;
            let expected: Binding =
                serde_json::from_value(report["binding"].clone()).map_err(|e| e.to_string())?;
            let mut number = 0;
            let mut pending: Option<Action> = None;
            let mut granted = false;
            let mut program_grants = 0u32;
            let mut done = false;
            let mut released = false;
            for line in journal.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                let row: serde_json::Value =
                    serde_json::from_slice(line).map_err(|e| e.to_string())?;
                let value = &row["value"];
                if value["number"] != number {
                    return Err("button recovery journal cursor differs".into());
                }
                match row["kind"].as_str() {
                    Some("button_intent") if pending.is_none() && !done => {
                        let action: Action = serde_json::from_value(value["action"].clone())
                            .map_err(|e| e.to_string())?;
                        source.validate_action(&action, &expected)?;
                        pending = Some(action);
                        granted = false;
                    }
                    Some("button_grant") if pending.is_some() && !granted => {
                        let permit = value["permit"]
                            .as_bool()
                            .ok_or("button grant permission missing")?;
                        if permit
                            && matches!(pending.as_ref(),Some(Action::Feature{kind:CallKind::Set,frame,..}) if frame[1]==0x2f)
                        {
                            possible_program = true;
                            program_grants += 1;
                        }
                        granted = true;
                    }
                    Some("button_completion") if pending.is_some() && granted => {
                        pending = None;
                        number += 1;
                    }
                    Some("button_done") if pending.is_none() && !done => {
                        let _: State = serde_json::from_value(value["state"].clone())
                            .map_err(|e| e.to_string())?;
                        done = true;
                    }
                    Some("button_release")
                        if done && !released && value["release_after_done"] == true =>
                    {
                        released = true;
                    }
                    _ => return Err("button recovery journal order differs".into()),
                }
                if number > MAX_ACTIONS {
                    return Err("button recovery journal exceeded bound".into());
                }
            }
            if report["program_grants"] != program_grants {
                return Err("button recovery grant count differs".into());
            }
            if let Some(want) = report["saved_sha256"]["original-sparse.json"].as_str() {
                let original = read_file(&path.join("original-sparse.json"), 16384)?;
                if sha256(&original) != want {
                    return Err("saved button original changed".into());
                }
                let windows: Windows =
                    serde_json::from_slice(&original).map_err(|e| e.to_string())?;
                validate_captured(&source.original, &windows)?;
                if captured.as_ref().is_some_and(|old| old != &windows) {
                    return Err("button original changed between attempts".into());
                }
                captured = Some(windows);
            }
            reports.push((path.clone(), sha256(&raw), sha256(&journal)));
        }
        if possible_program && captured.is_none() {
            return Err("possible button program lacks durable original".into());
        }
        Ok(Self {
            source_sha256: source.fingerprint.clone(),
            native: source.native,
            binding,
            reports,
            captured,
            possible_program,
        })
    }
    pub fn load(source: &Source, path: &Path, native_required: bool) -> Result<Self, String> {
        let saved: Self =
            serde_json::from_slice(&read_file(path, 65536)?).map_err(|e| e.to_string())?;
        if saved.source_sha256 != source.fingerprint
            || saved.native != source.native
            || (native_required && !saved.native)
        {
            return Err("button recovery provenance differs".into());
        }
        let paths: Vec<_> = saved.reports.iter().map(|r| r.0.clone()).collect();
        let rebuilt = Self::make(source, &paths, saved.binding.clone())?;
        if serde_json::to_value(&saved).unwrap() != serde_json::to_value(&rebuilt).unwrap() {
            return Err("button recovery proof changed".into());
        }
        Ok(rebuilt)
    }
}
