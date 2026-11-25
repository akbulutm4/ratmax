//! Versioned local projects and shared CLI/TUI compiler previews.
use crate::{
    firmware::sha256,
    model::Model,
    profile::{self, ProfilePreview, ProgramSelection},
    settings::{self, SettingsEdits, SettingsPreview},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    schema_version: u8,
    model: Model,
    settings: Option<SettingsSource>,
    programs: Option<ProgramSelection>,
    custom_shooting: Option<crate::program::gun_a::GunA>,
    macros: Option<crate::macros::Project>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsSource {
    image: PathBuf,
    response_mask: PathBuf,
    #[serde(default)]
    edits: SettingsEdits,
}

#[derive(Serialize)]
pub struct Preview {
    pub schema_version: u8,
    pub model: Model,
    pub project_sha256: String,
    pub settings: Option<SettingsPreview>,
    pub programs: Option<ProfilePreview>,
    pub custom_shooting: Option<crate::program::gun_a::Preview>,
    pub macros: Option<crate::macros::ProjectPreview>,
    pub write_ready: bool,
}

pub(crate) fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let error = |reason: &str| format!("{}: {reason}", path.display());
    let canonical = path.canonicalize().map_err(|e| error(&e.to_string()))?;
    if ["/dev", "/sys", "/proc"]
        .iter()
        .any(|p| canonical.starts_with(p))
        || !fs::symlink_metadata(path)
            .map_err(|e| error(&e.to_string()))?
            .is_file()
    {
        return Err(error(
            "inputs must be regular local files outside /dev, /sys and /proc",
        ));
    }
    let file = fs::File::open(canonical).map_err(|e| error(&e.to_string()))?;
    if !file
        .metadata()
        .map_err(|e| error(&e.to_string()))?
        .is_file()
    {
        return Err(error("opened input is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error(&e.to_string()))?;
    if bytes.len() > limit {
        return Err(error("input exceeds its size limit"));
    }
    Ok(bytes)
}

pub fn load(path: &Path) -> Result<Preview, String> {
    let raw = read_file(path, 64 * 1024)?;
    let project: Project =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if project.schema_version != 1 {
        return Err("unsupported preview project schema version".into());
    }
    if project.settings.is_none()
        && project.programs.is_none()
        && project.custom_shooting.is_none()
        && project.macros.is_none()
    {
        return Err("project requires settings, programs, custom_shooting or macros".into());
    }
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let settings = project
        .settings
        .as_ref()
        .map(|source| {
            let image = read_file(&root.join(&source.image), 0x10000)?;
            let mask = read_file(&root.join(&source.response_mask), 0x10000)?;
            settings::preview(&image, &mask, &source.edits)
        })
        .transpose()?;
    let programs = project
        .programs
        .as_ref()
        .map(profile::preview)
        .transpose()?;
    let custom_shooting = project
        .custom_shooting
        .as_ref()
        .map(crate::program::gun_a::preview)
        .transpose()?;
    let macros = project
        .macros
        .as_ref()
        .map(crate::macros::preview)
        .transpose()?;
    Ok(Preview {
        schema_version: 1,
        model: project.model,
        project_sha256: sha256(&raw),
        settings,
        programs,
        custom_shooting,
        macros,
        write_ready: false,
    })
}

impl Preview {
    pub fn text(&self) -> String {
        let mut text = format!("{} | offline compiler preview\n", self.model);
        if let Some(settings) = &self.settings {
            let _ = writeln!(
                text,
                "\nSettings · Core 1 / 0028 at {:04X}\n{} enabled slot(s) · selected slot {} · {}/256 non-echo bytes",
                settings.base,
                settings.enabled_slots,
                settings.selected_slot,
                settings.non_echo_bytes
            );
            for slot in &settings.slots {
                let [x, y, sensor] = slot.candidate_words;
                let coverage = if slot.non_echo { "" } else { " (ambiguous)" };
                let request = slot
                    .requested_cpi
                    .map_or_else(String::new, |value| format!(" ({value} CPI requested)"));
                let _ = writeln!(
                    text,
                    "Slot {}    {x:04X} {y:04X} {sensor:04X}{request}{coverage}",
                    slot.slot
                );
            }
            let rate_coverage = if settings.rate_non_echo {
                ""
            } else {
                " (ambiguous)"
            };
            let _ = writeln!(
                text,
                "Rate word   {:04X}{rate_coverage}",
                settings.candidate_rate_word
            );
            let [sum, weighted] = settings.candidate_checksums;
            let _ = writeln!(text, "Candidate checksums   {sum:04X} {weighted:04X}");
            for change in &settings.changes {
                let _ = writeln!(
                    text,
                    "+{:02X}    {:04X} → {:04X}",
                    change.offset, change.original, change.candidate
                );
            }
            let _ = writeln!(text, "Settings write blocked");
            for blocker in &settings.write_blockers {
                let _ = writeln!(text, "{blocker}");
            }
        }
        if let Some(programs) = &self.programs {
            let _ = writeln!(
                text,
                "\nPrograms · Core {} · isolated placement",
                programs.core.number()
            );
            for entry in &programs.placements {
                let target = entry
                    .nor_byte_address
                    .map_or_else(|| "inline".into(), |address| format!("NOR {address:05X}"));
                let release = entry
                    .main_release_word
                    .map_or_else(String::new, |word| format!(" · release {word:04X}"));
                let _ = writeln!(
                    text,
                    "{}    {} press word(s) · {:04X} · {target}{release}",
                    entry.program,
                    entry.words.press.len(),
                    entry.main_press_word
                );
            }
            let _ = writeln!(
                text,
                "{} NOR words · {} macro pointers",
                programs.nor_words.len(),
                programs.macro_pointer_words.len() / 2
            );
            for blocker in programs.whole_profile_blockers {
                let _ = writeln!(text, "{blocker}");
            }
        }
        if let Some(custom) = &self.custom_shooting {
            let _ = writeln!(
                text,
                "\nCustom Core-3 GunA · {} bullets · {} instruction words · offline only",
                custom.shot_timing_ms.len(),
                custom.words.press.len()
            );
            for word in &custom.words.press {
                let _ = write!(text, "{word:04X} ");
            }
            text.push('\n');
            for limitation in custom.limitations {
                let _ = writeln!(text, "{limitation}");
            }
        }
        if let Some(macros) = &self.macros {
            let _ = writeln!(
                text,
                "\nButton macros · Core {} · up to {} simultaneous buttons ({} / {} bytes, {} extra page(s))",
                macros.core.number(),
                macros.simultaneous_device_programs,
                macros.combined_internal_bytes,
                crate::macros::storage::MAX_STORAGE_BYTES,
                macros.combined_extended_pages
            );
            for b in &macros.bindings {
                let _ = writeln!(
                    text,
                    "{}: {} · {} ms · {} internal bytes ({} extra page(s)) · {}",
                    b.button.name(),
                    b.name,
                    b.compiled.duration_ms,
                    b.compiled.internal_bytes,
                    b.compiled.extended_pages,
                    if b.compiled.internal_installable {
                        "fits internal storage; device review required"
                    } else {
                        "exceeds 6,056-byte internal storage"
                    }
                );
                let _ = writeln!(
                    text,
                    "Press {:04X?} / release {:04X?}",
                    b.compiled.words.press, b.compiled.words.release
                );
            }
        }
        text
    }
}
