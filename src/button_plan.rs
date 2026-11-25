//! Offline, allocation-free edits of an existing ordinary-button table.
use crate::{
    firmware::sha256,
    model::Core,
    preview::read_file,
    program::{self, Program},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

const BASE: usize = 0xe200;
const END: usize = 0xfe9c;
const TRIGGERS: usize = 24;
const EMPTY: u16 = 0x262e;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Disabled,
    Mouse { button: u8 },
    Program { program: Program },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    /// One-based host Trigger ordinal; physical labeling is separate.
    pub trigger: u8,
    pub action: Action,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub core: Core,
    pub version: u16,
    pub profile_index: u8,
    #[serde(default)]
    pub allow_shared_table: bool,
    pub edits: Vec<Edit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    schema_version: u8,
    image: PathBuf,
    image_sha256: String,
    request: Request,
}

#[derive(Debug, Serialize)]
pub struct WordChange {
    pub address: usize,
    pub main_word_index: usize,
    pub before: u16,
    pub after: u16,
}

#[derive(Debug, Serialize)]
pub struct Page {
    pub address: usize,
    pub original: Vec<u8>,
    pub candidate: Vec<u8>,
    pub original_sha256: String,
    pub candidate_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub mode: &'static str,
    pub core: Core,
    pub version: u16,
    pub image_sha256: String,
    pub profile_index: u8,
    pub affected_profiles: Vec<u8>,
    pub pointer_table_word_index: usize,
    pub button_table_word_index: usize,
    pub original_checksums: [u16; 2],
    pub candidate_checksums: [u16; 2],
    pub changes: Vec<WordChange>,
    pub pages: Vec<Page>,
    pub preflight_burst_addresses: Vec<usize>,
    pub burst_bytes: usize,
    pub full_device_reads: u8,
    pub uses_nor: bool,
    pub allocates_programs: bool,
    pub original_aggregate_checksums_independently_verified: bool,
    pub physical_execution_available: bool,
    pub blockers: [&'static str; 3],
}

fn word(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([image[at], image[at + 1]])
}

fn table_address(index: usize, words: usize) -> Result<usize, String> {
    let at = BASE + 2 * index;
    if index < 16 || at + 2 * words > END {
        return Err("profile table lies outside the supported main-profile area".into());
    }
    Ok(at)
}

fn action_words(action: &Action, core: Core, original_release: u16) -> Result<[u16; 2], String> {
    match action {
        Action::Disabled => Ok([EMPTY; 2]),
        Action::Mouse {
            button: button @ 1..=5,
        } => {
            let mask = 1u16 << (button - 1);
            Ok([0x2500 | mask, 0x2400 | mask])
        }
        Action::Mouse { .. } => Err("mouse button must be 1 through 5".into()),
        Action::Program { program } => {
            let words = program::compile(*program, core)?;
            if words.press.len() != 1 {
                return Err(
                    "multiword programs require allocation; this planner preserves existing pools"
                        .into(),
                );
            }
            let release = match words.release.as_deref() {
                Some([]) => EMPTY,
                Some([release]) => *release,
                None if original_release == EMPTY => original_release,
                _ => return Err(
                    "release behavior requires a separate allocation or established empty baseline"
                        .into(),
                ),
            };
            Ok([words.press[0], release])
        }
    }
}

pub fn plan(image: &[u8], request: &Request) -> Result<Plan, String> {
    if image.len() != 65536 {
        return Err("button plan requires one saved 64 KiB application image".into());
    }
    if !(request.version == 0x34 || (request.version == 0x28 && request.core == Core::One))
        || word(image, 0xfec4) != request.version
        || word(image, 0xfec6) != (0x578 | u16::from(request.core.firmware_index().get()))
    {
        return Err("image model/Core/version differs from supported request".into());
    }
    if image[BASE..BASE + 4] != [0xa4; 4] {
        return Err(
            "saved profile is invalid; built-in fallback materialization is separate".into(),
        );
    }
    let selector = word(image, BASE + 8);
    let max_profile = usize::from(selector >> 8);
    if max_profile > 6
        || usize::from(selector & 255) > max_profile
        || usize::from(request.profile_index) > max_profile
    {
        return Err("unsupported profile selector or profile index".into());
    }
    let pointer = usize::from(word(image, BASE + 14));
    if pointer & 0xc000 != 0 {
        return Err("external or flagged button pointer table is unsupported".into());
    }
    let pointer_address = table_address(pointer, max_profile + 1)?;
    let tables: Vec<_> = (0..=max_profile)
        .map(|i| usize::from(word(image, pointer_address + 2 * i)))
        .collect();
    for (i, &index) in tables.iter().enumerate() {
        table_address(index, 2 * TRIGGERS)?;
        let range = index..index + 2 * TRIGGERS;
        if range.start < pointer + max_profile + 1 && pointer < range.end {
            return Err("button data overlaps its pointer table".into());
        }
        for &other in &tables[..i] {
            if index != other && range.start < other + 2 * TRIGGERS && other < range.end {
                return Err("partially overlapping button tables are unsupported".into());
            }
        }
    }
    let table = tables[usize::from(request.profile_index)];
    let affected_profiles: Vec<_> = tables
        .iter()
        .enumerate()
        .filter_map(|(i, &index)| (index == table).then_some(i as u8))
        .collect();
    if affected_profiles.len() > 1 && !request.allow_shared_table {
        return Err(format!(
            "button table is shared by profiles {affected_profiles:?}; require allow_shared_table"
        ));
    }
    if request.edits.is_empty() || request.edits.len() > TRIGGERS {
        return Err("button plan requires 1 through 24 distinct trigger edits".into());
    }
    let mut seen = BTreeSet::new();
    let mut changes = Vec::new();
    let mut candidate = image.to_vec();
    let original_checksums = [word(image, BASE + 4), word(image, BASE + 6)];
    let mut checksums = original_checksums;
    for edit in &request.edits {
        if !(1..=24).contains(&edit.trigger) || !seen.insert(edit.trigger) {
            return Err("trigger ordinals must be distinct and within 1 through 24".into());
        }
        let index = table + 2 * usize::from(edit.trigger - 1);
        let at = table_address(index, 2)?;
        let values = action_words(&edit.action, request.core, word(image, at + 2))?;
        for (i, after) in values.into_iter().enumerate() {
            let address = at + 2 * i;
            let before = word(image, address);
            if before == after {
                continue;
            }
            let delta = after.wrapping_sub(before);
            checksums[0] = checksums[0].wrapping_add(delta);
            checksums[1] = checksums[1].wrapping_add(((index + i) as u16).wrapping_mul(delta));
            candidate[address..address + 2].copy_from_slice(&after.to_le_bytes());
            changes.push(WordChange {
                address,
                main_word_index: index + i,
                before,
                after,
            });
        }
    }
    if changes.is_empty() {
        return Err("requested assignments already match the image".into());
    }
    for (i, after) in checksums.iter().copied().enumerate() {
        let address = BASE + 4 + 2 * i;
        let before = word(image, address);
        candidate[address..address + 2].copy_from_slice(&after.to_le_bytes());
        if before != after {
            changes.push(WordChange {
                address,
                main_word_index: 2 + i,
                before,
                after,
            });
        }
    }
    changes.sort_by_key(|change| change.address);
    let mut addresses: BTreeSet<_> = changes.iter().map(|change| change.address & !63).collect();
    addresses.insert(BASE);
    let pages: Vec<_> = addresses
        .into_iter()
        .map(|address| {
            let original = image[address..address + 64].to_vec();
            let candidate = candidate[address..address + 64].to_vec();
            Page {
                address,
                original_sha256: sha256(&original),
                candidate_sha256: sha256(&candidate),
                original,
                candidate,
            }
        })
        .collect();
    let mut bursts = BTreeSet::from([0xfec0, 0xff40]);
    for page in &pages {
        bursts.extend([page.address, page.address + 32]);
    }
    for at in
        (pointer_address & !31..(pointer_address + 2 * (max_profile + 1) + 31) & !31).step_by(32)
    {
        bursts.insert(at);
    }
    Ok(Plan {
        mode: "offline_existing_button_table_plan",
        core: request.core,
        version: request.version,
        image_sha256: sha256(image),
        profile_index: request.profile_index,
        affected_profiles,
        pointer_table_word_index: pointer,
        button_table_word_index: table,
        original_checksums,
        candidate_checksums: checksums,
        changes,
        pages,
        preflight_burst_addresses: bursts.into_iter().collect(),
        burst_bytes: 32,
        full_device_reads: 0,
        uses_nor: false,
        allocates_programs: false,
        original_aggregate_checksums_independently_verified: false,
        physical_execution_available: false,
        blockers: [
            "Original combined main/additional/NOR checksum validity is not independently established by this delta plan.",
            "Profile write/commit, runtime activation and interrupted-write restoration need a dedicated executor and offline fault checks.",
            "Trigger ordinals identify compiler slots; physical button and special-function behavior still require qualification.",
        ],
    })
}

pub fn load(project: &Path) -> Result<Plan, String> {
    load_image_and_plan(project).map(|(_, plan)| plan)
}

pub(crate) fn load_image_and_plan(project: &Path) -> Result<(Vec<u8>, Plan), String> {
    let project_data: Project =
        serde_json::from_slice(&read_file(project, 65536)?).map_err(|e| e.to_string())?;
    if project_data.schema_version != 1 {
        return Err("unsupported button-plan schema version".into());
    }
    let image = read_file(
        &project
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(project_data.image),
        65536,
    )?;
    if sha256(&image) != project_data.image_sha256 {
        return Err("saved image hash differs from project".into());
    }
    let plan = plan(&image, &project_data.request)?;
    Ok((image, plan))
}
