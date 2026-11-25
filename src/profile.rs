//! Isolated program placement with the documented main-reference and NOR rules.
use crate::{
    model::Core,
    program::{self, Program, ProgramWords},
};
use serde::{Deserialize, Serialize};

const NOR_BYTE_BASE: u32 = 0x40000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Checksums {
    pub sum: u16,
    pub weighted: u16,
}

/// Each vector has its own index origin. Main indices 0–3 are excluded.
pub fn checksums(main: &[u16], additional: &[u16], nor: &[u16]) -> Checksums {
    let mut sum = 0u16;
    let mut weighted = 0u16;
    for (words, start) in [(main, 4), (additional, 0), (nor, 0)] {
        for (index, word) in words.iter().copied().enumerate().skip(start) {
            sum = sum.wrapping_add(word);
            weighted = weighted.wrapping_add((index as u16).wrapping_mul(word));
        }
    }
    Checksums { sum, weighted }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSelection {
    pub core: Core,
    pub entries: Vec<Program>,
}

#[derive(Debug, Serialize)]
pub struct ProgramPlacement {
    pub program: Program,
    pub words: ProgramWords,
    pub main_press_word: u16,
    pub main_release_word: Option<u16>,
    pub nor_start_word: Option<u32>,
    pub nor_byte_address: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ProfilePreview {
    pub core: Core,
    pub placements: Vec<ProgramPlacement>,
    pub macro_pointer_words: Vec<u16>,
    pub nor_words: Vec<u16>,
    pub nor_checksum_contribution: Checksums,
    pub whole_profile_blockers: [&'static str; 3],
}

/// Use the supplied order for this isolated vector and first-seen reference scan.
/// A named multiword list has a unique source identity; duplicates reuse it.
pub fn preview(selection: &ProgramSelection) -> Result<ProfilePreview, String> {
    if !(1..=64).contains(&selection.entries.len()) {
        return Err("program preview accepts 1 to 64 ordered entries".into());
    }
    let mut placements = Vec::new();
    let mut allocated: Vec<(Program, u32, u16)> = Vec::new();
    let mut pointers = Vec::new();
    let mut nor = Vec::new();
    for &program in &selection.entries {
        let words = program::compile(program, selection.core)?;
        let (main_press_word, nor_start_word) = if words.press.len() == 1 {
            (words.press[0], None)
        } else if let Some(&(_, start, reference)) =
            allocated.iter().find(|entry| entry.0 == program)
        {
            (reference, Some(start))
        } else {
            // At most 64 named lists with fewer than 32 words each.
            let start = nor.len() as u32;
            let reference = 0xB000 + allocated.len() as u16;
            allocated.push((program, start, reference));
            pointers.extend([start as u16, ((start >> 16) & 0xFF) as u16]);
            nor.extend_from_slice(&words.press);
            (reference, Some(start))
        };
        placements.push(ProgramPlacement {
            program,
            main_press_word,
            main_release_word: words
                .release
                .as_deref()
                .and_then(|words| words.first().copied()),
            nor_start_word,
            nor_byte_address: nor_start_word.map(|start| NOR_BYTE_BASE + 2 * start),
            words,
        });
    }
    Ok(ProfilePreview {
        core: selection.core,
        placements,
        macro_pointer_words: pointers,
        nor_checksum_contribution: checksums(&[], &[], &nor),
        nor_words: nor,
        whole_profile_blockers: [
            "Complete trigger, shooting-slot and lighting allocation order is unresolved.",
            "Complete main, additional and NOR baseline vectors are missing.",
            "Physical erase footprint, preservation and restoration are unverified.",
        ],
    })
}
