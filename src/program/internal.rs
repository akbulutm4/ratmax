//! Self-describing Core-3 GunA shooting program in internal main-profile flash
//! (`E6D8..FE80`). 1–2 bullets keep the compact 40-byte `A701`/`A702` layout in
//! `E6D8..E700` (0 extra pages); 3–5 bullets use the page-aligned `A783`..`A785`
//! extended layout inside `E6D8..E780` (1 extra 64-byte page), with zero
//! external NOR writes.
use super::gun_a::{self, GunA, Shot};
use crate::{boot_roundtrip::Mode, model::Core};
use serde::{Deserialize, Serialize};

const BASE: usize = 0xe200;
pub const START: usize = BASE + 0x4d8;
pub const END: usize = BASE + 0x500;
const EXT_END: usize = 0xfe80;
const MAX_EXT_PAGES: usize = (EXT_END - END) / 64;
const TAG_COMPACT: u16 = 0xa700;
const TAG_EXT: u16 = 0xa780;
const SLOT: usize = BASE + 34; // Stock header word 11 points to word 16; slot 1.

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Edit {
    Install { program: GunA },
    Remove,
}

fn word(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(image[at..at + 2].try_into().unwrap())
}
fn put(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// Returns `(bytes_used, extra_64b_pages)` for a valid Core-3 GunA program (1–5 bullets).
pub fn storage_bytes_and_pages(program: &GunA) -> Result<(usize, usize), String> {
    let preview = gun_a::preview(program)?;
    let count = program.bullets.len();
    let compact_len = 2 + 4 * count + 2 * preview.words.press.len() + 4;
    if count <= 2 && compact_len <= END - START {
        Ok((compact_len, 0))
    } else {
        let ext_len = 4 + 4 * count + 2 * preview.words.press.len() + 4;
        let pages = ext_len.saturating_sub(END - START).div_ceil(64);
        if pages > MAX_EXT_PAGES {
            return Err("GunA program exceeds internal flash storage".into());
        }
        Ok((ext_len, pages))
    }
}

/// The decoder recovers source parameters and recompiles them before admission.
/// The two trailing zero words keep the receiver's three-word fetch in bounds.
fn encode(program: &GunA) -> Result<(Vec<u8>, u16, usize), String> {
    let preview = gun_a::preview(program)?;
    let count = program.bullets.len();
    let compact_offset = 2 + 4 * count;
    if count <= 2 && compact_offset + 2 * preview.words.press.len() + 4 <= END - START {
        let mut bytes = vec![0; END - START];
        bytes[..2].copy_from_slice(&(TAG_COMPACT | count as u16).to_le_bytes());
        for (i, shot) in program.bullets.iter().enumerate() {
            let at = 2 + 4 * i;
            bytes[at..at + 2].copy_from_slice(&shot.interval_ms.to_le_bytes());
            bytes[at + 2] = shot.move_x as u8;
            bytes[at + 3] = shot.move_y as u8;
        }
        for (i, value) in preview.words.press.iter().enumerate() {
            bytes[compact_offset + 2 * i..compact_offset + 2 * i + 2]
                .copy_from_slice(&value.to_le_bytes());
        }
        Ok((bytes, 0xc000 | ((START - BASE + compact_offset) / 2) as u16, 0))
    } else {
        let (needed, ext_pages) = storage_bytes_and_pages(program)?;
        let span = (END - START) + 64 * ext_pages;
        assert!(needed <= span);
        let offset = 4 + 4 * count;
        let mut bytes = vec![0; span];
        bytes[..2].copy_from_slice(&(TAG_EXT | count as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&(ext_pages as u16).to_le_bytes());
        for (i, shot) in program.bullets.iter().enumerate() {
            let at = 4 + 4 * i;
            bytes[at..at + 2].copy_from_slice(&shot.interval_ms.to_le_bytes());
            bytes[at + 2] = shot.move_x as u8;
            bytes[at + 3] = shot.move_y as u8;
        }
        for (i, value) in preview.words.press.iter().enumerate() {
            bytes[offset + 2 * i..offset + 2 * i + 2].copy_from_slice(&value.to_le_bytes());
        }
        Ok((
            bytes,
            0xc000 | ((START - BASE + offset) / 2) as u16,
            ext_pages,
        ))
    }
}

pub(crate) fn extended_pages(image: &[u8]) -> Result<usize, String> {
    if image.len() != 65536 {
        return Err("custom-program inspection requires a complete image".into());
    }
    let tag = word(image, START);
    if tag & 0xff80 == TAG_EXT {
        let count = usize::from(tag & 0x7f);
        let pages = usize::from(word(image, START + 2));
        if !(1..=5).contains(&count) || pages == 0 || pages > MAX_EXT_PAGES {
            return Err("invalid extended custom-program header".into());
        }
        Ok(pages)
    } else {
        Ok(0)
    }
}

pub fn validate_edit(edit: &Edit, mode: Mode) -> Result<(), String> {
    if mode != Mode::Target(Core::Three) {
        return Err("custom GunA installation requires prepared Core 3".into());
    }
    if let Edit::Install { program } = edit {
        encode(program)?;
    }
    Ok(())
}

pub fn current(image: &[u8], mode: Mode) -> Result<Option<GunA>, String> {
    if image.len() != 65536 {
        return Err("custom-program decoding requires a complete expected image".into());
    }
    if mode != Mode::Target(Core::Three) {
        return Ok(None);
    }
    if crate::macros::storage::present(image) {
        return Ok(None);
    }
    let tail_end = crate::lighting::block_start(image)?.unwrap_or(EXT_END);
    if image[START..tail_end].iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let tag = word(image, START);
    let (count, meta_start, ext_pages) = if tag & 0xff80 == TAG_EXT {
        let count = usize::from(tag & 0x7f);
        let pages = extended_pages(image)?;
        if !(3..=5).contains(&count) {
            return Err("invalid extended custom-program count".into());
        }
        (count, START + 4, pages)
    } else if tag & 0xff80 == TAG_COMPACT {
        let count = usize::from(tag & 0x7f);
        if !(1..=2).contains(&count) {
            return Err("invalid internal custom-program count".into());
        }
        (count, START + 2, 0)
    } else {
        return Err("unrecognized internal custom-program storage".into());
    };
    let bullets = (0..count)
        .map(|i| {
            let at = meta_start + 4 * i;
            Shot {
                interval_ms: word(image, at),
                move_x: image[at + 2] as i8,
                move_y: image[at + 3] as i8,
            }
        })
        .collect();
    let program = GunA {
        core: Core::Three,
        bullets,
    };
    let (bytes, reference, expected_pages) = encode(&program)?;
    let span_end = END + 64 * ext_pages;
    if expected_pages != ext_pages
        || span_end > tail_end
        || image[START..span_end] != bytes
        || image[span_end..tail_end].iter().any(|b| *b != 0)
        || word(image, SLOT) != reference
    {
        return Err("custom-program source, instructions or reference differ".into());
    }
    Ok(Some(program))
}

fn canonical_layout(canonical: &[u8]) -> Result<(), String> {
    if canonical.len() != 65536
        || word(canonical, BASE + 22) != 16
        || word(canonical, SLOT) != 0xc1f0
        || canonical[START..EXT_END].iter().any(|b| *b != 0)
    {
        return Err("internal custom-program stock layout differs".into());
    }
    Ok(())
}

/// Rebuild all checksums only after the caller has admitted the self-contained
/// stock/Ratmax main and the stock unallocated additional-vector marker.
pub(crate) fn apply(
    image: &mut [u8],
    canonical: &[u8],
    mode: Mode,
    edit: &Edit,
) -> Result<(), String> {
    validate_edit(edit, mode)?;
    canonical_layout(canonical)?;
    image[START..EXT_END].copy_from_slice(&canonical[START..EXT_END]);
    put(image, SLOT, word(canonical, SLOT));
    let mut sum_end = END;
    if let Edit::Install { program } = edit {
        let (bytes, reference, ext_pages) = encode(program)?;
        sum_end = END + 64 * ext_pages;
        image[START..sum_end].copy_from_slice(&bytes);
        put(image, SLOT, reference);
    }
    let words: Vec<_> = image[BASE..sum_end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let sums = crate::profile::checksums(&words, &[], &[]);
    put(image, BASE + 4, sums.sum);
    put(image, BASE + 6, sums.weighted);
    Ok(())
}

pub(crate) fn admit(
    image: &[u8],
    expected: &mut [u8],
    canonical: &[u8],
    mode: Mode,
) -> Result<(), String> {
    if let Some(program) = current(image, mode)? {
        apply(expected, canonical, mode, &Edit::Install { program })?;
    }
    Ok(())
}
