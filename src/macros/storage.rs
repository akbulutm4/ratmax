//! Bounded ordinary-button macros in internal main-profile flash (`E6D8..FE80`).
//! Single small macros (<= 40 bytes) keep the compact `A8xx` layout inside
//! `E6D8..E700`. Larger programs (up to 3,019 words) and multi-button sets
//! (up to all 7 configurable buttons, 6,056 bytes total) use the page-aligned
//! `A9xx` table in `E6D8..FE80`, staying strictly below the `FE80..FEBF` page
//! that holds the `FE9C` additional-vector marker.
use super::{Mouse, Sequence, Step, Target, compile};
use crate::{boot_roundtrip::Mode, model::Core, workflow::Button};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const BASE: usize = 0xe200;
const START: usize = 0xe6d8;
const COMPACT_END: usize = 0xe700;
pub const EXT_END: usize = 0xfe80;
pub const COMPACT_BYTES: usize = COMPACT_END - START; // 40 bytes
pub const MAX_EXT_PAGES: usize = (EXT_END - COMPACT_END) / 64; // 92 pages (5,888 bytes)
pub const MAX_STORAGE_BYTES: usize = EXT_END - START; // 6,056 bytes
const TAG_V1: u16 = 0xa800;
const TAG_V2: u16 = 0xa900;
const V2_HEADER_BYTES: usize = 4;
const V2_ENTRY_BYTES: usize = 10;
const GUARD_BYTES: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingEdit {
    pub button: Target,
    pub program: Sequence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Edit {
    Install { button: Target, program: Sequence },
    InstallAll { bindings: Vec<BindingEdit> },
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Current {
    pub button: Target,
    pub press_words: usize,
    pub release_words: usize,
}

struct Stored {
    button: Target,
    prior: [u16; 2],
    press: Vec<u16>,
    release: Vec<u16>,
}

fn word(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn put(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn v1_references(press: usize, release: usize) -> [u16; 2] {
    let start = ((START + 8 - BASE) / 2) as u16;
    [
        if press == 0 { 0x262e } else { 0xc000 | start },
        if release == 0 {
            0x262e
        } else {
            0xc000 | (start + press as u16)
        },
    ]
}

fn v2_references(stream_byte_offset: usize, press: usize, release: usize) -> [u16; 2] {
    let start = ((stream_byte_offset - BASE) / 2) as u16;
    [
        if press == 0 { 0x262e } else { 0xc000 | start },
        if release == 0 {
            0x262e
        } else {
            0xc000 | (start + press as u16)
        },
    ]
}

pub fn compact_bytes(press_words: usize, release_words: usize) -> usize {
    8 + 2 * (press_words + release_words) + GUARD_BYTES
}

pub fn v2_bytes_and_pages(entries: &[(usize, usize)]) -> (usize, usize) {
    let total_words: usize = entries.iter().map(|(p, r)| p + r).sum();
    let bytes = V2_HEADER_BYTES + V2_ENTRY_BYTES * entries.len() + 2 * total_words + GUARD_BYTES;
    let ext_pages = bytes.saturating_sub(COMPACT_BYTES).div_ceil(64);
    (bytes, ext_pages)
}

/// Returns `(bytes, extended_pages, installable)` for one button program.
pub fn single_storage(press_words: usize, release_words: usize) -> (usize, usize, bool) {
    let compact = compact_bytes(press_words, release_words);
    if compact <= COMPACT_BYTES {
        (compact, 0, true)
    } else {
        let (bytes, pages) = v2_bytes_and_pages(&[(press_words, release_words)]);
        (bytes, pages, bytes <= MAX_STORAGE_BYTES && pages <= MAX_EXT_PAGES)
    }
}

/// Returns `(bytes, extended_pages, installable)` for 1..=7 simultaneous button programs.
pub fn combined_storage(entries: &[(usize, usize)]) -> (usize, usize, bool) {
    if entries.is_empty() || entries.len() > Target::ALL.len() {
        return (0, 0, false);
    }
    if entries.len() == 1 {
        return single_storage(entries[0].0, entries[0].1);
    }
    let (bytes, pages) = v2_bytes_and_pages(entries);
    (bytes, pages, bytes <= MAX_STORAGE_BYTES && pages <= MAX_EXT_PAGES)
}

pub(crate) fn present(image: &[u8]) -> bool {
    image.len() == 65536 && matches!(word(image, START) & 0xff00, TAG_V1 | TAG_V2)
}

pub(crate) fn extended_pages(image: &[u8]) -> Result<usize, String> {
    if image.len() != 65536 {
        return Err("macro storage inspection requires a complete image".into());
    }
    let tag = word(image, START);
    if tag & 0xff00 == TAG_V2 {
        let count = usize::from(tag & 0xff);
        let pages = usize::from(word(image, START + 2));
        if !(1..=Target::ALL.len()).contains(&count) || pages > MAX_EXT_PAGES {
            return Err("invalid extended macro storage header".into());
        }
        Ok(pages)
    } else {
        Ok(0)
    }
}

fn canonical(canonical: &[u8]) -> Result<(), String> {
    if canonical.len() != 65536 || canonical[START..EXT_END].iter().any(|b| *b != 0) {
        return Err("macro storage stock tail differs".into());
    }
    Ok(())
}

fn allowed(pair: [u16; 2], image: &[u8], mode: Mode, target: Target) -> bool {
    pair == [
        word(image, target.address()),
        word(image, target.address() + 2),
    ] || Button::ALL
        .into_iter()
        .any(|a| a.words(mode, image).ok() == Some(pair))
}

fn decode(words: &[u16]) -> Result<Vec<Step>, String> {
    if words.is_empty() {
        return Ok(vec![]);
    }
    if words.last() != Some(&0x262f) {
        return Err("macro ending is missing".into());
    }
    words[..words.len() - 1]
        .iter()
        .map(|w| {
            let low = (w & 255) as u8;
            Ok(match w & 0xff00 {
                0x2100 | 0x2000 if (4..=0x97).contains(&low) => {
                    if w & 0xff00 == 0x2100 {
                        Step::KeyDown {
                            key: format!("hid:0x{low:02x}"),
                        }
                    } else {
                        Step::KeyUp {
                            key: format!("hid:0x{low:02x}"),
                        }
                    }
                }
                0x2300 | 0x2200 if low.is_power_of_two() => {
                    let key = format!("hid:0x{:02x}", 0xe0 + low.trailing_zeros());
                    if w & 0xff00 == 0x2300 {
                        Step::KeyDown { key }
                    } else {
                        Step::KeyUp { key }
                    }
                }
                0x2500 | 0x2400 => {
                    let button =
                        Mouse::from_mask(u16::from(low)).ok_or("unsupported macro mouse mask")?;
                    if w & 0xff00 == 0x2500 {
                        Step::MouseDown { button }
                    } else {
                        Step::MouseUp { button }
                    }
                }
                _ if (0x2801..=0x2be7).contains(w) => Step::Delay { ms: w - 0x2800 },
                _ if (0x4000..=0x7fff).contains(w) => {
                    let signed = |v: u16| {
                        if v & 64 != 0 {
                            (v as i16) - 128
                        } else {
                            v as i16
                        }
                    };
                    Step::Move {
                        x: signed((w >> 7) & 127),
                        y: signed(w & 127),
                    }
                }
                _ => return Err("unrecognized macro instruction".into()),
            })
        })
        .collect()
}

fn verify_words(press: &[u16], release: &[u16]) -> Result<(), String> {
    let program = Sequence {
        press: decode(press)?,
        release: decode(release)?,
        repeat: 1,
    };
    let compiled = compile(&program)?;
    if compiled.words.press != press || compiled.words.release.as_deref() != Some(release) {
        return Err("stored macro instructions differ after recompilation".into());
    }
    Ok(())
}

fn stored_all(image: &[u8], canonical_image: &[u8], mode: Mode) -> Result<Vec<Stored>, String> {
    if !present(image) {
        return Ok(vec![]);
    }
    if !matches!(mode, Mode::Target(Core::Three | Core::Four)) {
        return Err("ordinary macros require prepared Core 3/4".into());
    }
    canonical(canonical_image)?;
    let tag = word(image, START);
    if tag & 0xff00 == TAG_V1 {
        let id = usize::from(tag & 255);
        let button = *Target::ALL.get(id).ok_or("invalid stored macro button")?;
        let prior = [word(image, START + 2), word(image, START + 4)];
        if !allowed(prior, canonical_image, mode, button) {
            return Err("stored macro has an unsupported prior assignment".into());
        }
        let counts = word(image, START + 6);
        let pn = usize::from(counts & 255);
        let rn = usize::from(counts >> 8);
        if pn + rn == 0 || pn + rn > 14 {
            return Err("stored macro exceeds compact internal capacity".into());
        }
        let words: Vec<_> = (0..pn + rn)
            .map(|i| word(image, START + 8 + 2 * i))
            .collect();
        verify_words(&words[..pn], &words[pn..])?;
        let tail_end = crate::lighting::block_start(image)?.unwrap_or(EXT_END);
        if START + 8 + 2 * (pn + rn) + GUARD_BYTES > tail_end
            || image[START + 8 + 2 * (pn + rn)..tail_end]
                .iter()
                .any(|b| *b != 0)
        {
            return Err("stored macro guard/padding bytes differ".into());
        }
        let refs = v1_references(pn, rn);
        let at = button.address();
        if [word(image, at), word(image, at + 2)] != refs {
            return Err("stored macro control references differ".into());
        }
        return Ok(vec![Stored {
            button,
            prior,
            press: words[..pn].to_vec(),
            release: words[pn..].to_vec(),
        }]);
    }

    // Extended v2 format (TAG_V2 | count)
    let count = usize::from(tag & 0xff);
    let ext_pages = usize::from(word(image, START + 2));
    if !(1..=Target::ALL.len()).contains(&count) || ext_pages > MAX_EXT_PAGES {
        return Err("invalid extended macro storage header".into());
    }
    let region_end = COMPACT_END + 64 * ext_pages;
    let table_end = START + V2_HEADER_BYTES + V2_ENTRY_BYTES * count;
    if table_end + GUARD_BYTES > region_end {
        return Err("extended macro table exceeds declared pages".into());
    }
    let mut specs = Vec::with_capacity(count);
    let mut prev_id: Option<usize> = None;
    for i in 0..count {
        let off = START + V2_HEADER_BYTES + V2_ENTRY_BYTES * i;
        let id = usize::from(word(image, off));
        let button = *Target::ALL.get(id).ok_or("invalid stored macro button")?;
        if prev_id.is_some_and(|p| id <= p) {
            return Err("extended macro table must have strictly ascending unique buttons".into());
        }
        prev_id = Some(id);
        let prior = [word(image, off + 2), word(image, off + 4)];
        if !allowed(prior, canonical_image, mode, button) {
            return Err("stored macro has an unsupported prior assignment".into());
        }
        let pn = usize::from(word(image, off + 6));
        let rn = usize::from(word(image, off + 8));
        if pn + rn == 0 {
            return Err("extended macro entry has zero instructions".into());
        }
        specs.push((button, prior, pn, rn));
    }
    let word_pairs: Vec<(usize, usize)> = specs.iter().map(|(_, _, p, r)| (*p, *r)).collect();
    let (needed_bytes, expected_pages) = v2_bytes_and_pages(&word_pairs);
    if needed_bytes > MAX_STORAGE_BYTES || expected_pages != ext_pages {
        return Err("extended macro page count does not match minimal required pages".into());
    }
    let mut cursor = table_end;
    let mut entries = Vec::with_capacity(count);
    for (button, prior, pn, rn) in specs {
        let total = pn + rn;
        if cursor + 2 * total + GUARD_BYTES > region_end {
            return Err("extended macro stream exceeds declared pages".into());
        }
        let words: Vec<u16> = (0..total).map(|i| word(image, cursor + 2 * i)).collect();
        verify_words(&words[..pn], &words[pn..])?;
        let refs = v2_references(cursor, pn, rn);
        let at = button.address();
        if [word(image, at), word(image, at + 2)] != refs {
            return Err("stored extended macro control references differ".into());
        }
        cursor += 2 * total;
        entries.push(Stored {
            button,
            prior,
            press: words[..pn].to_vec(),
            release: words[pn..].to_vec(),
        });
    }
    let tail_end = crate::lighting::block_start(image)?.unwrap_or(EXT_END);
    if region_end > tail_end || image[cursor..tail_end].iter().any(|b| *b != 0) {
        return Err("extended macro guard/padding bytes are nonzero".into());
    }
    Ok(entries)
}

pub fn current(
    image: &[u8],
    canonical_image: &[u8],
    mode: Mode,
) -> Result<Option<Current>, String> {
    let all = current_all(image, canonical_image, mode)?;
    Ok((all.len() == 1).then(|| all.into_iter().next().unwrap()))
}

pub fn current_all(
    image: &[u8],
    canonical_image: &[u8],
    mode: Mode,
) -> Result<Vec<Current>, String> {
    Ok(stored_all(image, canonical_image, mode)?
        .into_iter()
        .map(|p| Current {
            button: p.button,
            press_words: p.press.len(),
            release_words: p.release.len(),
        })
        .collect())
}

pub fn validate_edit(edit: &Edit, mode: Mode) -> Result<(), String> {
    if !matches!(mode, Mode::Target(Core::Three | Core::Four)) {
        return Err("ordinary macros require prepared Core 3/4".into());
    }
    match edit {
        Edit::Remove => Ok(()),
        Edit::Install { program, .. } => {
            let compiled = compile(program)?;
            if !compiled.internal_installable {
                return Err(format!(
                    "macro needs {} bytes; extended internal storage holds {} bytes",
                    compiled.internal_bytes, MAX_STORAGE_BYTES
                ));
            }
            Ok(())
        }
        Edit::InstallAll { bindings } => {
            if bindings.is_empty() || bindings.len() > Target::ALL.len() {
                return Err("multi-button macro install requires 1..7 bindings".into());
            }
            let mut seen = BTreeSet::new();
            let mut sizes = Vec::with_capacity(bindings.len());
            for item in bindings {
                if !seen.insert(item.button) {
                    return Err("duplicate button in multi-button macro install".into());
                }
                let c = compile(&item.program)?;
                sizes.push((c.words.press.len(), c.words.release.as_deref().unwrap().len()));
            }
            let (bytes, _, fits) = combined_storage(&sizes);
            if !fits {
                return Err(format!(
                    "combined macros need {bytes} bytes; extended internal storage holds {MAX_STORAGE_BYTES} bytes"
                ));
            }
            Ok(())
        }
    }
}

fn build_entries(image: &mut [u8], entries: &[Stored]) {
    image[START..EXT_END].fill(0);
    if entries.len() == 1 {
        let e = &entries[0];
        if compact_bytes(e.press.len(), e.release.len()) <= COMPACT_BYTES {
            put(image, START, TAG_V1 | e.button.index() as u16);
            put(image, START + 2, e.prior[0]);
            put(image, START + 4, e.prior[1]);
            put(
                image,
                START + 6,
                e.press.len() as u16 | ((e.release.len() as u16) << 8),
            );
            for (i, w) in e.press.iter().chain(&e.release).enumerate() {
                put(image, START + 8 + 2 * i, *w);
            }
            for (i, w) in v1_references(e.press.len(), e.release.len())
                .into_iter()
                .enumerate()
            {
                put(image, e.button.address() + 2 * i, w);
            }
            checksum(image);
            return;
        }
    }
    if !entries.is_empty() {
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by_key(|&i| entries[i].button.index());
        let word_pairs: Vec<(usize, usize)> = order
            .iter()
            .map(|&i| (entries[i].press.len(), entries[i].release.len()))
            .collect();
        let (_, ext_pages) = v2_bytes_and_pages(&word_pairs);
        put(image, START, TAG_V2 | entries.len() as u16);
        put(image, START + 2, ext_pages as u16);
        let mut cursor = START + V2_HEADER_BYTES + V2_ENTRY_BYTES * entries.len();
        for (slot, &idx) in order.iter().enumerate() {
            let e = &entries[idx];
            let off = START + V2_HEADER_BYTES + V2_ENTRY_BYTES * slot;
            put(image, off, e.button.index() as u16);
            put(image, off + 2, e.prior[0]);
            put(image, off + 4, e.prior[1]);
            put(image, off + 6, e.press.len() as u16);
            put(image, off + 8, e.release.len() as u16);
            for (j, w) in e.press.iter().chain(&e.release).enumerate() {
                put(image, cursor + 2 * j, *w);
            }
            for (j, w) in v2_references(cursor, e.press.len(), e.release.len())
                .into_iter()
                .enumerate()
            {
                put(image, e.button.address() + 2 * j, w);
            }
            cursor += 2 * (e.press.len() + e.release.len());
        }
    }
    checksum(image);
}

fn checksum(image: &mut [u8]) {
    let words: Vec<_> = image[BASE..EXT_END]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let c = crate::profile::checksums(&words, &[], &[]);
    put(image, BASE + 4, c.sum);
    put(image, BASE + 6, c.weighted);
}

pub(crate) fn apply(
    image: &mut [u8],
    canonical_image: &[u8],
    mode: Mode,
    edit: &Edit,
) -> Result<(), String> {
    validate_edit(edit, mode)?;
    canonical(canonical_image)?;
    let previous = stored_all(image, canonical_image, mode)?;
    if previous.is_empty() && image[START..EXT_END].iter().any(|b| *b != 0) {
        return Err("remove the shooting program before installing an ordinary macro".into());
    }
    for old in &previous {
        for (i, w) in old.prior.into_iter().enumerate() {
            put(image, old.button.address() + 2 * i, w);
        }
    }
    image[START..EXT_END].fill(0);
    match edit {
        Edit::Remove => checksum(image),
        Edit::Install { button, program } => {
            let c = compile(program)?;
            let at = button.address();
            let prior = [word(image, at), word(image, at + 2)];
            if !allowed(prior, canonical_image, mode, *button) {
                return Err("macro destination has an unsupported assignment".into());
            }
            build_entries(
                image,
                &[Stored {
                    button: *button,
                    prior,
                    press: c.words.press,
                    release: c.words.release.unwrap(),
                }],
            );
        }
        Edit::InstallAll { bindings } => {
            let mut entries = Vec::with_capacity(bindings.len());
            for item in bindings {
                let c = compile(&item.program)?;
                let at = item.button.address();
                let prior = [word(image, at), word(image, at + 2)];
                if !allowed(prior, canonical_image, mode, item.button) {
                    return Err("macro destination has an unsupported assignment".into());
                }
                entries.push(Stored {
                    button: item.button,
                    prior,
                    press: c.words.press,
                    release: c.words.release.unwrap(),
                });
            }
            build_entries(image, &entries);
        }
    }
    Ok(())
}

/// Remove only `target` from the installed macro set, preserving all other macros.
pub(crate) fn remove_target(
    image: &mut [u8],
    canonical_image: &[u8],
    mode: Mode,
    target: Target,
) -> Result<(), String> {
    let mut previous = stored_all(image, canonical_image, mode)?;
    let Some(pos) = previous.iter().position(|e| e.button == target) else {
        return Ok(());
    };
    for old in &previous {
        for (i, w) in old.prior.into_iter().enumerate() {
            put(image, old.button.address() + 2 * i, w);
        }
    }
    previous.remove(pos);
    build_entries(image, &previous);
    Ok(())
}

/// Called before ordinary-button admission to recover all overwritten pairs.
pub(crate) fn priors(
    image: &[u8],
    canonical_image: &[u8],
    mode: Mode,
) -> Result<Vec<(Target, [u16; 2])>, String> {
    Ok(stored_all(image, canonical_image, mode)?
        .into_iter()
        .map(|p| (p.button, p.prior))
        .collect())
}

pub(crate) fn admit(
    image: &[u8],
    expected: &mut [u8],
    canonical_image: &[u8],
    mode: Mode,
) -> Result<(), String> {
    let entries = stored_all(image, canonical_image, mode)?;
    if !entries.is_empty() {
        build_entries(expected, &entries);
    }
    Ok(())
}

pub(crate) fn summary_all(image: &[u8]) -> Result<Vec<Current>, String> {
    if !present(image) {
        return Ok(vec![]);
    }
    let tag = word(image, START);
    if tag & 0xff00 == TAG_V1 {
        let button = *Target::ALL
            .get(usize::from(tag & 255))
            .ok_or("invalid stored macro button")?;
        let count = word(image, START + 6);
        return Ok(vec![Current {
            button,
            press_words: usize::from(count & 255),
            release_words: usize::from(count >> 8),
        }]);
    }
    let count = usize::from(tag & 0xff);
    let ext_pages = usize::from(word(image, START + 2));
    if !(1..=Target::ALL.len()).contains(&count) || ext_pages > MAX_EXT_PAGES {
        return Err("invalid extended macro storage header".into());
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = START + V2_HEADER_BYTES + V2_ENTRY_BYTES * i;
        let button = *Target::ALL
            .get(usize::from(word(image, off)))
            .ok_or("invalid stored macro button")?;
        out.push(Current {
            button,
            press_words: usize::from(word(image, off + 6)),
            release_words: usize::from(word(image, off + 8)),
        });
    }
    Ok(out)
}
