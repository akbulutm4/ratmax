//! Localized edits to a captured W95 Max Core 1/version 0028 candidate.
use crate::{firmware::sha256, sensitivity_block::checksums};
use serde::{Deserialize, Serialize};

const BASE: usize = 0xE000;
const SIZE: usize = 256;
const METADATA: std::ops::Range<usize> = 0xFEC0..0xFEE0;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpiEdit {
    pub slot: u8,
    pub cpi: u16,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsEdits {
    #[serde(default)]
    pub cpi: Vec<CpiEdit>,
    pub report_rate_hz: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct CpiSlot {
    pub slot: u8,
    pub original_words: [u16; 3],
    pub candidate_words: [u16; 3],
    pub non_echo: bool,
    pub requested_cpi: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct WordChange {
    pub offset: usize,
    pub original: u16,
    pub candidate: u16,
}

#[derive(Debug, Serialize)]
pub struct SettingsPreview {
    pub image_sha256: String,
    pub response_mask_sha256: String,
    pub candidate_sha256: String,
    pub base: usize,
    pub enabled_slots: u16,
    pub selected_slot: u16,
    pub slots: [CpiSlot; 5],
    pub original_rate_word: u16,
    pub candidate_rate_word: u16,
    pub rate_non_echo: bool,
    pub requested_rate_hz: Option<u16>,
    pub original_checksums: [u16; 2],
    pub candidate_checksums: [u16; 2],
    pub changes: Vec<WordChange>,
    pub non_echo_bytes: usize,
    pub response_mask: Vec<u8>,
    pub candidate_bytes: Vec<u8>,
    pub write_blockers: Vec<&'static str>,
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Calibrated 63-entry `SENSOR_3327` (`P3332A`) sensor step table (0..=6200 CPI in 100-CPI steps).
const SENSOR_3327_TABLE: [u16; 63] = [
    0x00, 0x00, 0x04, 0x06, 0x09, 0x0b, 0x0e, 0x10, 0x12, 0x15, 0x17, 0x19, 0x1b, 0x1d, 0x20, 0x22,
    0x24, 0x27, 0x29, 0x2b, 0x2e, 0x30, 0x32, 0x34, 0x37, 0x39, 0x3b, 0x3e, 0x40, 0x42, 0x45, 0x48,
    0x4a, 0x4d, 0x4e, 0x51, 0x54, 0x55, 0x58, 0x5b, 0x5d, 0x5f, 0x62, 0x64, 0x66, 0x69, 0x6b, 0x6d,
    0x70, 0x72, 0x74, 0x77, 0x79, 0x7b, 0x7e, 0x80, 0x82, 0x85, 0x87, 0x89, 0x8c, 0x8e, 0x91,
];
pub const MAX_CPI: u16 = 12_000;
pub const NATIVE_MAX_CPI: u16 = 6_200;
pub const MAX_SENSOR_STEP: u16 = 0x0091; // 145 (6200 CPI)
const MAX_SCALE_WORD: u16 = 124; // round(12000 / (6200 / 64)) = 0x007C

fn scale_above_6200(cpi: u16) -> u16 {
    // Q10.6 fixed-point scale relative to 6200 CPI native ceiling:
    // floor(cpi / (6200.0 / 64.0) + 0.5)
    let raw = (f64::from(cpi) / (f64::from(NATIVE_MAX_CPI) / 64.0) + 0.5).floor();
    raw.clamp(1.0, f64::from(MAX_SCALE_WORD)) as u16
}

fn ratio_scale(minor: u16, major: u16) -> u16 {
    // Q10.6 fixed-point minor/major axis ratio:
    // floor(((minor << 6) * 1.0) / major + 0.5)
    let raw = (f64::from(u32::from(minor) << 6) / f64::from(major) + 0.5).floor();
    raw.clamp(1.0, 64.0) as u16
}

pub fn encode_cpi(cpi: u16) -> Result<[u16; 3], String> {
    if !(22..=MAX_CPI).contains(&cpi) {
        return Err("equal-axis CPI supports 22–12000".into());
    }
    if cpi <= NATIVE_MAX_CPI {
        Ok([0x0040, 0x0040, (cpi + 22) / 44 - 1])
    } else {
        let s = scale_above_6200(cpi);
        Ok([s, s, MAX_SENSOR_STEP])
    }
}

/// Encode equal or asymmetric X/Y CPI for W95 Max `SENSOR_3327` (`P3332A`).
/// Equal-axis accepts 22–12000 CPI; asymmetric X != Y accepts 100–12000 CPI.
pub fn encode_cpi_xy(x: u16, y: u16) -> Result<[u16; 3], String> {
    if x == y {
        return encode_cpi(x);
    }
    if !(100..=MAX_CPI).contains(&x) || !(100..=MAX_CPI).contains(&y) {
        return Err("asymmetric X/Y CPI supports 100–12000 per axis".into());
    }
    if x > NATIVE_MAX_CPI || y > NATIVE_MAX_CPI {
        return Ok([scale_above_6200(x), scale_above_6200(y), MAX_SENSOR_STEP]);
    }
    if x > y {
        Ok([
            0x0040,
            ratio_scale(y, x),
            SENSOR_3327_TABLE[usize::from(x / 100)],
        ])
    } else {
        Ok([
            ratio_scale(x, y),
            0x0040,
            SENSOR_3327_TABLE[usize::from(y / 100)],
        ])
    }
}

pub fn valid_cpi_words(words: [u16; 3]) -> bool {
    let [wx, wy, step] = words;
    if !(1..=MAX_SCALE_WORD).contains(&wx)
        || !(1..=MAX_SCALE_WORD).contains(&wy)
        || step > MAX_SENSOR_STEP
    {
        return false;
    }
    if wx > 0x0040 || wy > 0x0040 {
        step == MAX_SENSOR_STEP
    } else {
        wx == 0x0040 || wy == 0x0040 || step == MAX_SENSOR_STEP
    }
}

/// Approximate `[x, y]` CPI decoding for stored sensitivity triples.
pub fn decode_cpi_xy(words: [u16; 3]) -> Option<[u32; 2]> {
    if !valid_cpi_words(words) {
        return None;
    }
    let [wx, wy, step] = words;
    if wx == 0x0040 && wy == 0x0040 && step <= 140 {
        let v = 44 * (u32::from(step) + 1);
        return Some([v, v]);
    }
    if step == MAX_SENSOR_STEP {
        let x = ((f64::from(wx) * f64::from(NATIVE_MAX_CPI)) / 64.0).round() as u32;
        let y = ((f64::from(wy) * f64::from(NATIVE_MAX_CPI)) / 64.0).round() as u32;
        return Some([x, y]);
    }
    let base = SENSOR_3327_TABLE
        .iter()
        .enumerate()
        .skip(1)
        .min_by_key(|(_, v)| v.abs_diff(step))
        .map_or(44 * (u32::from(step) + 1), |(idx, _)| (idx as u32) * 100);
    let x = ((f64::from(base) * f64::from(wx)) / 64.0).round() as u32;
    let y = ((f64::from(base) * f64::from(wy)) / 64.0).round() as u32;
    Some([x, y])
}

/// Parse user CPI text: `"1600"` for equal-axis or `"1600x800"` / `"1600/800"` / `"1600,800"` for asymmetric.
pub fn parse_cpi_input(input: &str) -> Result<(Option<u16>, Option<[u16; 2]>), String> {
    let trimmed = input.trim();
    if let Some((a, b)) = trimmed
        .split_once(['x', 'X', '/', ','])
    {
        let x = a
            .trim()
            .parse::<u16>()
            .map_err(|_| "invalid X CPI value".to_string())?;
        let y = b
            .trim()
            .parse::<u16>()
            .map_err(|_| "invalid Y CPI value".to_string())?;
        encode_cpi_xy(x, y)?;
        if x == y {
            Ok((Some(x), None))
        } else {
            Ok((None, Some([x, y])))
        }
    } else {
        let n = trimmed
            .parse::<u16>()
            .map_err(|_| "invalid CPI value (use e.g. 1600 or 1600x800)".to_string())?;
        encode_cpi(n)?;
        Ok((Some(n), None))
    }
}

pub fn encode_report_rate(hz: u16) -> Result<u16, String> {
    match hz {
        125 | 250 | 500 | 1000 => Ok(1000 / hz),
        2000 => Ok(0x0011),
        _ => Err("report-rate preview supports 125, 250, 500, 1000 or 2000 Hz".into()),
    }
}

pub fn preview(
    image: &[u8],
    mask: &[u8],
    edits: &SettingsEdits,
) -> Result<SettingsPreview, String> {
    if image.len() != 0x10000 || mask.len() != image.len() || mask.iter().any(|&b| b > 1) {
        return Err(
            "settings preview requires a 64 KiB image and an equally sized 0/1 response mask"
                .into(),
        );
    }
    let covered = |bytes: &[u8]| bytes.iter().all(|&b| b == 1);
    if !covered(&mask[METADATA]) || word(image, 0xFEC4) != 0x28 || word(image, 0xFEC6) != 0x579 {
        return Err(
            "settings preview requires non-echo W95 Max Core 1/version 0028 metadata".into(),
        );
    }
    let original = &image[BASE..BASE + SIZE];
    let coverage = &mask[BASE..BASE + SIZE];
    if !covered(&coverage[..12]) || original[..4] != [0xA4; 4] {
        return Err(
            "settings marker, checksums and selection fields must have non-echo coverage".into(),
        );
    }
    let stored = (word(original, 4), word(original, 6));
    if checksums(original)? != stored {
        return Err("settings candidate does not match its stored checksums".into());
    }
    let enabled_slots = word(original, 8)
        .checked_add(1)
        .ok_or("invalid enabled-slot count")?;
    let selected_slot = word(original, 10);
    if enabled_slots > 5 || selected_slot >= enabled_slots {
        return Err("settings candidate has invalid slot count or selection".into());
    }
    let mut candidate = original.to_vec();
    let mut requested = [None; 5];
    for edit in &edits.cpi {
        let slot = usize::from(edit.slot);
        if slot >= requested.len() || requested[slot].replace(edit.cpi).is_some() {
            return Err("CPI edits require distinct slots numbered 0–4".into());
        }
        let offset = 0x0C + 6 * slot;
        if !covered(&coverage[offset..offset + 6]) {
            return Err(format!("CPI slot {slot} includes an ambiguous byte"));
        }
        for (dest, encoded) in candidate[offset..offset + 6]
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(encode_cpi(edit.cpi)?)
        {
            dest.copy_from_slice(&encoded.to_le_bytes());
        }
    }
    let rate_non_echo = covered(&coverage[0x3C..0x3E]);
    if let Some(rate) = edits.report_rate_hz {
        if !rate_non_echo {
            return Err("report-rate field includes an ambiguous byte".into());
        }
        candidate[0x3C..0x3E].copy_from_slice(&encode_report_rate(rate)?.to_le_bytes());
    }
    let computed = checksums(&candidate)?;
    candidate[4..6].copy_from_slice(&computed.0.to_le_bytes());
    candidate[6..8].copy_from_slice(&computed.1.to_le_bytes());
    let slots = std::array::from_fn(|slot| {
        let offset = 0x0C + 6 * slot;
        CpiSlot {
            slot: slot as u8,
            original_words: std::array::from_fn(|i| word(original, offset + 2 * i)),
            candidate_words: std::array::from_fn(|i| word(&candidate, offset + 2 * i)),
            non_echo: covered(&coverage[offset..offset + 6]),
            requested_cpi: requested[slot],
        }
    });
    let changes = (4..SIZE)
        .step_by(2)
        .filter_map(|offset| {
            let original = word(original, offset);
            let candidate = word(&candidate, offset);
            (original != candidate).then_some(WordChange {
                offset,
                original,
                candidate,
            })
        })
        .collect();
    let non_echo_bytes = coverage.iter().map(|&v| usize::from(v)).sum();
    let mut write_blockers = Vec::new();
    if non_echo_bytes < SIZE {
        write_blockers.push("The sensitivity baseline includes ambiguous bytes.");
    }
    write_blockers.extend([
        "The affected erase footprint and preservation rules are unverified.",
        "Commit, runtime apply and restoration behavior require validation.",
    ]);
    Ok(SettingsPreview {
        image_sha256: sha256(image),
        response_mask_sha256: sha256(mask),
        candidate_sha256: sha256(&candidate),
        base: BASE,
        enabled_slots,
        selected_slot,
        slots,
        original_rate_word: word(original, 0x3C),
        candidate_rate_word: word(&candidate, 0x3C),
        rate_non_echo,
        requested_rate_hz: edits.report_rate_hz,
        original_checksums: [stored.0, stored.1],
        candidate_checksums: [computed.0, computed.1],
        changes,
        non_echo_bytes,
        response_mask: coverage.to_vec(),
        candidate_bytes: candidate,
        write_blockers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_and_asymmetric_cpi_match_vendor_sensor_3327_encoder() {
        // Verified equal-axis <= 6200 preserves exact legacy formula.
        assert_eq!(encode_cpi(1000).unwrap(), [0x0040, 0x0040, 0x0016]);
        assert_eq!(encode_cpi(1200).unwrap(), [0x0040, 0x0040, 0x001a]);
        assert_eq!(encode_cpi(1600).unwrap(), [0x0040, 0x0040, 0x0023]);
        assert_eq!(encode_cpi(6200).unwrap(), [0x0040, 0x0040, 0x008c]);
        // High equal-axis > 6200 uses Q10.6 scaling at sensor step 0x0091.
        assert_eq!(encode_cpi(8000).unwrap(), [83, 83, 0x0091]);
        assert_eq!(encode_cpi(12000).unwrap(), [124, 124, 0x0091]);
        assert!(encode_cpi(12001).is_err());
        assert!(encode_cpi(21).is_err());

        // Asymmetric <= 6200 uses SENSOR_3327_TABLE + Q10.6 ratio scale.
        assert_eq!(encode_cpi_xy(1600, 800).unwrap(), [0x0040, 0x0020, 0x0024]);
        assert_eq!(encode_cpi_xy(800, 1600).unwrap(), [0x0020, 0x0040, 0x0024]);
        // Asymmetric > 6200 scales both axes against 6200 at step 0x0091.
        assert_eq!(encode_cpi_xy(10000, 5000).unwrap(), [103, 52, 0x0091]);
        assert_eq!(encode_cpi_xy(3100, 9300).unwrap(), [32, 96, 0x0091]);
        assert!(encode_cpi_xy(99, 800).is_err());
        assert!(encode_cpi_xy(12001, 800).is_err());

        // Validation & decoding round-trip cleanly.
        for words in [
            encode_cpi(1200).unwrap(),
            encode_cpi(10000).unwrap(),
            encode_cpi_xy(1600, 800).unwrap(),
            encode_cpi_xy(10000, 5000).unwrap(),
        ] {
            assert!(valid_cpi_words(words));
            assert!(decode_cpi_xy(words).is_some());
        }
        assert_eq!(decode_cpi_xy([0x0040, 0x0040, 0x001a]), Some([1188, 1188]));
        assert_eq!(decode_cpi_xy([0x0040, 0x0020, 0x0024]), Some([1600, 800]));
        assert_eq!(decode_cpi_xy([124, 124, 0x0091]), Some([12013, 12013]));
        assert!(!valid_cpi_words([0, 64, 22]));
        assert!(!valid_cpi_words([100, 100, 50])); // >64 scale requires step 0x0091
        assert!(!valid_cpi_words([125, 125, 0x0091]));

        assert_eq!(parse_cpi_input("1600").unwrap(), (Some(1600), None));
        assert_eq!(parse_cpi_input("1600x800").unwrap(), (None, Some([1600, 800])));
        assert_eq!(parse_cpi_input("1600/1600").unwrap(), (Some(1600), None));
        assert!(parse_cpi_input("1600x").is_err());
    }
}
