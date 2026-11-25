//! Bounded, offline HID geometry inspection. This is not a general HID decoder
//! or validator of all logical/physical field semantics. Unsupported syntax
//! fails closed; raw descriptor bytes are retained by the passive collector.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub const MAX_DESCRIPTOR_BYTES: usize = 65_535;
const MAX_DEPTH: usize = 32;
const MAX_REPORT_BITS: u32 = 65_535 * 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorError {
    pub offset: usize,
    pub detail: String,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "descriptor byte {}: {}", self.offset, self.detail)
    }
}
impl std::error::Error for DescriptorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub page: u16,
    pub id: u16,
}

impl Usage {
    pub const fn excluded_normal_control(self) -> bool {
        matches!(
            (self.page, self.id),
            (1, 2) | (1, 6) | (1, 0x80) | (0x0C, 1)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Input,
    Output,
    Feature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationCollection {
    pub index: usize,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportLayout {
    pub kind: ReportKind,
    pub report_id: u8,
    pub bits: u32,
    pub data_bytes: u32,
    /// Unnumbered reports have no ID byte on the wire. Numbered reports add one.
    pub total_report_bytes: u32,
    pub application_collections: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorSummary {
    pub application_collections: Vec<ApplicationCollection>,
    pub reports: Vec<ReportLayout>,
}

impl DescriptorSummary {
    pub fn feature_report(&self, id: u8) -> Option<&ReportLayout> {
        self.reports
            .iter()
            .find(|report| report.kind == ReportKind::Feature && report.report_id == id)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Globals {
    page: u16,
    size: u32,
    count: u32,
    id: u8,
}

#[derive(Default)]
struct Locals {
    usages: Vec<Usage>,
    minimum: Option<Usage>,
    maximum: Option<Usage>,
}

impl Locals {
    fn validate(&self) -> Result<(), &'static str> {
        match (self.minimum, self.maximum) {
            (None, None) => Ok(()),
            (Some(min), Some(max)) if min.page == max.page && min.id <= max.id => Ok(()),
            _ => Err("incomplete, reversed or cross-page usage range"),
        }
    }
    fn first(&self) -> Option<Usage> {
        self.usages.first().copied().or(self.minimum)
    }
}

#[derive(Default)]
struct Accumulator {
    bits: u32,
    applications: BTreeSet<usize>,
}

fn error(offset: usize, detail: impl Into<String>) -> DescriptorError {
    DescriptorError {
        offset,
        detail: detail.into(),
    }
}

fn usage(value: u32, size: usize, page: u16) -> Usage {
    Usage {
        page: if size == 4 {
            (value >> 16) as u16
        } else {
            page
        },
        id: value as u16,
    }
}

pub fn inspect(bytes: &[u8]) -> Result<DescriptorSummary, DescriptorError> {
    if bytes.is_empty() || bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(error(0, "empty or oversized descriptor"));
    }
    let mut globals = Globals::default();
    let mut global_stack = Vec::new();
    let mut locals = Locals::default();
    let mut collections: Vec<usize> = Vec::new();
    let mut applications = Vec::new();
    let mut reports: BTreeMap<(ReportKind, u8), Accumulator> = BTreeMap::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let at = offset;
        let prefix = bytes[offset];
        offset += 1;
        if prefix == 0xFE {
            return Err(error(
                at,
                "long items are unsupported; geometry is untrusted",
            ));
        }
        let size = match prefix & 3 {
            3 => 4,
            value => usize::from(value),
        };
        if bytes.len() - offset < size {
            return Err(error(at, "truncated short item"));
        }
        let mut raw = [0_u8; 4];
        raw[..size].copy_from_slice(&bytes[offset..offset + size]);
        let value = u32::from_le_bytes(raw);
        offset += size;
        let kind = (prefix >> 2) & 3;
        let tag = prefix >> 4;
        match kind {
            0 => {
                locals.validate().map_err(|detail| error(at, detail))?;
                match tag {
                    8 | 9 | 11 => {
                        let application = *collections.last().ok_or_else(|| {
                            error(at, "report field outside an Application collection")
                        })?;
                        if globals.size == 0 || globals.count == 0 {
                            return Err(error(at, "zero/missing report size or count"));
                        }
                        let bits = globals
                            .size
                            .checked_mul(globals.count)
                            .ok_or_else(|| error(at, "report bit count overflow"))?;
                        let report_kind = match tag {
                            8 => ReportKind::Input,
                            9 => ReportKind::Output,
                            _ => ReportKind::Feature,
                        };
                        let report = reports.entry((report_kind, globals.id)).or_default();
                        report.bits = report
                            .bits
                            .checked_add(bits)
                            .filter(|bits| *bits <= MAX_REPORT_BITS)
                            .ok_or_else(|| error(at, "report exceeds bounded geometry capacity"))?;
                        // Constant fields and padding contribute to length too.
                        report.applications.insert(application);
                    }
                    10 => {
                        if size != 1 || collections.len() >= MAX_DEPTH {
                            return Err(error(at, "invalid collection item or excessive nesting"));
                        }
                        let current = if collections.is_empty() {
                            if value != 1 {
                                return Err(error(at, "top-level collection is not Application"));
                            }
                            let collection_usage = locals
                                .first()
                                .ok_or_else(|| error(at, "Application collection has no usage"))?;
                            let index = applications.len();
                            applications.push(ApplicationCollection {
                                index,
                                usage: collection_usage,
                            });
                            index
                        } else {
                            if value == 1 {
                                return Err(error(
                                    at,
                                    "nested Application collections require separate analysis",
                                ));
                            }
                            *collections.last().expect("nonempty stack")
                        };
                        collections.push(current);
                    }
                    12 => {
                        if size != 0 || collections.pop().is_none() {
                            return Err(error(at, "unbalanced/invalid End Collection"));
                        }
                    }
                    _ => return Err(error(at, "unsupported main item")),
                }
                locals = Locals::default();
            }
            1 => match tag {
                0 => {
                    globals.page = u16::try_from(value)
                        .map_err(|_| error(at, "usage page exceeds 16 bits"))?;
                }
                1..=6 => {} // Logical/physical ranges and units do not alter geometry.
                7 => globals.size = value,
                8 => {
                    if size != 1 || value == 0 {
                        return Err(error(at, "invalid/reserved report ID"));
                    }
                    globals.id = value as u8;
                }
                9 => globals.count = value,
                10 => {
                    if size != 0 || global_stack.len() >= MAX_DEPTH {
                        return Err(error(at, "invalid/excessive global Push"));
                    }
                    global_stack.push(globals);
                }
                11 => {
                    if size != 0 {
                        return Err(error(at, "invalid global Pop"));
                    }
                    globals = global_stack
                        .pop()
                        .ok_or_else(|| error(at, "global Pop underflow"))?;
                }
                _ => return Err(error(at, "unsupported global item")),
            },
            2 => match tag {
                0 => {
                    if locals.usages.len() >= 1024 {
                        return Err(error(at, "too many local usages"));
                    }
                    locals.usages.push(usage(value, size, globals.page));
                }
                1 => locals.minimum = Some(usage(value, size, globals.page)),
                2 => locals.maximum = Some(usage(value, size, globals.page)),
                3..=5 | 7..=9 => {} // Designator/string indices do not alter geometry.
                _ => return Err(error(at, "unsupported local item/delimiter")),
            },
            _ => return Err(error(at, "reserved item type")),
        }
    }
    if !collections.is_empty() || !global_stack.is_empty() {
        return Err(error(offset, "unclosed collection/global stack"));
    }
    if applications.is_empty() || reports.is_empty() {
        return Err(error(offset, "no Application collection/report fields"));
    }
    for kind in [ReportKind::Input, ReportKind::Output, ReportKind::Feature] {
        if reports.contains_key(&(kind, 0))
            && reports.keys().any(|(other, id)| *other == kind && *id != 0)
        {
            return Err(error(
                offset,
                "mixed numbered/unnumbered reports of one type",
            ));
        }
    }
    let reports = reports
        .into_iter()
        .map(|((kind, report_id), report)| {
            let data_bytes = report.bits.div_ceil(8);
            ReportLayout {
                kind,
                report_id,
                bits: report.bits,
                data_bytes,
                total_report_bytes: data_bytes + u32::from(report_id != 0),
                application_collections: report.applications.into_iter().collect(),
            }
        })
        .collect();
    Ok(DescriptorSummary {
        application_collections: applications,
        reports,
    })
}
