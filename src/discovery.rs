//! P1 passive discovery. Reads bounded, whitelisted cached sysfs files only.
//! No hidraw node is opened and no device report/driver operation is exposed.

use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use crate::{
    descriptor::{self, DescriptorSummary},
    firmware,
    queries::{NormalQuery, OfflineQueryFrame},
};

const TEXT_LIMIT: usize = 8192;
const ENTRY_LIMIT: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub node: Option<String>,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorSnapshot {
    pub bytes: usize,
    pub sha256: String,
    pub hex: String,
    pub summary: Option<DescriptorSummary>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSnapshot {
    pub node: String,
    pub devnode_name_only: String,
    pub hid_sysfs_path: String,
    pub hid_id: String,
    pub bus: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub major_minor: Option<String>,
    pub hid_name: Option<String>,
    pub hid_phys: Option<String>,
    pub hid_unique: Option<String>,
    pub usb_parent: Option<String>,
    pub usb_interface_path: Option<String>,
    pub usb_interface_number: Option<u8>,
    pub usb_bus_number: Option<u32>,
    pub usb_device_number: Option<u32>,
    pub usb_release_bcd: Option<u16>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub descriptor: Option<DescriptorSnapshot>,
    pub feature_07_total_bytes: Option<u32>,
    pub vendor_string_hint: Option<String>,
    pub candidate_for_later_query: bool,
    pub candidate_blockers: Vec<String>,
    pub model_confirmed: bool,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryReport {
    pub schema_version: u32,
    pub mode: &'static str,
    pub sysfs_root: String,
    pub collection_complete: bool,
    pub descriptor_analysis_complete: bool,
    pub scanned_hidraw_entries: usize,
    pub filtered_out_entries: usize,
    pub matching_interfaces: Vec<InterfaceSnapshot>,
    pub unique_query_candidate: Option<String>,
    pub ambiguous_query_candidates: Vec<String>,
    pub errors: Vec<Issue>,
    pub cached_file_open_attempts: Vec<String>,
    pub hidraw_handles_opened: usize,
    pub device_reports_sent: usize,
    pub live_queries_enabled: bool,
    pub limitations: Vec<&'static str>,
}

struct Reader {
    root: PathBuf,
    devices: PathBuf,
    open_attempts: RefCell<Vec<String>>,
}

impl Reader {
    fn canonical(&self, path: &Path) -> Result<PathBuf, String> {
        let target = path.canonicalize().map_err(|error| error.to_string())?;
        if !target.starts_with(&self.devices) {
            return Err("path escapes the selected sysfs devices tree".into());
        }
        Ok(target)
    }

    fn bytes(&self, path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
        let target = self.canonical(path)?;
        if !fs::metadata(&target)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("cached attribute is not a regular sysfs/fixture file".into());
        }
        // Sysfs st_size may be zero or a page size; read to EOF with a cap+1.
        let mut bytes = Vec::new();
        self.open_attempts
            .borrow_mut()
            .push(target.display().to_string());
        File::open(target)
            .map_err(|error| error.to_string())?
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > maximum {
            return Err(format!(
                "cached attribute exceeds {maximum}-byte bound; not truncated into valid data"
            ));
        }
        Ok(bytes)
    }

    fn text(&self, path: &Path) -> Result<String, String> {
        let bytes = self.bytes(path, TEXT_LIMIT)?;
        let mut text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
        if text.ends_with('\n') {
            text.pop();
        }
        Ok(text)
    }

    fn optional(&self, path: &Path, node: &str, errors: &mut Vec<Issue>) -> Option<String> {
        // NotFound is legitimate for optional USB strings; other failures are
        // visible rather than converted into empty metadata.
        if matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return None;
        }
        match self.text(path) {
            Ok(text) => Some(text),
            Err(detail) => {
                errors.push(issue(Some(node), path, detail));
                None
            }
        }
    }

    fn attribute_exists(&self, path: &Path, node: &str, errors: &mut Vec<Issue>) -> bool {
        match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                errors.push(issue(Some(node), path, error.to_string()));
                false
            }
        }
    }
}

fn issue(node: Option<&str>, path: &Path, detail: impl Into<String>) -> Issue {
    Issue {
        node: node.map(str::to_owned),
        path: path.display().to_string(),
        detail: detail.into(),
    }
}

fn valid_node(name: &str) -> bool {
    name.strip_prefix("hidraw").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn hid_identifiers(value: &str) -> Result<(u16, u16, u16), String> {
    let fields: Vec<_> = value.split(':').collect();
    if fields.len() != 3 {
        return Err("invalid HID_ID tuple".into());
    }
    let parse = |value: &str| {
        u16::from_str_radix(value, 16).map_err(|_| "invalid HID_ID number".to_owned())
    };
    Ok((parse(fields[0])?, parse(fields[1])?, parse(fields[2])?))
}

fn property<'a>(text: &'a str, name: &str) -> Result<Option<&'a str>, String> {
    let mut values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter_map(|(key, value)| (key == name).then_some(value));
    let value = values.next();
    if values.next().is_some() {
        return Err(format!("duplicate {name} property"));
    }
    Ok(value)
}

fn number<T>(
    text: Option<String>,
    radix: u32,
    node: &str,
    path: &Path,
    errors: &mut Vec<Issue>,
) -> Option<T>
where
    T: TryFrom<u32>,
{
    let text = text?;
    match u32::from_str_radix(text.trim(), radix)
        .ok()
        .and_then(|value| T::try_from(value).ok())
    {
        Some(value) => Some(value),
        None => {
            errors.push(issue(Some(node), path, "invalid numeric cached attribute"));
            None
        }
    }
}

pub fn collect(sysfs_root: &Path) -> Result<DiscoveryReport, String> {
    let root = sysfs_root
        .canonicalize()
        .map_err(|error| format!("sysfs root: {error}"))?;
    let reader = Reader {
        devices: root.join("devices"),
        root,
        open_attempts: RefCell::new(Vec::new()),
    };
    let class_path = reader.root.join("class/hidraw");
    let canonical_class = class_path.canonicalize().map_err(|error| {
        format!("hidraw class metadata unavailable: {error}; no raw-device fallback attempted")
    })?;
    if !canonical_class.starts_with(&reader.root) {
        return Err("hidraw class escapes the selected sysfs root".into());
    }
    let entries = fs::read_dir(&class_path)
        .map_err(|error| format!("cannot enumerate cached hidraw class: {error}"))?;
    let mut names = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                let name = entry.file_name().to_string_lossy().into_owned();
                if valid_node(&name) {
                    if names.len() == ENTRY_LIMIT {
                        errors.push(issue(None, &class_path, "hidraw entry limit exceeded"));
                        break;
                    }
                    names.push(name);
                }
            }
            Err(error) => errors.push(issue(None, &class_path, error.to_string())),
        }
    }
    names.sort();
    let scanned = names.len();
    let mut interfaces = Vec::new();
    let mut filtered = 0;
    for node in names {
        match collect_interface(&reader, &class_path, &node, &mut errors) {
            Ok(Some(interface)) => interfaces.push(interface),
            Ok(None) => filtered += 1,
            Err((path, detail)) => errors.push(issue(Some(&node), &path, detail)),
        }
    }
    let candidates: Vec<_> = interfaces
        .iter()
        .filter(|interface| interface.candidate_for_later_query)
        .map(|interface| interface.node.clone())
        .collect();
    let unique = (candidates.len() == 1 && errors.is_empty()).then(|| candidates[0].clone());
    Ok(DiscoveryReport {
        schema_version: 1,
        mode: "passive_cached_metadata",
        sysfs_root: reader.root.display().to_string(),
        collection_complete: errors.is_empty(),
        descriptor_analysis_complete: interfaces.iter().all(|interface| {
            interface
                .descriptor
                .as_ref()
                .is_some_and(|descriptor| descriptor.summary.is_some())
        }),
        scanned_hidraw_entries: scanned,
        filtered_out_entries: filtered,
        matching_interfaces: interfaces,
        unique_query_candidate: unique,
        ambiguous_query_candidates: if candidates.len() > 1 {
            candidates
        } else {
            Vec::new()
        },
        errors,
        cached_file_open_attempts: reader.open_attempts.into_inner(),
        hidraw_handles_opened: 0,
        device_reports_sent: 0,
        live_queries_enabled: false,
        limitations: vec![
            "Only cached sysfs metadata/descriptors were read; devnode paths are names, never opened.",
            "VID/product strings are candidate hints; ordinary W95 Max model/Core/firmware are unconfirmed until a separately scoped query.",
            "Descriptor geometry is advertised metadata, not measured feature-call behavior or configuration backup.",
            "Unique candidate selection does not enable live queries or prove cross-mode unit correlation.",
        ],
    })
}

fn collect_interface(
    reader: &Reader,
    class: &Path,
    node: &str,
    errors: &mut Vec<Issue>,
) -> Result<Option<InterfaceSnapshot>, (PathBuf, String)> {
    let entry = class.join(node);
    let device_link = entry.join("device");
    let hid = reader
        .canonical(&device_link)
        .map_err(|error| (device_link, error))?;
    let uevent_path = hid.join("uevent");
    let uevent = reader
        .text(&uevent_path)
        .map_err(|error| (uevent_path.clone(), error))?;
    let id = property(&uevent, "HID_ID")
        .map_err(|error| (uevent_path.clone(), error))?
        .ok_or_else(|| (uevent_path.clone(), "missing HID_ID".into()))?;
    let (bus, vid, pid) = hid_identifiers(id).map_err(|error| (uevent_path.clone(), error))?;
    if bus != 3 || vid != 0x09DA {
        return Ok(None);
    }
    let initial_errors = errors.len();
    let prop = |name| {
        property(&uevent, name)
            .map(|value| value.map(str::to_owned))
            .map_err(|error| (uevent_path.clone(), error))
    };
    let mut snapshot = InterfaceSnapshot {
        node: node.into(),
        devnode_name_only: format!("/dev/{node}"),
        hid_sysfs_path: hid.display().to_string(),
        hid_id: id.into(),
        bus,
        vendor_id: vid,
        product_id: pid,
        major_minor: reader.optional(&entry.join("dev"), node, errors),
        hid_name: prop("HID_NAME")?,
        hid_phys: prop("HID_PHYS")?,
        hid_unique: prop("HID_UNIQ")?,
        usb_parent: None,
        usb_interface_path: None,
        usb_interface_number: None,
        usb_bus_number: None,
        usb_device_number: None,
        usb_release_bcd: None,
        manufacturer: None,
        product: None,
        serial: None,
        descriptor: None,
        feature_07_total_bytes: None,
        vendor_string_hint: None,
        candidate_for_later_query: false,
        candidate_blockers: Vec::new(),
        model_confirmed: false,
    };
    for ancestor in hid
        .ancestors()
        .take(32)
        .filter(|path| path.starts_with(&reader.devices))
    {
        if snapshot.usb_interface_path.is_none()
            && reader.attribute_exists(&ancestor.join("bInterfaceNumber"), node, errors)
        {
            snapshot.usb_interface_path = Some(ancestor.display().to_string());
            let path = ancestor.join("bInterfaceNumber");
            snapshot.usb_interface_number = number(
                reader.optional(&path, node, errors),
                16,
                node,
                &path,
                errors,
            );
        }
        if reader.attribute_exists(&ancestor.join("idVendor"), node, errors) {
            let vendor_path = ancestor.join("idVendor");
            let product_path = ancestor.join("idProduct");
            let parent_vid: Option<u16> = number(
                reader.optional(&vendor_path, node, errors),
                16,
                node,
                &vendor_path,
                errors,
            );
            let parent_pid: Option<u16> = number(
                reader.optional(&product_path, node, errors),
                16,
                node,
                &product_path,
                errors,
            );
            if parent_vid != Some(vid) || parent_pid != Some(pid) {
                errors.push(issue(
                    Some(node),
                    ancestor,
                    "USB parent and HID identifiers differ/missing",
                ));
            }
            snapshot.usb_parent = Some(ancestor.display().to_string());
            snapshot.manufacturer = reader.optional(&ancestor.join("manufacturer"), node, errors);
            snapshot.product = reader.optional(&ancestor.join("product"), node, errors);
            snapshot.serial = reader.optional(&ancestor.join("serial"), node, errors);
            for (name, target) in [
                ("busnum", &mut snapshot.usb_bus_number),
                ("devnum", &mut snapshot.usb_device_number),
            ] {
                let path = ancestor.join(name);
                *target = number(
                    reader.optional(&path, node, errors),
                    10,
                    node,
                    &path,
                    errors,
                );
            }
            let path = ancestor.join("bcdDevice");
            snapshot.usb_release_bcd = number(
                reader.optional(&path, node, errors),
                16,
                node,
                &path,
                errors,
            );
            break;
        }
    }
    if snapshot.usb_parent.is_none() {
        snapshot
            .candidate_blockers
            .push("USB parent metadata not established".into());
    }
    if snapshot.usb_interface_number.is_none() {
        snapshot
            .candidate_blockers
            .push("USB interface number unavailable".into());
    }
    if snapshot
        .major_minor
        .as_ref()
        .is_none_or(|value| !valid_major_minor(value))
    {
        snapshot
            .candidate_blockers
            .push("device major/minor unavailable or invalid".into());
    }
    let descriptor_path = hid.join("report_descriptor");
    match reader.bytes(&descriptor_path, descriptor::MAX_DESCRIPTOR_BYTES) {
        Ok(bytes) => {
            let (summary, parse_error) = match descriptor::inspect(&bytes) {
                Ok(summary) => (Some(summary), None),
                Err(error) => (None, Some(error.to_string())),
            };
            snapshot.descriptor = Some(DescriptorSnapshot {
                bytes: bytes.len(),
                sha256: firmware::sha256(&bytes),
                hex: hex(&bytes),
                summary,
                parse_error,
            });
        }
        Err(detail) => errors.push(issue(Some(node), &descriptor_path, detail)),
    }
    if errors.len() != initial_errors {
        snapshot
            .candidate_blockers
            .push("cached metadata/descriptor read contains errors".into());
    }
    assess(&mut snapshot);
    Ok(Some(snapshot))
}

fn valid_major_minor(value: &str) -> bool {
    value
        .split_once(':')
        .is_some_and(|(major, minor)| major.parse::<u32>().is_ok() && minor.parse::<u32>().is_ok())
}

fn assess(snapshot: &mut InterfaceSnapshot) {
    let manufacturer = snapshot
        .manufacturer
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let product = snapshot
        .product
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if manufacturer.trim_end() == "a4 boot" || product.trim_end() == "boot device" {
        snapshot
            .candidate_blockers
            .push("known boot string; P1 normal query selection excludes it".into());
    }
    snapshot.vendor_string_hint = if manufacturer == "company " && product == "usb device  " {
        Some("vendor generic normal-string branch; model unknown".into())
    } else if matches!(manufacturer.as_str(), "company " | "a4tech  ")
        && matches!(product.as_str(), "w95max      " | "w95maxweb   ")
    {
        Some("named W95 Max product hint; model unknown".into())
    } else if matches!(manufacturer.as_str(), "company " | "a4tech  ")
        && product.contains("bloody")
        && product.encode_utf16().count() == 19
    {
        Some("vendor Bloody fallback string branch; model unknown".into())
    } else {
        None
    };
    if snapshot.vendor_string_hint.is_none() {
        snapshot
            .candidate_blockers
            .push("normal W95/generic vendor string hint not established".into());
    }
    match snapshot
        .descriptor
        .as_ref()
        .and_then(|descriptor| descriptor.summary.as_ref())
    {
        Some(summary) => match summary.feature_report(7) {
            Some(report) => {
                snapshot.feature_07_total_bytes = Some(report.total_report_bytes);
                if report.application_collections.len() != 1 {
                    snapshot
                        .candidate_blockers
                        .push("Feature ID 07 spans multiple Application collections".into());
                } else {
                    let usage =
                        summary.application_collections[report.application_collections[0]].usage;
                    if usage.excluded_normal_control() || usage.page == 0 || usage.id == 0 {
                        snapshot
                            .candidate_blockers
                            .push("Feature ID 07 belongs to an excluded/undefined usage".into());
                    }
                }
                if OfflineQueryFrame::new(NormalQuery::Status, report.total_report_bytes as usize)
                    .is_err()
                {
                    snapshot.candidate_blockers.push(
                        "Feature ID 07 geometry falls outside audited normal-query bounds".into(),
                    );
                }
            }
            None => snapshot
                .candidate_blockers
                .push("no Feature report ID 07 advertised".into()),
        },
        None => snapshot.candidate_blockers.push(
            "descriptor unavailable or not fully understood by the geometry inspector".into(),
        ),
    }
    snapshot.candidate_for_later_query = snapshot.candidate_blockers.is_empty();
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("String formatting");
    }
    text
}

impl DiscoveryReport {
    pub fn complete(&self) -> bool {
        self.collection_complete && self.descriptor_analysis_complete
    }

    /// Creates a new host-artifact directory; never overwrites an existing path.
    pub fn save(&self, output: &Path) -> Result<(), String> {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|error| error.to_string())?;
        if parent.starts_with(&self.sysfs_root) {
            return Err("snapshot output must be outside the sysfs root".into());
        }
        fs::create_dir(output)
            .map_err(|error| format!("snapshot directory must be new: {error}"))?;
        let document = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        fs::write(output.join("discovery.json"), document).map_err(|error| error.to_string())?;
        for interface in &self.matching_interfaces {
            if let Some(descriptor) = &interface.descriptor {
                let bytes = descriptor
                    .hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        u8::from_str_radix(std::str::from_utf8(pair).expect("hex ASCII"), 16)
                            .expect("captured hex")
                    })
                    .collect::<Vec<_>>();
                fs::write(
                    output.join(format!("{}.report_descriptor.bin", interface.node)),
                    bytes,
                )
                .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    pub fn text(&self) -> String {
        let mut text = format!(
            "ratmax | PASSIVE CACHED METADATA\nCached interfaces scanned: {}; filtered out: {}\nCollection complete: {}; descriptor analysis complete: {}\n",
            self.scanned_hidraw_entries,
            self.filtered_out_entries,
            self.collection_complete,
            self.descriptor_analysis_complete
        );
        for interface in &self.matching_interfaces {
            text.push_str(&format!("\n{} | USB {:04X}:{:04X} | interface {:?}\n  Manufacturer: {:?}\n  Product: {:?}\n  USB parent: {:?}\n  Feature ID 07 total bytes: {:?}\n  Candidate for later query: {} (model unconfirmed)\n", interface.node, interface.vendor_id, interface.product_id, interface.usb_interface_number, interface.manufacturer, interface.product, interface.usb_parent, interface.feature_07_total_bytes, interface.candidate_for_later_query));
            if let Some(descriptor) = &interface.descriptor {
                text.push_str(&format!(
                    "  Descriptor: {} bytes | SHA-256 {}\n",
                    descriptor.bytes, descriptor.sha256
                ));
                if let Some(error) = &descriptor.parse_error {
                    text.push_str(&format!("  Parse error: {error}\n"));
                }
            }
            for reason in &interface.candidate_blockers {
                text.push_str(&format!("  Blocked: {reason}\n"));
            }
        }
        for error in &self.errors {
            text.push_str(&format!("Error {}: {}\n", error.path, error.detail));
        }
        text.push_str(&format!("\nUnique candidate: {:?}; ambiguous candidates: {:?}\nNo hidraw handle opened. No device report sent. Live queries disabled.\n", self.unique_query_candidate, self.ambiguous_query_candidates));
        text
    }
}
