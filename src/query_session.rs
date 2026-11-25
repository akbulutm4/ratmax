//! P2 typed query state machine and process supervision. Only the optional
//! worker owns a HID handle. Neither the TUI nor offline simulation calls it.
use crate::{
    discovery::{self, DiscoveryReport, InterfaceSnapshot},
    firmware,
    model::Core,
    queries::{NormalQuery, NormalReply, OfflineQueryFrame},
    readback::{
        self, BaselineAssessment, HeaderBaseline, HeaderObservation, HeaderRead, HeaderRegion,
        RuntimeDescriptorReply,
    },
    sensitivity_block::{BlockCapture, BlockCollector},
    sensitivity_body::{self, BodyCoverage, BodyObservation, FirstBodyRead},
    transport::LocalFeatureTransport,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SNAPSHOT_LIMIT: u64 = 1_048_576;
const LINE_LIMIT: usize = 16_384;
const DEADLINE: Duration = Duration::from_secs(5);
const BLOCK_MODE: &str = "normal_sensitivity_block_capture";
const MEMORY02_MODE: &str = "normal_sensitivity_memory02_capture";

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockMode {
    None,
    Legacy2f,
    Memory02,
}

fn make_collector(anchor: &BodyAnchor, memory02: bool) -> Result<BlockCollector, String> {
    if memory02 {
        anchor.validate_memory02_scope()?;
        BlockCollector::new_memory02(&anchor.header_anchor.layout()?, &anchor.sensitivity_header)
    } else {
        BlockCollector::new(&anchor.header_anchor.layout()?, &anchor.sensitivity_header)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub node: String,
    pub hid_sysfs_path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub major_minor: String,
    pub usb_parent: String,
    pub usb_interface_path: String,
    pub usb_interface_number: u8,
    pub usb_bus_number: u32,
    pub usb_device_number: u32,
    pub usb_release_bcd: u16,
    pub manufacturer: String,
    pub product: String,
    pub serial: Option<String>,
    pub hid_phys: Option<String>,
    pub hid_unique: Option<String>,
    pub descriptor_sha256: String,
    pub descriptor_bytes: usize,
    pub feature_07_total_bytes: usize,
}

impl Binding {
    pub fn from_report(report: &DiscoveryReport) -> Result<Self, String> {
        if !report.complete() || report.sysfs_root != "/sys" {
            return Err("query binding requires a complete real /sys snapshot".into());
        }
        let node = report
            .unique_query_candidate
            .as_deref()
            .ok_or("one unique control candidate is required")?;
        let interface = report
            .matching_interfaces
            .iter()
            .find(|i| i.node == node)
            .ok_or("candidate absent from snapshot")?;
        Self::from_interface(interface)
    }
    fn from_interface(i: &InterfaceSnapshot) -> Result<Self, String> {
        let d = i.descriptor.as_ref().ok_or("missing descriptor")?;
        if !i.candidate_for_later_query
            || i.model_confirmed
            || !i.candidate_blockers.is_empty()
            || d.parse_error.is_some()
        {
            return Err("not an unqueried normal control candidate".into());
        }
        i.manufacturer
            .as_ref()
            .ok_or("binding missing manufacturer")?;
        i.product.as_ref().ok_or("binding missing product")?;
        Self::from_control_interface(i)
    }
    pub(crate) fn from_control_interface(i: &InterfaceSnapshot) -> Result<Self, String> {
        fn required<T: Clone>(v: &Option<T>, name: &str) -> Result<T, String> {
            v.clone().ok_or_else(|| format!("binding missing {name}"))
        }
        let d = i.descriptor.as_ref().ok_or("missing descriptor")?;
        let binding = Self {
            node: i.node.clone(),
            hid_sysfs_path: i.hid_sysfs_path.clone(),
            vendor_id: i.vendor_id,
            product_id: i.product_id,
            major_minor: required(&i.major_minor, "major/minor")?,
            usb_parent: required(&i.usb_parent, "USB parent")?,
            usb_interface_path: required(&i.usb_interface_path, "USB interface path")?,
            usb_interface_number: required(&i.usb_interface_number, "USB interface number")?,
            usb_bus_number: required(&i.usb_bus_number, "USB bus")?,
            usb_device_number: required(&i.usb_device_number, "USB device generation")?,
            usb_release_bcd: required(&i.usb_release_bcd, "bcdDevice")?,
            manufacturer: i.manufacturer.clone().unwrap_or_default(),
            product: i.product.clone().unwrap_or_default(),
            serial: i.serial.clone(),
            hid_phys: i.hid_phys.clone(),
            hid_unique: i.hid_unique.clone(),
            descriptor_sha256: d.sha256.clone(),
            descriptor_bytes: d.bytes,
            feature_07_total_bytes: required(&i.feature_07_total_bytes, "Feature 07 length")?
                as usize,
        };
        binding.validate()?;
        Ok(binding)
    }
    pub fn validate(&self) -> Result<(), String> {
        let suffix = self
            .node
            .strip_prefix("hidraw")
            .ok_or("invalid node name")?;
        if suffix.is_empty()
            || !suffix.bytes().all(|b| b.is_ascii_digit())
            || self.vendor_id != 0x09DA
        {
            return Err("invalid query node or VID".into());
        }
        for p in [
            &self.hid_sysfs_path,
            &self.usb_parent,
            &self.usb_interface_path,
        ] {
            let path = Path::new(p);
            if !path.starts_with("/sys/devices")
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err("binding must remain under /sys/devices".into());
            }
        }
        if !Path::new(&self.hid_sysfs_path).starts_with(&self.usb_interface_path)
            || !Path::new(&self.usb_interface_path).starts_with(&self.usb_parent)
            || self.major_minor.split(':').count() != 2
            || self
                .major_minor
                .split(':')
                .any(|s| s.parse::<u32>().is_err())
            || self.descriptor_bytes == 0
            || self.descriptor_bytes > 65_535
            || self.descriptor_sha256.len() != 64
            || !self
                .descriptor_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("inconsistent binding metadata".into());
        }
        // R3c supports only the normal geometry actually captured in R3b.
        if self.feature_07_total_bytes != 64 {
            return Err("P2 requires the captured 64-byte normal Feature 07 geometry".into());
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> String {
        firmware::sha256(&serde_json::to_vec(self).expect("binding serializes"))
    }
    pub fn revalidate(&self, report: &DiscoveryReport) -> Result<(), String> {
        if Self::from_report(report)? != *self {
            return Err("candidate binding changed; no access/query permitted".into());
        }
        Ok(())
    }
    pub(crate) fn revalidate_control(&self, report: &DiscoveryReport) -> Result<(), String> {
        if !report.complete() || report.sysfs_root != "/sys" {
            return Err("control binding requires complete cached metadata".into());
        }
        let interface = report
            .matching_interfaces
            .iter()
            .find(|interface| interface.node == self.node)
            .ok_or("control interface disappeared")?;
        let observed = Self::from_control_interface(interface)?;
        if observed != *self {
            let expected = serde_json::to_value(self).map_err(|e| e.to_string())?;
            let actual = serde_json::to_value(&observed).map_err(|e| e.to_string())?;
            let fields: Vec<_> = expected
                .as_object()
                .expect("binding object")
                .iter()
                .filter_map(|(key, value)| (actual.get(key) != Some(value)).then_some(key.as_str()))
                .collect();
            return Err(format!(
                "control binding changed in [{}]: expected {}, observed {}",
                fields.join(", "),
                self.fingerprint(),
                observed.fingerprint()
            ));
        }
        Ok(())
    }
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    fn device_path(&self) -> String {
        format!("/dev/{}", self.node)
    }
}

/// Read saved P1 evidence, never a raw device path. Revalidated from /sys before access.
pub fn load_binding(path: &Path) -> Result<Binding, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(SNAPSHOT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > SNAPSHOT_LIMIT as usize {
        return Err("snapshot exceeds 1 MiB bound".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value["schema_version"] != 1
        || value["mode"] != "passive_cached_metadata"
        || value["sysfs_root"] != "/sys"
        || value["collection_complete"] != true
        || value["descriptor_analysis_complete"] != true
        || value["errors"].as_array().is_none_or(|v| !v.is_empty())
        || value["ambiguous_query_candidates"]
            .as_array()
            .is_none_or(|v| !v.is_empty())
    {
        return Err("saved P1 snapshot is incomplete or not a real passive snapshot".into());
    }
    // InterfaceSnapshot contains only owned fields and bounded descriptor bytes.
    let node = value["unique_query_candidate"]
        .as_str()
        .ok_or("no unique saved candidate")?;
    let matches = value["matching_interfaces"]
        .as_array()
        .ok_or("missing interfaces")?;
    let selected: Vec<_> = matches.iter().filter(|i| i["node"] == node).collect();
    if selected.len() != 1 {
        return Err("saved candidate must occur exactly once".into());
    }
    let interface: InterfaceSnapshot =
        serde_json::from_value(selected[0].clone()).map_err(|e| e.to_string())?;
    let d = interface
        .descriptor
        .as_ref()
        .ok_or("missing saved descriptor")?;
    let raw = decode_hex(&d.hex)?;
    if raw.len() != d.bytes || firmware::sha256(&raw) != d.sha256 {
        return Err("saved descriptor bytes/hash mismatch".into());
    }
    let parsed = crate::descriptor::inspect(&raw).map_err(|e| e.to_string())?;
    let feature = parsed
        .feature_report(7)
        .ok_or("saved descriptor has no Feature 07")?;
    if feature.total_report_bytes != 64 || feature.application_collections.len() != 1 {
        return Err("saved Feature 07 geometry/association invalid".into());
    }
    Binding::from_interface(&interface)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err("invalid descriptor hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).expect("ASCII"), 16)
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// Pins a descriptor session to a previously successful bound information
/// capture. Raw replies are decoded again; JSON's decoded claims are not trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineAnchor {
    binding_sha256: String,
    core: Core,
    version_compare_word: u16,
    display_version_word: u16,
    source_session_sha256: String,
}
impl BaselineAnchor {
    pub fn from_session_bytes(bytes: &[u8], binding: &Binding) -> Result<Self, String> {
        if bytes.len() > SNAPSHOT_LIMIT as usize {
            return Err("information baseline exceeds 1 MiB".into());
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if value["schema_version"] != 1
            || value["mode"] != "normal_information_queries"
            || value["complete"] != true
            || value["worker_reaped"] != true
            || value["worker_exit_success"] != true
            || value["uncertain"] != false
            || value["lock_retained"] != false
            || value["post_binding_matches"] != true
            || value["configuration_or_firmware_writes"] != 0
            || value["resets_or_boot_transitions"] != 0
            || !value["failure"].is_null()
        {
            return Err(
                "baseline must be a completed, stopped, bound normal information session".into(),
            );
        }
        let saved: Binding =
            serde_json::from_value(value["binding"].clone()).map_err(|e| e.to_string())?;
        saved.validate()?;
        if saved != *binding || value["binding_sha256"] != binding.fingerprint() {
            return Err("information baseline binding differs from selected snapshot".into());
        }
        let events: Vec<WorkerEvent> =
            serde_json::from_value(value["events"].clone()).map_err(|e| e.to_string())?;
        let phases = [
            "open",
            "IdentitySet",
            "IdentityGet",
            "StatusSet",
            "StatusGet",
            "Close",
        ];
        if events.len() != phases.len()
            || events
                .iter()
                .zip(phases)
                .any(|(e, p)| e.phase != p || !e.ok || e.error.is_some())
        {
            return Err("information baseline has missing/failed/out-of-order events".into());
        }
        let commands = std::iter::once(WorkerCommand::Open(Box::new(binding.clone()))).chain(
            QueryAction::SEQUENCE
                .into_iter()
                .map(WorkerCommand::Advance),
        );
        for (command, event) in commands.zip(&events) {
            validate_event(&command, event)?;
        }
        let Some(NormalReply::Identity {
            core,
            version_compare_word,
            ..
        }) = events[2].decoded
        else {
            return Err("baseline identity missing".into());
        };
        let Some(NormalReply::Status {
            display_version_word,
            ..
        }) = events[4].decoded
        else {
            return Err("baseline status missing".into());
        };
        Ok(Self {
            binding_sha256: binding.fingerprint(),
            core,
            version_compare_word,
            display_version_word,
            source_session_sha256: firmware::sha256(bytes),
        })
    }
    fn validate_binding(&self, binding: &Binding) -> Result<(), String> {
        if self.binding_sha256 != binding.fingerprint()
            || self.source_session_sha256.len() != 64
            || !self
                .source_session_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("descriptor baseline does not bind this interface/session evidence".into());
        }
        Ok(())
    }
    fn check_reply(&self, reply: &NormalReply) -> Result<(), String> {
        match reply {
            NormalReply::Identity{core,version_compare_word,..} if *core!=self.core || *version_compare_word!=self.version_compare_word => Err("normal identity/Core/comparison-version changed from baseline; descriptor prohibited".into()),
            NormalReply::Status{display_version_word,..} if *display_version_word!=self.display_version_word => Err("normal display-version changed from baseline; descriptor prohibited".into()),
            _=>Ok(()),
        }
    }
}
fn load_anchor(path: &Path, binding: &Binding) -> Result<BaselineAnchor, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(SNAPSHOT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    BaselineAnchor::from_session_bytes(&bytes, binding)
}

/// A saved successful layout, tied to the independently validated information
/// baseline. Only its two audited header windows can reach the live transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderAnchor {
    baseline: BaselineAnchor,
    layout_reply: Vec<u8>,
    source_layout_session_sha256: String,
}
impl HeaderAnchor {
    pub fn from_session_bytes(
        bytes: &[u8],
        binding: &Binding,
        baseline: &BaselineAnchor,
    ) -> Result<Self, String> {
        if bytes.len() > SNAPSHOT_LIMIT as usize {
            return Err("layout baseline exceeds 1 MiB".into());
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if value["schema_version"] != 1
            || value["mode"] != "normal_runtime_descriptor_query"
            || value["complete"] != true
            || value["worker_reaped"] != true
            || value["worker_exit_success"] != true
            || value["uncertain"] != false
            || value["lock_retained"] != false
            || value["post_binding_matches"] != true
            || value["configuration_or_firmware_writes"] != 0
            || value["resets_or_boot_transitions"] != 0
            || !value["failure"].is_null()
        {
            return Err("headers require a successful stopped bound layout session".into());
        }
        let saved: Binding =
            serde_json::from_value(value["binding"].clone()).map_err(|e| e.to_string())?;
        let saved_anchor: BaselineAnchor =
            serde_json::from_value(value["baseline"].clone()).map_err(|e| e.to_string())?;
        if saved != *binding
            || value["binding_sha256"] != binding.fingerprint()
            || saved_anchor != *baseline
        {
            return Err("saved layout binding/information baseline differs".into());
        }
        let events: Vec<WorkerEvent> =
            serde_json::from_value(value["events"].clone()).map_err(|e| e.to_string())?;
        let commands = std::iter::once(WorkerCommand::OpenLayout {
            binding: Box::new(binding.clone()),
            baseline: Box::new(baseline.clone()),
        })
        .chain(
            QueryAction::LAYOUT_SEQUENCE
                .into_iter()
                .map(WorkerCommand::Advance),
        );
        if events.len() != 8 || events.iter().any(|e| !e.ok || e.error.is_some()) {
            return Err("saved layout events incomplete or failed".into());
        }
        for (command, event) in commands.zip(&events) {
            validate_event(&command, event)?;
            if let Some(decoded) = &event.decoded {
                baseline.check_reply(decoded)?;
            }
        }
        let raw = events[6]
            .reply
            .clone()
            .ok_or("saved layout raw reply missing")?;
        let decoded = RuntimeDescriptorReply::decode(&raw).map_err(|e| e.to_string())?;
        if value["runtime_descriptor"]
            != serde_json::to_value(&decoded).map_err(|e| e.to_string())?
        {
            return Err("saved layout decoded claims differ from raw reply".into());
        }
        let anchor = Self {
            baseline: baseline.clone(),
            layout_reply: raw,
            source_layout_session_sha256: firmware::sha256(bytes),
        };
        anchor.validate_binding(binding)?;
        Ok(anchor)
    }
    fn layout(&self) -> Result<RuntimeDescriptorReply, String> {
        RuntimeDescriptorReply::decode(&self.layout_reply).map_err(|e| e.to_string())
    }
    fn validate_binding(&self, binding: &Binding) -> Result<(), String> {
        self.baseline.validate_binding(binding)?;
        if self.source_layout_session_sha256.len() != 64
            || !self
                .source_layout_session_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid saved layout session digest".into());
        }
        let layout = self.layout()?;
        let sensitivity = layout
            .header_read(HeaderRegion::Sensitivity)
            .map_err(|e| e.to_string())?
            .requested_span();
        let main = layout
            .header_read(HeaderRegion::MainProfile)
            .map_err(|e| e.to_string())?
            .requested_span();
        if u64::from(sensitivity.start()) < main.end_exclusive()
            && u64::from(main.start()) < sensitivity.end_exclusive()
        {
            return Err("audited header windows overlap; stop for layout review".into());
        }
        Ok(())
    }
    fn check_layout(&self, layout: &RuntimeDescriptorReply) -> Result<(), String> {
        if layout.raw_reply() != self.layout_reply {
            return Err("full runtime descriptor changed; no header read permitted".into());
        }
        Ok(())
    }
    fn read(&self, action: QueryAction) -> Result<HeaderRead, String> {
        self.layout()?
            .header_read(action.header_region().ok_or("not a scoped header action")?)
            .map_err(|e| e.to_string())
    }
}

/// Saved R3h provenance and exact sensitivity header for the one +8 experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyAnchor {
    header_anchor: HeaderAnchor,
    sensitivity_header: Vec<u8>,
    source_headers_session_sha256: String,
}
impl BodyAnchor {
    pub fn from_session_bytes(
        bytes: &[u8],
        binding: &Binding,
        anchor: &HeaderAnchor,
    ) -> Result<Self, String> {
        if bytes.len() > SNAPSHOT_LIMIT as usize {
            return Err("header baseline exceeds 1 MiB".into());
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if value["schema_version"] != 1
            || value["mode"] != "normal_header_observations"
            || value["complete"] != true
            || value["worker_reaped"] != true
            || value["worker_exit_success"] != true
            || value["uncertain"] != false
            || value["lock_retained"] != false
            || value["post_binding_matches"] != true
            || value["configuration_or_firmware_writes"] != 0
            || value["resets_or_boot_transitions"] != 0
            || !value["failure"].is_null()
        {
            return Err("body experiment requires a completed stopped bound header session".into());
        }
        let saved_binding: Binding =
            serde_json::from_value(value["binding"].clone()).map_err(|e| e.to_string())?;
        let saved_anchor: HeaderAnchor =
            serde_json::from_value(value["header_anchor"].clone()).map_err(|e| e.to_string())?;
        let saved_info: BaselineAnchor =
            serde_json::from_value(value["baseline"].clone()).map_err(|e| e.to_string())?;
        if saved_binding != *binding
            || value["binding_sha256"] != binding.fingerprint()
            || saved_anchor != *anchor
            || saved_info != anchor.baseline
        {
            return Err("header baseline binding/layout/information provenance differs".into());
        }
        anchor.validate_binding(binding)?;
        let events: Vec<WorkerEvent> =
            serde_json::from_value(value["events"].clone()).map_err(|e| e.to_string())?;
        if events.len() != 12 || events.iter().any(|e| !e.ok || e.error.is_some()) {
            return Err("header baseline events incomplete/failed".into());
        }
        let commands = std::iter::once(WorkerCommand::OpenHeaders {
            binding: Box::new(binding.clone()),
            anchor: Box::new(anchor.clone()),
        })
        .chain(
            QueryAction::HEADER_SEQUENCE
                .into_iter()
                .map(WorkerCommand::Advance),
        );
        for (command, event) in commands.zip(&events) {
            validate_scoped_event(&command, event, Some(anchor))?;
            if let Some(reply) = &event.decoded {
                anchor.baseline.check_reply(reply)?;
            }
        }
        let layout = RuntimeDescriptorReply::decode(
            events[6]
                .reply
                .as_deref()
                .ok_or("header baseline layout absent")?,
        )
        .map_err(|e| e.to_string())?;
        anchor.check_layout(&layout)?;
        if value["runtime_descriptor"]
            != serde_json::to_value(&layout).map_err(|e| e.to_string())?
        {
            return Err("saved descriptor claims differ from raw reply".into());
        }
        let mut baseline = HeaderBaseline::new(&layout);
        let mut observations = Vec::new();
        for (action, index) in [
            (QueryAction::SensitivityHeaderGet, 8),
            (QueryAction::MainHeaderGet, 10),
        ] {
            let read = anchor.read(action)?;
            let observation = read
                .observe_reply(
                    events[index]
                        .reply
                        .as_deref()
                        .ok_or("saved header raw reply missing")?,
                )
                .map_err(|e| e.to_string())?;
            baseline.record(&observation).map_err(|e| e.to_string())?;
            observations.push(observation);
        }
        if value["header_observations"]
            != serde_json::to_value(&observations).map_err(|e| e.to_string())?
            || value["header_coverage"]
                != serde_json::to_value(baseline.assessment()).map_err(|e| e.to_string())?
        {
            return Err("saved header observations/coverage differ from raw bytes".into());
        }
        let body = Self {
            header_anchor: anchor.clone(),
            sensitivity_header: observations[0].data().to_vec(),
            source_headers_session_sha256: firmware::sha256(bytes),
        };
        body.validate_binding(binding)?;
        body.check_header(
            events[8]
                .reply
                .as_deref()
                .ok_or("saved sensitivity header missing")?,
        )?;
        Ok(body)
    }
    fn validate_binding(&self, binding: &Binding) -> Result<(), String> {
        self.header_anchor.validate_binding(binding)?;
        if self.sensitivity_header.len() != 8
            || self.source_headers_session_sha256.len() != 64
            || !self
                .source_headers_session_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid body baseline header or digest".into());
        }
        self.read()?;
        Ok(())
    }
    fn validate_memory02_scope(&self) -> Result<(), String> {
        let info = &self.header_anchor.baseline;
        if info.core != Core::One
            || info.version_compare_word != 0x28
            || info.display_version_word != 0x28
            || self
                .header_anchor
                .layout()?
                .descriptor()
                .bases()
                .sensitivity
                != 0xE000
            || self.sensitivity_header.len() != 8
            || self.sensitivity_header[..4] != [0xA4; 4]
        {
            return Err(
                "02 experiment restricted to saved W95 Max/Core 1/version 0028/E000/A4 baseline"
                    .into(),
            );
        }
        Ok(())
    }
    fn read(&self) -> Result<FirstBodyRead, String> {
        FirstBodyRead::from_layout(&self.header_anchor.layout()?).map_err(|e| e.to_string())
    }
    fn check_header(&self, raw: &[u8]) -> Result<(), String> {
        let read = self.header_anchor.read(QueryAction::SensitivityHeaderGet)?;
        sensitivity_body::conservative_echo(&read.request(), raw).map_err(|e| e.to_string())?;
        let obs = read.observe_reply(raw).map_err(|e| e.to_string())?;
        if obs.data() != self.sensitivity_header {
            return Err("fresh sensitivity header changed; body read prohibited".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryAction {
    IdentitySet,
    IdentityGet,
    StatusSet,
    StatusGet,
    DescriptorSet,
    DescriptorGet,
    SensitivityHeaderSet,
    SensitivityHeaderGet,
    MainHeaderSet,
    MainHeaderGet,
    SensitivityBodySet,
    SensitivityBodyGet,
    Memory02HeaderSet,
    Memory02HeaderGet,
    BlockChunkSet { pass: u8, chunk: u8 },
    BlockChunkGet { pass: u8, chunk: u8 },
    BlockAfterSet { pass: u8 },
    BlockAfterGet { pass: u8 },
    Close,
}
impl QueryAction {
    pub const SEQUENCE: [Self; 5] = [
        Self::IdentitySet,
        Self::IdentityGet,
        Self::StatusSet,
        Self::StatusGet,
        Self::Close,
    ];
    pub const LAYOUT_SEQUENCE: [Self; 7] = [
        Self::IdentitySet,
        Self::IdentityGet,
        Self::StatusSet,
        Self::StatusGet,
        Self::DescriptorSet,
        Self::DescriptorGet,
        Self::Close,
    ];
    pub const HEADER_SEQUENCE: [Self; 11] = [
        Self::IdentitySet,
        Self::IdentityGet,
        Self::StatusSet,
        Self::StatusGet,
        Self::DescriptorSet,
        Self::DescriptorGet,
        Self::SensitivityHeaderSet,
        Self::SensitivityHeaderGet,
        Self::MainHeaderSet,
        Self::MainHeaderGet,
        Self::Close,
    ];
    pub const BODY_SEQUENCE: [Self; 11] = [
        Self::IdentitySet,
        Self::IdentityGet,
        Self::StatusSet,
        Self::StatusGet,
        Self::DescriptorSet,
        Self::DescriptorGet,
        Self::SensitivityHeaderSet,
        Self::SensitivityHeaderGet,
        Self::SensitivityBodySet,
        Self::SensitivityBodyGet,
        Self::Close,
    ];
    pub const BLOCK_SEQUENCE: [Self; 137] = Self::block_sequence();
    pub const MEMORY02_SEQUENCE: [Self; 139] = Self::memory02_sequence();
    const fn memory02_sequence() -> [Self; 139] {
        let mut out = [Self::Close; 139];
        let mut n = 0;
        while n < 8 {
            out[n] = Self::BLOCK_SEQUENCE[n];
            n += 1;
        }
        out[8] = Self::Memory02HeaderSet;
        out[9] = Self::Memory02HeaderGet;
        while n < 137 {
            out[n + 2] = Self::BLOCK_SEQUENCE[n];
            n += 1;
        }
        out
    }
    const fn block_sequence() -> [Self; 137] {
        let mut out = [Self::Close; 137];
        let first = [
            Self::IdentitySet,
            Self::IdentityGet,
            Self::StatusSet,
            Self::StatusGet,
            Self::DescriptorSet,
            Self::DescriptorGet,
            Self::SensitivityHeaderSet,
            Self::SensitivityHeaderGet,
        ];
        let mut n = 0;
        while n < 8 {
            out[n] = first[n];
            n += 1;
        }
        let mut pass = 0;
        while pass < 2 {
            let mut chunk = 0;
            while chunk < 31 {
                out[n] = Self::BlockChunkSet { pass, chunk };
                out[n + 1] = Self::BlockChunkGet { pass, chunk };
                n += 2;
                chunk += 1;
            }
            out[n] = Self::BlockAfterSet { pass };
            out[n + 1] = Self::BlockAfterGet { pass };
            n += 2;
            pass += 1;
        }
        out
    }
    fn is_block(self) -> bool {
        matches!(
            self,
            Self::Memory02HeaderSet
                | Self::Memory02HeaderGet
                | Self::BlockChunkSet { .. }
                | Self::BlockChunkGet { .. }
                | Self::BlockAfterSet { .. }
                | Self::BlockAfterGet { .. }
        )
    }
    fn is_block_set(self) -> bool {
        matches!(
            self,
            Self::Memory02HeaderSet | Self::BlockChunkSet { .. } | Self::BlockAfterSet { .. }
        )
    }
    fn header_region(self) -> Option<HeaderRegion> {
        match self {
            Self::SensitivityHeaderSet | Self::SensitivityHeaderGet => {
                Some(HeaderRegion::Sensitivity)
            }
            Self::MainHeaderSet | Self::MainHeaderGet => Some(HeaderRegion::MainProfile),
            _ => None,
        }
    }
    fn query(self) -> Option<NormalQuery> {
        match self {
            Self::IdentitySet | Self::IdentityGet => Some(NormalQuery::Identity),
            Self::StatusSet | Self::StatusGet => Some(NormalQuery::Status),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerEvent {
    pub phase: String,
    pub ok: bool,
    pub request: Option<Vec<u8>>,
    pub reply: Option<Vec<u8>>,
    pub decoded: Option<NormalReply>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_payload: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_candidate: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_candidate: Option<Vec<u8>>,
    pub error: Option<String>,
}
impl WorkerEvent {
    fn new(phase: impl Into<String>) -> Self {
        Self {
            phase: phase.into(),
            ok: true,
            request: None,
            reply: None,
            decoded: None,
            descriptor_payload: None,
            header_candidate: None,
            body_candidate: None,
            error: None,
        }
    }
    fn fail(mut self, error: impl ToString) -> Self {
        self.ok = false;
        self.error = Some(error.to_string());
        self
    }
}

/// Owns the transport, exposes only ordered typed actions; no raw send API.
pub struct QuerySession<T> {
    transport: T,
    next: usize,
    terminal: bool,
    baseline: Option<BaselineAnchor>,
    header_anchor: Option<HeaderAnchor>,
    runtime_descriptor: Option<RuntimeDescriptorReply>,
    body_anchor: Option<BodyAnchor>,
    sensitivity_header_verified: bool,
    block: Option<BlockCollector>,
}
impl<T: LocalFeatureTransport> QuerySession<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next: 0,
            terminal: false,
            baseline: None,
            header_anchor: None,
            runtime_descriptor: None,
            body_anchor: None,
            sensitivity_header_verified: false,
            block: None,
        }
    }
    pub fn for_layout(transport: T, baseline: BaselineAnchor) -> Self {
        Self {
            transport,
            next: 0,
            terminal: false,
            baseline: Some(baseline),
            header_anchor: None,
            runtime_descriptor: None,
            body_anchor: None,
            sensitivity_header_verified: false,
            block: None,
        }
    }
    pub fn for_headers(transport: T, anchor: HeaderAnchor) -> Self {
        Self {
            transport,
            next: 0,
            terminal: false,
            baseline: Some(anchor.baseline.clone()),
            header_anchor: Some(anchor),
            runtime_descriptor: None,
            body_anchor: None,
            sensitivity_header_verified: false,
            block: None,
        }
    }
    pub fn for_body(transport: T, anchor: BodyAnchor) -> Self {
        Self {
            transport,
            next: 0,
            terminal: false,
            baseline: Some(anchor.header_anchor.baseline.clone()),
            header_anchor: Some(anchor.header_anchor.clone()),
            runtime_descriptor: None,
            body_anchor: Some(anchor),
            sensitivity_header_verified: false,
            block: None,
        }
    }
    pub fn for_block(transport: T, anchor: BodyAnchor) -> Result<Self, String> {
        let block =
            BlockCollector::new(&anchor.header_anchor.layout()?, &anchor.sensitivity_header)?;
        let mut session = Self::for_body(transport, anchor);
        session.block = Some(block);
        Ok(session)
    }
    pub fn for_memory02(transport: T, anchor: BodyAnchor) -> Result<Self, String> {
        let block = make_collector(&anchor, true)?;
        let mut session = Self::for_body(transport, anchor);
        session.block = Some(block);
        Ok(session)
    }
    pub fn advance(&mut self, action: QueryAction) -> WorkerEvent {
        let event = WorkerEvent::new(format!("{action:?}"));
        if self.terminal
            || session_actions(
                self.baseline.is_some(),
                self.header_anchor.is_some(),
                self.body_anchor.is_some(),
                self.block.is_some(),
                self.block.as_ref().is_some_and(BlockCollector::is_memory02),
            )
            .get(self.next)
                != Some(&action)
        {
            self.terminal = true;
            return event.fail("out-of-order action or terminal query session");
        }
        self.next += 1;
        if action == QueryAction::Close {
            self.terminal = true;
            return event;
        }
        let mut event = event;
        if action.is_block() {
            let result = (|| -> Result<(), String> {
                let block = self
                    .block
                    .as_mut()
                    .ok_or("block actions prohibited in this mode")?;
                let request = block_request(block, action)?;
                if action.is_block_set() {
                    event.request = Some(request.to_vec());
                    self.transport
                        .set_local(&request)
                        .map_err(|e| e.to_string())?;
                } else {
                    let raw = self.transport.get_local(7, 64).map_err(|e| e.to_string())?;
                    event.reply = Some(raw.clone());
                    record_block(block, action, &raw)?;
                    if matches!(action, QueryAction::BlockChunkGet { .. }) {
                        event.body_candidate = Some(raw[32..40].to_vec());
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                self.terminal = true;
                return event.fail(e);
            }
            return event;
        }
        if matches!(
            action,
            QueryAction::SensitivityBodySet | QueryAction::SensitivityBodyGet
        ) {
            let result = (|| -> Result<(), String> {
                let anchor = self
                    .body_anchor
                    .as_ref()
                    .ok_or("body actions prohibited in this mode")?;
                if !self.sensitivity_header_verified {
                    return Err("fresh matching sensitivity header required before body".into());
                }
                anchor.header_anchor.check_layout(
                    self.runtime_descriptor
                        .as_ref()
                        .ok_or("fresh descriptor missing")?,
                )?;
                let read = anchor.read()?;
                if action == QueryAction::SensitivityBodySet {
                    let request = read.request().to_vec();
                    event.request = Some(request.clone());
                    self.transport
                        .set_local(&request)
                        .map_err(|e| e.to_string())?;
                } else {
                    let raw = self.transport.get_local(7, 64).map_err(|e| e.to_string())?;
                    event.reply = Some(raw.clone());
                    let obs = read.observe_reply(&raw).map_err(|e| e.to_string())?;
                    event.body_candidate = Some(obs.candidate);
                }
                Ok(())
            })();
            if let Err(e) = result {
                self.terminal = true;
                return event.fail(e);
            }
            return event;
        }
        if action.header_region().is_some() {
            let result = (|| -> Result<(), String> {
                let anchor = self
                    .header_anchor
                    .as_ref()
                    .ok_or("headers prohibited in this mode")?;
                anchor.check_layout(
                    self.runtime_descriptor
                        .as_ref()
                        .ok_or("fresh descriptor required before headers")?,
                )?;
                let read = anchor.read(action)?;
                if matches!(
                    action,
                    QueryAction::SensitivityHeaderSet | QueryAction::MainHeaderSet
                ) {
                    let request = read.request().to_vec();
                    event.request = Some(request.clone());
                    self.transport
                        .set_local(&request)
                        .map_err(|e| e.to_string())?;
                } else {
                    let raw = self.transport.get_local(7, 64).map_err(|e| e.to_string())?;
                    event.reply = Some(raw.clone());
                    let observation = read.observe_reply(&raw).map_err(|e| e.to_string())?;
                    if let Some(anchor) = &self.body_anchor {
                        anchor.check_header(&raw)?;
                        self.sensitivity_header_verified = true;
                    }
                    if let Some(block) = &mut self.block {
                        block.initial_header(&raw)?;
                    }
                    event.header_candidate = Some(observation.data().to_vec());
                }
                Ok(())
            })();
            if let Err(e) = result {
                self.terminal = true;
                return event.fail(e);
            }
            return event;
        }
        match action {
            QueryAction::IdentitySet | QueryAction::StatusSet | QueryAction::DescriptorSet => {
                let request = if action == QueryAction::DescriptorSet {
                    readback::descriptor_request().to_vec()
                } else {
                    OfflineQueryFrame::new(action.query().expect("normal query"), 64)
                        .expect("reviewed geometry")
                        .request()
                };
                let result = self.transport.set_local(&request);
                event.request = Some(request);
                if let Err(e) = result {
                    event = event.fail(e);
                }
            }
            QueryAction::IdentityGet | QueryAction::StatusGet | QueryAction::DescriptorGet => {
                match self.transport.get_local(7, 64) {
                    Err(e) => event = event.fail(e),
                    Ok(reply) => {
                        if action == QueryAction::DescriptorGet {
                            match RuntimeDescriptorReply::decode(&reply) {
                                Ok(layout) => {
                                    event.descriptor_payload =
                                        Some(layout.descriptor().raw_payload().to_vec());
                                    if let Some(anchor) = &self.header_anchor
                                        && let Err(e) = anchor.check_layout(&layout)
                                    {
                                        event = event.fail(e);
                                    }
                                    self.runtime_descriptor = Some(layout);
                                }
                                Err(e) => event = event.fail(e),
                            }
                        } else {
                            match OfflineQueryFrame::new(action.query().expect("normal query"), 64)
                                .expect("reviewed geometry")
                                .decode(&reply)
                            {
                                Ok(decoded) => {
                                    if let Some(baseline) = &self.baseline
                                        && let Err(e) = baseline.check_reply(&decoded)
                                    {
                                        event = event.fail(e);
                                    }
                                    event.decoded = Some(decoded);
                                }
                                Err(e) => event = event.fail(e),
                            }
                        }
                        event.reply = Some(reply);
                    }
                }
            }
            _ => unreachable!(),
        }
        if !event.ok {
            self.terminal = true;
        }
        event
    }
}

fn actions(layout: bool) -> &'static [QueryAction] {
    if layout {
        &QueryAction::LAYOUT_SEQUENCE
    } else {
        &QueryAction::SEQUENCE
    }
}
fn session_actions(
    layout: bool,
    headers: bool,
    body: bool,
    block: bool,
    memory02: bool,
) -> &'static [QueryAction] {
    if memory02 {
        &QueryAction::MEMORY02_SEQUENCE
    } else if block {
        &QueryAction::BLOCK_SEQUENCE
    } else if body {
        &QueryAction::BODY_SEQUENCE
    } else if headers {
        &QueryAction::HEADER_SEQUENCE
    } else {
        actions(layout)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum WorkerCommand {
    Open(Box<Binding>),
    OpenLayout {
        binding: Box<Binding>,
        baseline: Box<BaselineAnchor>,
    },
    OpenHeaders {
        binding: Box<Binding>,
        anchor: Box<HeaderAnchor>,
    },
    OpenBody {
        binding: Box<Binding>,
        anchor: Box<BodyAnchor>,
    },
    OpenBlock {
        binding: Box<Binding>,
        anchor: Box<BodyAnchor>,
    },
    OpenMemory02 {
        binding: Box<Binding>,
        anchor: Box<BodyAnchor>,
    },
    Advance(QueryAction),
}

fn block_request(block: &BlockCollector, action: QueryAction) -> Result<[u8; 64], String> {
    match action {
        QueryAction::Memory02HeaderSet | QueryAction::Memory02HeaderGet => {
            block.memory_header_request()
        }
        QueryAction::BlockChunkSet { pass, chunk } | QueryAction::BlockChunkGet { pass, chunk } => {
            block.chunk_request(pass, chunk)
        }
        QueryAction::BlockAfterSet { pass } | QueryAction::BlockAfterGet { pass } => {
            block.after_header_request(pass)
        }
        _ => Err("not a settings block step".into()),
    }
}
fn record_block(block: &mut BlockCollector, action: QueryAction, raw: &[u8]) -> Result<(), String> {
    match action {
        QueryAction::Memory02HeaderGet => block.record_memory_header(raw),
        QueryAction::BlockChunkGet { pass, chunk } => block.record_chunk(pass, chunk, raw),
        QueryAction::BlockAfterGet { pass } => block.record_after_header(pass, raw),
        _ => Err("not a block Get".into()),
    }
}

/// A bounded JSON line avoids unbounded pipe reads on malformed input/output.
fn read_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut bytes = Vec::new();
    reader
        .take((LINE_LIMIT + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > LINE_LIMIT || bytes.last() != Some(&b'\n') {
        return Err("overlong or unterminated worker protocol line".into());
    }
    Ok(Some(bytes))
}
fn send<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value).map_err(|e| e.to_string())?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|e| e.to_string())
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
mod native {
    use super::*;
    use crate::transport::{TransportError, TransportFailure};
    use std::{
        ffi::CString,
        os::unix::fs::{FileTypeExt, MetadataExt},
    };
    pub(super) struct QueryDevice(hidapi::HidDevice);
    impl LocalFeatureTransport for QueryDevice {
        fn set_local(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            self.0
                .send_feature_report(bytes)
                .map_err(|e| TransportError::new(TransportFailure::Rejected, e.to_string()))
        }
        fn get_local(&mut self, id: u8, length: usize) -> Result<Vec<u8>, TransportError> {
            let mut reply = vec![0; length];
            reply[0] = id;
            let n = self
                .0
                .get_feature_report(&mut reply)
                .map_err(|e| TransportError::new(TransportFailure::Rejected, e.to_string()))?;
            if n > reply.len() {
                return Err(TransportError::new(
                    TransportFailure::Rejected,
                    "backend returned oversized byte count",
                ));
            }
            reply.truncate(n);
            Ok(reply)
        }
    }
    pub(super) fn open(binding: &Binding) -> Result<QueryDevice, String> {
        binding.validate()?;
        binding.revalidate(&discovery::collect(Path::new("/sys"))?)?;
        let device = open_handle(binding)?;
        binding.revalidate(&discovery::collect(Path::new("/sys"))?)?;
        Ok(device)
    }
    pub(super) fn open_handle(binding: &Binding) -> Result<QueryDevice, String> {
        binding.validate()?;
        let path = binding.device_path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.file_type().is_char_device() {
            return Err("query node must be a character device, not a symlink/file".into());
        }
        // rdev is checked via sysfs's kernel-generated major/minor association;
        // get_device_info below performs fstat on the opened handle in hidapi.
        let sysdev = PathBuf::from(format!("/sys/dev/char/{}", binding.major_minor));
        let class = fs::canonicalize(format!("/sys/class/hidraw/{}", binding.node))
            .map_err(|e| e.to_string())?;
        if fs::canonicalize(&sysdev).map_err(|e| e.to_string())? != class
            || format!(
                "{}:{}",
                rustix::fs::major(meta.rdev()),
                rustix::fs::minor(meta.rdev())
            ) != binding.major_minor
        {
            return Err("device-node/sysfs binding mismatch".into());
        }
        hidapi::HidApi::disable_device_discovery();
        let api = hidapi::HidApi::new().map_err(|e| e.to_string())?;
        let device = api
            .open_path(&CString::new(path.as_str()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let info = device.get_device_info().map_err(|e| e.to_string())?;
        if info.path().to_bytes() != path.as_bytes()
            || info.vendor_id() != binding.vendor_id
            || info.product_id() != binding.product_id
            || info.interface_number() != i32::from(binding.usb_interface_number)
            || info.release_number() != binding.usb_release_bcd
            || info.manufacturer_string().unwrap_or_default() != binding.manufacturer
            || info.product_string().unwrap_or_default() != binding.product
            || !matches!(info.bus_type(), hidapi::BusType::Usb)
        {
            return Err("opened-handle metadata mismatch".into());
        }
        let mut raw = vec![0; 65_536];
        let n = device
            .get_report_descriptor(&mut raw)
            .map_err(|e| e.to_string())?;
        if n != binding.descriptor_bytes || firmware::sha256(&raw[..n]) != binding.descriptor_sha256
        {
            return Err("opened-handle descriptor mismatch".into());
        }
        Ok(QueryDevice(device))
    }
    pub fn worker() -> Result<(), String> {
        let mut input = BufReader::new(std::io::stdin().lock());
        let mut output = std::io::stdout().lock();
        let first = read_line(&mut input)?.ok_or("missing worker initialization")?;
        let (binding, baseline, header_anchor, body_anchor, block_mode) =
            match serde_json::from_slice(&first).map_err(|e| e.to_string())? {
                WorkerCommand::Open(binding) => (binding, None, None, None, BlockMode::None),
                WorkerCommand::OpenLayout { binding, baseline } => {
                    baseline.validate_binding(&binding)?;
                    (binding, Some(*baseline), None, None, BlockMode::None)
                }
                WorkerCommand::OpenHeaders { binding, anchor } => {
                    anchor.validate_binding(&binding)?;
                    (binding, None, Some(*anchor), None, BlockMode::None)
                }
                WorkerCommand::OpenBody { binding, anchor } => {
                    anchor.validate_binding(&binding)?;
                    (binding, None, None, Some(*anchor), BlockMode::None)
                }
                WorkerCommand::OpenBlock { binding, anchor } => {
                    anchor.validate_binding(&binding)?;
                    (binding, None, None, Some(*anchor), BlockMode::Legacy2f)
                }
                WorkerCommand::OpenMemory02 { binding, anchor } => {
                    anchor.validate_binding(&binding)?;
                    anchor.validate_memory02_scope()?;
                    (binding, None, None, Some(*anchor), BlockMode::Memory02)
                }
                _ => {
                    return Err("worker must start with a bound Open/OpenLayout/OpenHeaders".into());
                }
            };
        let ready = WorkerEvent::new("open");
        let device = match open(&binding) {
            Ok(device) => {
                send(&mut output, &ready)?;
                device
            }
            Err(e) => {
                send(&mut output, &ready.fail(e))?;
                return Ok(());
            }
        };
        let mut session = if block_mode == BlockMode::Memory02 {
            QuerySession::for_memory02(device, body_anchor.ok_or("02 anchor absent")?)?
        } else if block_mode == BlockMode::Legacy2f {
            QuerySession::for_block(device, body_anchor.ok_or("block anchor absent")?)?
        } else {
            match (baseline, header_anchor, body_anchor) {
                (_, _, Some(anchor)) => QuerySession::for_body(device, anchor),
                (_, Some(anchor), None) => QuerySession::for_headers(device, anchor),
                (Some(baseline), None, None) => QuerySession::for_layout(device, baseline),
                (None, None, None) => QuerySession::new(device),
            }
        };
        loop {
            let Some(line) = read_line(&mut input)? else {
                return Ok(());
            };
            let WorkerCommand::Advance(action) =
                serde_json::from_slice(&line).map_err(|e| e.to_string())?
            else {
                return Err("worker cannot reopen".into());
            };
            // Revalidate immediately before every potential device operation.
            if let Err(e) = binding.revalidate(&discovery::collect(Path::new("/sys"))?) {
                send(
                    &mut output,
                    &WorkerEvent::new(format!("{action:?}")).fail(e),
                )?;
                return Ok(());
            }
            let event = session.advance(action);
            send(&mut output, &event)?;
            if !event.ok || action == QueryAction::Close {
                return Ok(());
            }
        }
    }
}

pub fn worker_main() -> Result<(), String> {
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        native::worker()
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        Err("live query worker unavailable; build Linux with --features linux-query".into())
    }
}

pub const fn live_available() -> bool {
    cfg!(all(target_os = "linux", feature = "linux-query"))
}

pub(crate) fn lighting_exchange(
    binding: &Binding,
    frames: &[([u8; 64], bool)],
) -> Result<Vec<Option<[u8; 64]>>, String> {
    for (frame, _) in frames {
        if !crate::lighting::is_allowed_lighting_frame(frame) {
            return Err("lighting frame rejected by transport allowlist".into());
        }
    }
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    {
        let mut device = native::open(binding)?;
        let mut replies = Vec::with_capacity(frames.len());
        for (frame, read_reply) in frames {
            binding.revalidate(&discovery::collect(Path::new("/sys"))?)?;
            device.set_local(frame).map_err(|e| e.to_string())?;
            if *read_reply {
                let raw = device.get_local(7, 64).map_err(|e| e.to_string())?;
                let reply: [u8; 64] = raw
                    .try_into()
                    .map_err(|_| "lighting reply was not 64 bytes".to_string())?;
                replies.push(Some(reply));
            } else {
                replies.push(None);
            }
        }
        Ok(replies)
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-query")))]
    {
        let _ = binding;
        Err("live lighting transport unavailable; build Linux with --features linux-query".into())
    }
}

#[derive(Debug, Serialize)]
pub struct SessionReport {
    pub schema_version: u32,
    pub mode: &'static str,
    pub binding: Binding,
    pub binding_sha256: String,
    pub complete: bool,
    pub worker_pid: Option<u32>,
    pub worker_reaped: bool,
    pub worker_exit_success: Option<bool>,
    pub deadline_ms: u128,
    pub uncertain: bool,
    pub lock_retained: bool,
    pub events: Vec<WorkerEvent>,
    pub failure: Option<String>,
    pub post_binding_matches: bool,
    pub configuration_or_firmware_writes: usize,
    pub resets_or_boot_transitions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineAnchor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_descriptor: Option<RuntimeDescriptorReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_anchor: Option<HeaderAnchor>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub header_observations: Vec<HeaderObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_coverage: Option<BaselineAssessment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_anchor: Option<BodyAnchor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_observation: Option<BodyObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_coverage: Option<BodyCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_capture: Option<BlockCapture>,
    pub limitations: Vec<&'static str>,
}

impl SessionReport {
    fn new(binding: Binding) -> Self {
        Self {
            schema_version: 1,
            mode: "normal_information_queries",
            binding_sha256: binding.fingerprint(),
            binding: binding.clone(),
            complete: false,
            worker_pid: None,
            worker_reaped: false,
            worker_exit_success: None,
            deadline_ms: DEADLINE.as_millis(),
            uncertain: false,
            lock_retained: false,
            events: Vec::new(),
            failure: None,
            post_binding_matches: false,
            configuration_or_firmware_writes: 0,
            resets_or_boot_transitions: 0,
            baseline: None,
            runtime_descriptor: None,
            header_anchor: None,
            header_observations: Vec::new(),
            header_coverage: None,
            body_anchor: None,
            body_observation: None,
            body_coverage: None,
            block_capture: None,
            limitations: vec![
                "Only 07 1F and conditional 07 2D selectors are permitted; queries use outbound SetFeature then GetFeature.",
                "No serial: topology/descriptor binding does not establish cross-mode or cross-reconnect physical identity.",
                "No configuration/flash backup, firmware equality check or recovery proof.",
                "A process deadline/kill is not proof an in-kernel ioctl was cancelled; uncertain sessions retain their lock.",
            ],
        }
    }
}

pub(crate) fn journal(file: &mut File, kind: &str, value: &impl Serialize) -> Result<(), String> {
    let record = serde_json::json!({"unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),"kind":kind,"value":value});
    send(file, &record)?;
    file.sync_data().map_err(|e| e.to_string())
}
fn reap(child: &mut Child, limit: Duration) -> Result<Option<bool>, String> {
    let end = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(Some(status.success()));
        }
        if Instant::now() >= end {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn validate_event(command: &WorkerCommand, event: &WorkerEvent) -> Result<(), String> {
    let expected = match command {
        WorkerCommand::Open(_)
        | WorkerCommand::OpenLayout { .. }
        | WorkerCommand::OpenHeaders { .. }
        | WorkerCommand::OpenBody { .. }
        | WorkerCommand::OpenBlock { .. }
        | WorkerCommand::OpenMemory02 { .. } => "open".into(),
        WorkerCommand::Advance(a) => format!("{a:?}"),
    };
    if event.phase != expected {
        return Err("worker protocol phase mismatch".into());
    }
    if !event.ok {
        return Ok(());
    }
    if event.error.is_some() {
        return Err("successful worker event includes an error".into());
    }
    if event.body_candidate.is_some() {
        return Err("body data prohibited in ordinary event validation".into());
    }
    match command {
        WorkerCommand::Open(_)
        | WorkerCommand::OpenLayout { .. }
        | WorkerCommand::OpenHeaders { .. }
        | WorkerCommand::OpenBody { .. }
        | WorkerCommand::OpenBlock { .. }
        | WorkerCommand::OpenMemory02 { .. }
        | WorkerCommand::Advance(QueryAction::Close) => {
            if event.request.is_some()
                || event.reply.is_some()
                || event.decoded.is_some()
                || event.descriptor_payload.is_some()
                || event.header_candidate.is_some()
            {
                return Err("unexpected data in open/close event".into());
            }
        }
        WorkerCommand::Advance(action) => match action {
            QueryAction::DescriptorSet => {
                if event.request.as_deref() != Some(readback::descriptor_request().as_slice())
                    || event.reply.is_some()
                    || event.decoded.is_some()
                    || event.descriptor_payload.is_some()
                    || event.header_candidate.is_some()
                {
                    return Err("worker descriptor Set differs from exact query".into());
                }
            }
            QueryAction::DescriptorGet => {
                let raw = event
                    .reply
                    .as_ref()
                    .ok_or("descriptor Get omitted raw reply")?;
                let layout = RuntimeDescriptorReply::decode(raw).map_err(|e| e.to_string())?;
                if event.request.is_some()
                    || event.decoded.is_some()
                    || event.header_candidate.is_some()
                    || event.descriptor_payload.as_deref()
                        != Some(layout.descriptor().raw_payload())
                {
                    return Err("worker descriptor payload disagrees with raw bytes".into());
                }
            }
            QueryAction::IdentitySet | QueryAction::StatusSet => {
                let frame = OfflineQueryFrame::new(action.query().expect("normal query"), 64)
                    .expect("reviewed geometry");
                if event.request.as_ref() != Some(&frame.request())
                    || event.reply.is_some()
                    || event.decoded.is_some()
                    || event.descriptor_payload.is_some()
                    || event.header_candidate.is_some()
                {
                    return Err("worker Set evidence differs from exact query".into());
                }
            }
            QueryAction::IdentityGet | QueryAction::StatusGet => {
                let frame = OfflineQueryFrame::new(action.query().expect("normal query"), 64)
                    .expect("reviewed geometry");
                let raw = event.reply.as_ref().ok_or("worker Get omitted raw reply")?;
                let decoded = frame.decode(raw).map_err(|e| e.to_string())?;
                if event.request.is_some()
                    || event.decoded.as_ref() != Some(&decoded)
                    || event.descriptor_payload.is_some()
                    || event.header_candidate.is_some()
                {
                    return Err("worker decoded reply disagrees with raw bytes".into());
                }
            }
            QueryAction::Close => unreachable!(),
            _ => return Err("header actions require scoped validation".into()),
        },
    }
    Ok(())
}

fn validate_scoped_event(
    command: &WorkerCommand,
    event: &WorkerEvent,
    anchor: Option<&HeaderAnchor>,
) -> Result<(), String> {
    let WorkerCommand::Advance(action) = command else {
        return validate_event(command, event);
    };
    if action.header_region().is_none() {
        return validate_event(command, event);
    }
    let anchor = anchor.ok_or("header event prohibited outside scoped mode")?;
    if event.phase != format!("{action:?}") {
        return Err("worker header phase mismatch".into());
    }
    if !event.ok {
        return Ok(());
    }
    if event.error.is_some()
        || event.decoded.is_some()
        || event.descriptor_payload.is_some()
        || event.body_candidate.is_some()
    {
        return Err("unexpected fields in successful header event".into());
    }
    let read = anchor.read(*action)?;
    if matches!(
        action,
        QueryAction::SensitivityHeaderSet | QueryAction::MainHeaderSet
    ) {
        if event.request.as_deref() != Some(read.request().as_slice())
            || event.reply.is_some()
            || event.header_candidate.is_some()
        {
            return Err("header request differs from the exact saved eight-byte window".into());
        }
    } else {
        let observation = read
            .observe_reply(event.reply.as_deref().ok_or("missing raw header reply")?)
            .map_err(|e| e.to_string())?;
        if event.request.is_some() || event.header_candidate.as_deref() != Some(observation.data())
        {
            return Err("header candidate differs from raw reply".into());
        }
    }
    Ok(())
}

fn validate_body_event(
    command: &WorkerCommand,
    event: &WorkerEvent,
    header: Option<&HeaderAnchor>,
    body: Option<&BodyAnchor>,
) -> Result<(), String> {
    if let WorkerCommand::Advance(
        action @ (QueryAction::SensitivityBodySet | QueryAction::SensitivityBodyGet),
    ) = command
    {
        let anchor = body.ok_or("body action prohibited outside dedicated mode")?;
        if event.phase != format!("{action:?}") {
            return Err("worker body phase mismatch".into());
        }
        if !event.ok {
            return Ok(());
        }
        if event.error.is_some()
            || event.decoded.is_some()
            || event.descriptor_payload.is_some()
            || event.header_candidate.is_some()
        {
            return Err("unexpected fields in body event".into());
        }
        let read = anchor.read()?;
        if *action == QueryAction::SensitivityBodySet {
            if event.request.as_deref() != Some(read.request().as_slice())
                || event.reply.is_some()
                || event.body_candidate.is_some()
            {
                return Err("body request differs from exact base+8/count2 frame".into());
            }
        } else {
            let obs = read
                .observe_reply(event.reply.as_deref().ok_or("body Get missing raw reply")?)
                .map_err(|e| e.to_string())?;
            if event.request.is_some()
                || event.body_candidate.as_deref() != Some(obs.candidate.as_slice())
            {
                return Err("body candidate differs from raw reply".into());
            }
        }
        return Ok(());
    }
    validate_scoped_event(command, event, header)?;
    if event.ok
        && matches!(
            command,
            WorkerCommand::Advance(QueryAction::SensitivityHeaderGet)
        )
        && let Some(anchor) = body
    {
        anchor.check_header(
            event
                .reply
                .as_deref()
                .ok_or("sensitivity header raw reply missing")?,
        )?;
    }
    Ok(())
}

fn validate_block_event(
    command: &WorkerCommand,
    event: &WorkerEvent,
    block: &mut BlockCollector,
) -> Result<(), String> {
    let WorkerCommand::Advance(action) = command else {
        return Err("block validation requires typed action".into());
    };
    if event.phase != format!("{action:?}") {
        return Err("block worker phase mismatch".into());
    }
    if event.decoded.is_some()
        || event.descriptor_payload.is_some()
        || event.header_candidate.is_some()
    {
        return Err("unexpected decoded data in block event".into());
    }
    let request = block_request(block, *action)?;
    if action.is_block_set() {
        if event.request.as_deref() != Some(request.as_slice())
            || event.reply.is_some()
            || event.body_candidate.is_some()
        {
            return Err("block Set differs from cursor-derived fixed request".into());
        }
        if event.ok != event.error.is_none() {
            return Err("block Set status/error mismatch".into());
        }
    } else {
        if event.request.is_some() {
            return Err("request in block Get event".into());
        }
        let Some(raw) = &event.reply else {
            if !event.ok && event.error.is_some() && event.body_candidate.is_none() {
                return Ok(());
            }
            return Err("missing block raw reply".into());
        };
        let result = record_block(block, *action, raw);
        match result {
            Ok(()) => {
                if !event.ok || event.error.is_some() {
                    return Err("worker rejected independently valid block data".into());
                }
                let candidate =
                    matches!(action, QueryAction::BlockChunkGet { .. }).then(|| &raw[32..40]);
                if event.body_candidate.as_deref() != candidate {
                    return Err("block candidate differs from raw frame".into());
                }
            }
            Err(expected) => {
                if event.ok
                    || event.error.as_deref() != Some(expected.as_str())
                    || event.body_candidate.is_some()
                {
                    return Err(
                        "worker block verdict differs from independently decoded result".into(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn supervise(
    child: &mut Child,
    log: &mut File,
    report: &mut SessionReport,
    deadline: Duration,
) -> Result<(), String> {
    report.worker_pid = Some(child.id());
    let mut input = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let event = read_line(&mut reader)
                .and_then(|line| line.ok_or("worker stdout ended".to_owned()))
                .and_then(|bytes| {
                    serde_json::from_slice::<WorkerEvent>(&bytes).map_err(|e| e.to_string())
                });
            let stop = event.is_err();
            if tx.send(event).is_err() || stop {
                break;
            }
        }
    });
    let run = (|| -> Result<(), String> {
        let memory02 = report.mode == MEMORY02_MODE;
        let block_mode = report.mode == BLOCK_MODE || memory02;
        let mut block = if block_mode {
            let anchor = report.body_anchor.as_ref().ok_or("block anchor missing")?;
            Some(make_collector(anchor, memory02)?)
        } else {
            None
        };
        let open = if memory02 {
            WorkerCommand::OpenMemory02 {
                binding: Box::new(report.binding.clone()),
                anchor: Box::new(report.body_anchor.clone().ok_or("02 anchor missing")?),
            }
        } else if block_mode {
            WorkerCommand::OpenBlock {
                binding: Box::new(report.binding.clone()),
                anchor: Box::new(report.body_anchor.clone().ok_or("block anchor missing")?),
            }
        } else {
            match (&report.baseline, &report.header_anchor, &report.body_anchor) {
                (_, _, Some(anchor)) => WorkerCommand::OpenBody {
                    binding: Box::new(report.binding.clone()),
                    anchor: Box::new(anchor.clone()),
                },
                (_, Some(anchor), None) => WorkerCommand::OpenHeaders {
                    binding: Box::new(report.binding.clone()),
                    anchor: Box::new(anchor.clone()),
                },
                (Some(baseline), None, None) => WorkerCommand::OpenLayout {
                    binding: Box::new(report.binding.clone()),
                    baseline: Box::new(baseline.clone()),
                },
                (None, None, None) => WorkerCommand::Open(Box::new(report.binding.clone())),
            }
        };
        let commands = std::iter::once(open).chain(
            session_actions(
                report.baseline.is_some(),
                report.header_anchor.is_some(),
                report.body_anchor.is_some(),
                block_mode,
                memory02,
            )
            .iter()
            .copied()
            .map(WorkerCommand::Advance),
        );
        for command in commands {
            if let WorkerCommand::Advance(action) = command
                && action.is_block()
            {
                block_request(
                    block.as_ref().ok_or("block action outside block mode")?,
                    action,
                )?;
            }
            if matches!(
                command,
                WorkerCommand::Advance(QueryAction::SensitivityBodySet)
            ) {
                let anchor = report.body_anchor.as_ref().ok_or("body anchor absent")?;
                anchor.header_anchor.check_layout(
                    report
                        .runtime_descriptor
                        .as_ref()
                        .ok_or("fresh layout absent")?,
                )?;
                let raw = report
                    .header_observations
                    .first()
                    .ok_or("fresh sensitivity header absent")?
                    .raw_reply();
                anchor.check_header(raw)?;
            }
            // Persist intent before granting exactly one step to the worker.
            journal(log, "command_intent", &command)?;
            send(&mut input, &command)?;
            let event = rx
                .recv_timeout(deadline)
                .map_err(|e| format!("worker deadline/channel uncertainty: {e}"))??;
            journal(log, "worker_event", &event)?;
            if let WorkerCommand::Advance(action) = command
                && action.is_block()
            {
                let collector = block.as_mut().ok_or("block action outside block mode")?;
                validate_block_event(&command, &event, collector)?;
                report.block_capture = Some(collector.snapshot());
            } else {
                validate_body_event(
                    &command,
                    &event,
                    report.header_anchor.as_ref(),
                    report.body_anchor.as_ref(),
                )?;
            }
            if event.ok {
                if let (Some(baseline), Some(decoded)) = (&report.baseline, &event.decoded) {
                    baseline.check_reply(decoded)?;
                }
                if matches!(command, WorkerCommand::Advance(QueryAction::DescriptorGet)) {
                    let layout = RuntimeDescriptorReply::decode(
                        event.reply.as_deref().ok_or("missing descriptor bytes")?,
                    )
                    .map_err(|e| e.to_string())?;
                    if let Some(anchor) = &report.header_anchor {
                        anchor.check_layout(&layout)?;
                    }
                    report.runtime_descriptor = Some(layout);
                }
                if let WorkerCommand::Advance(
                    action @ (QueryAction::SensitivityHeaderGet | QueryAction::MainHeaderGet),
                ) = command
                {
                    let anchor = report
                        .header_anchor
                        .as_ref()
                        .ok_or("header anchor missing")?;
                    anchor.check_layout(
                        report
                            .runtime_descriptor
                            .as_ref()
                            .ok_or("fresh descriptor missing")?,
                    )?;
                    let observation = anchor
                        .read(action)?
                        .observe_reply(event.reply.as_deref().ok_or("header bytes missing")?)
                        .map_err(|e| e.to_string())?;
                    report.header_observations.push(observation);
                    let mut baseline = HeaderBaseline::new(
                        report
                            .runtime_descriptor
                            .as_ref()
                            .ok_or("fresh descriptor missing")?,
                    );
                    for observation in &report.header_observations {
                        baseline.record(observation).map_err(|e| e.to_string())?;
                    }
                    report.header_coverage = Some(baseline.assessment());
                    if let Some(collector) = &mut block {
                        collector.initial_header(
                            event
                                .reply
                                .as_deref()
                                .ok_or("initial block header absent")?,
                        )?;
                        report.block_capture = Some(collector.snapshot());
                    }
                    if report.body_anchor.is_some() && !block_mode {
                        report.body_coverage = Some(BodyCoverage::new(true, false));
                    }
                }
                if matches!(
                    command,
                    WorkerCommand::Advance(QueryAction::SensitivityBodyGet)
                ) {
                    let obs = report
                        .body_anchor
                        .as_ref()
                        .ok_or("body anchor absent")?
                        .read()?
                        .observe_reply(event.reply.as_deref().ok_or("body bytes absent")?)
                        .map_err(|e| e.to_string())?;
                    report.body_observation = Some(obs);
                    report.body_coverage = Some(BodyCoverage::new(true, true));
                }
            }
            let expected = event.phase.clone();
            let ok = event.ok;
            let error = event.error.clone();
            report.events.push(event);
            if !ok {
                return Err(format!(
                    "worker stopped at {expected}: {}",
                    error.unwrap_or_else(|| "unspecified failure".into())
                ));
            }
        }
        Ok(())
    })();
    drop(input);
    // Failures explicitly returned by the worker are definite stops. A
    // deadline, pipe, protocol or evidence failure is uncertain instead.
    let definite = report.events.last().is_some_and(|e| !e.ok);
    if run.is_err() && !definite {
        report.uncertain = true;
        let _ = child.kill();
    }
    let status = reap(child, Duration::from_millis(500))?;
    if status.is_none() {
        report.uncertain = true;
        let _ = child.kill();
    }
    report.worker_reaped = status.is_some();
    report.worker_exit_success = status;
    if report.uncertain {
        return Err(run
            .err()
            .unwrap_or_else(|| "worker did not exit within shutdown deadline".into()));
    }
    if status != Some(true) {
        return Err("query worker exited unsuccessfully".into());
    }
    run
}

// A persistent lock survives a coordinator crash or uncertain operation. Never
// auto-remove an old lock; it requires inspection at a later checkpoint.
pub(crate) fn lock_path() -> PathBuf {
    PathBuf::from("/tmp/ratmax-query-session.lock")
}

pub(crate) fn acquire_lock(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| format!("exclusive query lock unavailable (never automatically cleared): {e}"))
}

pub fn query_info(snapshot: &Path, output: &Path) -> Result<SessionReport, String> {
    run_session(snapshot, None, None, None, BlockMode::None, output)
}
pub fn query_layout(
    snapshot: &Path,
    baseline: &Path,
    output: &Path,
) -> Result<SessionReport, String> {
    run_session(
        snapshot,
        Some(baseline),
        None,
        None,
        BlockMode::None,
        output,
    )
}
pub fn query_headers(
    snapshot: &Path,
    baseline: &Path,
    layout_session: &Path,
    output: &Path,
) -> Result<SessionReport, String> {
    run_session(
        snapshot,
        Some(baseline),
        Some(layout_session),
        None,
        BlockMode::None,
        output,
    )
}
pub fn query_sensitivity_body(
    snapshot: &Path,
    baseline: &Path,
    layout_session: &Path,
    headers_session: &Path,
    output: &Path,
) -> Result<SessionReport, String> {
    run_session(
        snapshot,
        Some(baseline),
        Some(layout_session),
        Some(headers_session),
        BlockMode::None,
        output,
    )
}
pub fn query_sensitivity_block(
    snapshot: &Path,
    baseline: &Path,
    layout_session: &Path,
    headers_session: &Path,
    output: &Path,
) -> Result<SessionReport, String> {
    run_session(
        snapshot,
        Some(baseline),
        Some(layout_session),
        Some(headers_session),
        BlockMode::Legacy2f,
        output,
    )
}
pub fn query_sensitivity_memory02(
    snapshot: &Path,
    baseline: &Path,
    layout_session: &Path,
    headers_session: &Path,
    output: &Path,
) -> Result<SessionReport, String> {
    run_session(
        snapshot,
        Some(baseline),
        Some(layout_session),
        Some(headers_session),
        BlockMode::Memory02,
        output,
    )
}
fn run_session(
    snapshot: &Path,
    baseline_path: Option<&Path>,
    layout_path: Option<&Path>,
    headers_path: Option<&Path>,
    block_mode: BlockMode,
    output: &Path,
) -> Result<SessionReport, String> {
    if !live_available() {
        return Err(
            "live queries require Linux build --features linux-query; no device accessed".into(),
        );
    }
    let binding = load_binding(snapshot)?;
    let baseline = baseline_path
        .map(|p| load_anchor(p, &binding))
        .transpose()?;
    let header_anchor = layout_path
        .map(|path| {
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|e| e.to_string())?
                .take(SNAPSHOT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            HeaderAnchor::from_session_bytes(
                &bytes,
                &binding,
                baseline
                    .as_ref()
                    .ok_or("headers need information baseline")?,
            )
        })
        .transpose()?;
    let body_anchor = headers_path
        .map(|path| {
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|e| e.to_string())?
                .take(SNAPSHOT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            BodyAnchor::from_session_bytes(
                &bytes,
                &binding,
                header_anchor.as_ref().ok_or("body needs saved layout")?,
            )
        })
        .transpose()?;
    if block_mode == BlockMode::Memory02 {
        body_anchor
            .as_ref()
            .ok_or("02 requires saved headers")?
            .validate_memory02_scope()?;
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize().map_err(|e| e.to_string())?;
    if ["/sys", "/dev", "/proc"]
        .iter()
        .any(|p| parent.starts_with(p))
    {
        return Err("evidence output must be a host directory outside /sys, /dev and /proc".into());
    }
    let output = parent.join(output.file_name().ok_or("output directory name required")?);
    fs::create_dir(&output).map_err(|e| format!("output directory must be new: {e}"))?;
    let mut log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output.join("journal.jsonl"))
        .map_err(|e| e.to_string())?;
    let mut report = SessionReport::new(binding.clone());
    if let Some(baseline) = baseline {
        baseline.validate_binding(&binding)?;
        report.mode = "normal_runtime_descriptor_query";
        report.baseline = Some(baseline);
        report.limitations[0] = "Only fresh 07 1F / 07 2D and one conditional 07 05 pair; no addressed reads or writes.";
        report.limitations.push("Runtime addresses are raw metadata, not capacity/range/backup authorization; pause before any header read.");
    }
    if let Some(anchor) = header_anchor {
        anchor.validate_binding(&binding)?;
        report.mode = "normal_header_observations";
        report.limitations[0] = "Only fresh 1F/2D/05 followed by two runtime-derived eight-byte 2F00 header pairs; no scans or writes.";
        report
            .limitations
            .retain(|text| !text.contains("pause before any header read"));
        report.limitations.push("Header bytes are candidate observations: address/count/mode echoes unestablished; no complete backup or restoration.");
        report.header_coverage = Some(HeaderBaseline::new(&anchor.layout()?).assessment());
        report.header_anchor = Some(anchor);
    }
    if let Some(anchor) = body_anchor {
        anchor.validate_binding(&binding)?;
        report.mode = "normal_first_sensitivity_body_observation";
        report.limitations[0] = "Only fresh 1F/2D/05, matching sensitivity header and one eight-byte sensitivity+8 pair; no main/additional/NOR reads, scans or writes.";
        report.limitations.push("Conservative read echoes are enforced as stop rules; receiver correlation/authentication and full checksum/backup/restoration remain unestablished.");
        report.body_coverage = Some(BodyCoverage::new(false, false));
        report.body_anchor = Some(anchor);
    }
    if block_mode != BlockMode::None {
        let anchor = report
            .body_anchor
            .as_ref()
            .ok_or("block capture requires validated saved headers")?;
        report.mode = if block_mode == BlockMode::Memory02 {
            MEMORY02_MODE
        } else {
            BLOCK_MODE
        };
        report.body_coverage = None;
        report.block_capture =
            Some(make_collector(anchor, block_mode == BlockMode::Memory02)?.snapshot());
        report.limitations[0] = "Bounded 256-byte sensitivity capture only: two possible passes, second only after valid first checksum; no other region or mutation.";
        report.limitations.push("Checksum mismatch/header change stops before further reads. Matching weak checksums/two passes are candidate integrity evidence, not restoration or receiver authentication proof.");
    }
    if block_mode == BlockMode::Memory02 {
        report.limitations[0] = "Fresh 1F/2D/05/2F header, then one 02 E000/count2 header gate; only a match permits conditional 256-byte/two-pass capture. No access-key change, unlock, fallback, state change or writes.";
        report.limitations.push("Installed 0028 differs from decoded packaged 0034; 02 support is unmeasured. Header echo/failure stops after five pairs; maximum 69 pairs, all 64-byte frames with count2.");
    }
    let result = (|| -> Result<(), String> {
        let before = discovery::collect(Path::new("/sys"))?;
        before.save(&output.join("before"))?;
        binding.revalidate(&before)?;
        acquire_lock(&lock_path())?;
        report.lock_retained = true;
        fs::write(lock_path().join("owner.json"),serde_json::to_vec_pretty(&serde_json::json!({"coordinator_pid":std::process::id(),"binding_sha256":binding.fingerprint()})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        journal(&mut log, "binding", &binding)?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("worker.stderr.txt"))
            .map_err(|e| e.to_string())?;
        let child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("__query-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => return Err(format!("worker spawn failed: {e}")),
        };
        let run = supervise(&mut child, &mut log, &mut report, DEADLINE);
        if report.uncertain || report.worker_exit_success != Some(true) {
            return run;
        }
        let after = discovery::collect(Path::new("/sys"))?;
        after.save(&output.join("after"))?;
        binding.revalidate(&after)?;
        report.post_binding_matches = true;
        // Only a confirmed stopped process permits releasing the local lock.
        fs::remove_file(lock_path().join("owner.json")).map_err(|e| e.to_string())?;
        fs::remove_dir(lock_path()).map_err(|e| e.to_string())?;
        report.lock_retained = false;
        run?;
        report.complete = true;
        Ok(())
    })();
    if let Err(e) = result {
        report.failure = Some(e);
    }
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    fs::write(output.join("session.json"), bytes).map_err(|e| e.to_string())?;
    Ok(report)
}

/// Local-file-only bridge: reuse all saved raw provenance checks for the access plan.
pub fn load_access_baseline(
    snapshot: &Path,
    information: &Path,
    layout: &Path,
    headers: &Path,
) -> Result<crate::access_job::AccessBaseline, String> {
    fn bytes(path: &Path) -> Result<Vec<u8>, String> {
        let mut raw = Vec::new();
        File::open(path)
            .map_err(|e| e.to_string())?
            .take(SNAPSHOT_LIMIT + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() > SNAPSHOT_LIMIT as usize {
            return Err("access baseline exceeds 1 MiB".into());
        }
        Ok(raw)
    }
    for path in [snapshot, information, layout, headers] {
        let canonical = path.canonicalize().map_err(|e| e.to_string())?;
        if !fs::symlink_metadata(path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_file()
            || ["/dev", "/sys", "/proc"]
                .iter()
                .any(|p| canonical.starts_with(p))
        {
            return Err(
                "access inputs must be regular host files outside device/system pseudo-filesystems"
                    .into(),
            );
        }
    }
    let snapshot_raw = bytes(snapshot)?;
    let binding = load_binding(snapshot)?;
    let info_raw = bytes(information)?;
    let layout_raw = bytes(layout)?;
    let headers_raw = bytes(headers)?;
    let info = BaselineAnchor::from_session_bytes(&info_raw, &binding)?;
    let header = HeaderAnchor::from_session_bytes(&layout_raw, &binding, &info)?;
    let anchor = BodyAnchor::from_session_bytes(&headers_raw, &binding, &header)?;
    anchor.validate_memory02_scope()?;
    let value: serde_json::Value = serde_json::from_slice(&info_raw).map_err(|e| e.to_string())?;
    let events: Vec<WorkerEvent> =
        serde_json::from_value(value["events"].clone()).map_err(|e| e.to_string())?;
    let h: serde_json::Value = serde_json::from_slice(&headers_raw).map_err(|e| e.to_string())?;
    let he: Vec<WorkerEvent> =
        serde_json::from_value(h["events"].clone()).map_err(|e| e.to_string())?;
    crate::access_job::AccessBaseline::new(
        binding,
        [
            events[2].reply.clone().ok_or("missing identity")?,
            events[4].reply.clone().ok_or("missing status")?,
            header.layout_reply,
            he[8].reply.clone().ok_or("missing header")?,
        ],
        [snapshot_raw, info_raw, layout_raw, headers_raw]
            .iter()
            .map(|b| firmware::sha256(b))
            .collect(),
    )
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
pub(crate) fn open_access_transport(
    binding: &Binding,
) -> Result<impl LocalFeatureTransport + use<>, String> {
    native::open(binding)
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
pub(crate) fn open_transition_transport(
    binding: &Binding,
) -> Result<impl LocalFeatureTransport + use<>, String> {
    binding.revalidate_control(&discovery::collect(Path::new("/sys"))?)?;
    let device = native::open_handle(binding)?;
    binding.revalidate_control(&discovery::collect(Path::new("/sys"))?)?;
    Ok(device)
}
