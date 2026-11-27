//! Bound Linux `hidraw` control transport, exclusive session lock, and JSONL journaling.
#[cfg(all(target_os = "linux", feature = "linux-query"))]
use crate::discovery;
use crate::{
    discovery::{DiscoveryReport, InterfaceSnapshot},
    firmware,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(all(target_os = "linux", feature = "linux-query"))]
use crate::transport::LocalFeatureTransport;

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
            return Err("device binding requires a complete real /sys snapshot".into());
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
            return Err("not a valid normal control candidate".into());
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
            return Err("invalid HID node or VID".into());
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
        if self.feature_07_total_bytes != 64 {
            return Err("expected 64-byte normal Feature Report 07 geometry".into());
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        firmware::sha256(&serde_json::to_vec(self).expect("binding serializes"))
    }

    pub fn revalidate(&self, report: &DiscoveryReport) -> Result<(), String> {
        if Self::from_report(report)? != *self {
            return Err("candidate binding changed; refusing device access".into());
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
                .filter_map(|(key, value)| {
                    (actual.get(key) != Some(value)).then_some(key.as_str())
                })
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

    pub fn device_path(&self) -> String {
        format!("/dev/{}", self.node)
    }
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
            return Err("HID node must be a character device, not a symlink/file".into());
        }
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
}

pub const fn live_available() -> bool {
    cfg!(all(target_os = "linux", feature = "linux-query"))
}

#[cfg(all(target_os = "linux", feature = "linux-query"))]
pub(crate) fn open_init_device(
    binding: &Binding,
) -> Result<Box<dyn LocalFeatureTransport>, String> {
    match native::open(binding) {
        Ok(device) => Ok(Box::new(device)),
        Err(error) => {
            if error.to_ascii_lowercase().contains("permission denied")
                || error.to_ascii_lowercase().contains("eacces")
                || error.contains("Failed to open a device with path")
            {
                Err(format!(
                    "cannot open {} ({error}) — run with `sudo -E` or install the udev rules from `ratmax --help`",
                    binding.device_path()
                ))
            } else {
                Err(error)
            }
        }
    }
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

/// Persistent exclusive device lock path. Survives an uncertain failure until cleared.
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
        .map_err(|e| format!("exclusive device lock unavailable: {e}"))
}

pub(crate) fn journal(file: &mut File, kind: &str, value: &impl Serialize) -> Result<(), String> {
    let record = serde_json::json!({
        "unix_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        "kind": kind,
        "value": value,
    });
    serde_json::to_writer(&mut *file, &record).map_err(|e| e.to_string())?;
    file.write_all(b"\n")
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_data())
        .map_err(|e| e.to_string())
}
