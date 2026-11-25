//! Exact cached USB identity for the feature-only W95 Max loader.
use crate::{boot_bank, firmware::sha256, query_session};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
#[cfg(any(test, all(target_os = "linux", feature = "linux-query")))]
mod control;
#[cfg(all(target_os = "linux", feature = "linux-query"))]
mod native;
#[cfg(all(target_os = "linux", feature = "linux-query"))]
pub(super) use native::open;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Transport {
    UsbControl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    transport: Transport,
    #[serde(default, skip_serializing_if = "boot_bank::Revision::is_original")]
    pub boot_revision: boot_bank::Revision,
    pub usb_parent: String,
    pub usb_interface_path: String,
    pub bus_number: u8,
    pub device_address: u8,
    pub port_numbers: Vec<u8>,
    pub major_minor: String,
    pub descriptor_sha256: String,
    pub report_descriptor_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ownership {
    Available,
    Claimed,
    Released,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Driver {
    Hid,
    Usbfs,
    None,
}

fn descriptors(revision: boot_bank::Revision) -> Vec<u8> {
    revision.usb_descriptors()
}
pub(super) fn report_descriptor() -> &'static [u8] {
    &boot_bank::BOOT_HID_REPORT_DESCRIPTOR
}
fn bytes(path: &Path, parent: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let real = path.canonicalize().map_err(|e| e.to_string())?;
    if !real.starts_with(parent) || !fs::metadata(&real).map_err(|e| e.to_string())?.is_file() {
        return Err("USB attribute escapes its cached device".into());
    }
    let mut data = Vec::new();
    fs::File::open(real)
        .map_err(|e| e.to_string())?
        .take((maximum + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > maximum {
        return Err("oversized cached USB attribute".into());
    }
    Ok(data)
}
fn text(path: &Path, parent: &Path) -> Result<String, String> {
    String::from_utf8(bytes(path, parent, 128)?)
        .map(|s| s.trim().to_string())
        .map_err(|e| e.to_string())
}
fn mapped(parent: &str, root: &Path) -> Result<PathBuf, String> {
    let path = Path::new(parent);
    if !path.starts_with("/sys/devices")
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("invalid cached USB parent".into());
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let result = root.join(path.strip_prefix("/sys").map_err(|e| e.to_string())?);
    if result.canonicalize().map_err(|e| e.to_string())? != result {
        return Err("USB parent changed or is a symlink".into());
    }
    Ok(result)
}
fn driver(interface: &Path, root: &Path) -> Result<Driver, String> {
    let link = interface.join("driver");
    match fs::symlink_metadata(&link) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Driver::None),
        Err(e) => Err(e.to_string()),
        Ok(_) => {
            let actual = link.canonicalize().map_err(|e| e.to_string())?;
            for (name, driver) in [("usbhid", Driver::Hid), ("usbfs", Driver::Usbfs)] {
                if actual == root.join("bus/usb/drivers").join(name) {
                    return Ok(driver);
                }
            }
            Err("unexpected driver owns the boot interface".into())
        }
    }
}
fn ownership(driver: Driver, expected: Ownership) -> Result<(), String> {
    if matches!(
        (driver, expected),
        (Driver::Usbfs, Ownership::Claimed)
            | (
                Driver::Hid | Driver::None,
                Ownership::Available | Ownership::Released
            )
    ) {
        Ok(())
    } else {
        Err("boot USB interface ownership differs".into())
    }
}
fn topology(parent: &str, bus: u8) -> Result<Vec<u8>, String> {
    let name = Path::new(parent)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("missing USB port")?;
    let (number, ports) = name.split_once('-').ok_or("invalid USB port name")?;
    if number.parse::<u8>().map_err(|e| e.to_string())? != bus {
        return Err("USB port bus differs".into());
    }
    let ports: Vec<u8> = ports
        .split('.')
        .map(|p| p.parse::<u8>().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    if ports.is_empty() || ports.len() > 7 || ports.contains(&0) {
        return Err("invalid USB port chain".into());
    }
    Ok(ports)
}
impl Binding {
    /// Offline protocol model only; native bindings come from cached USB data.
    pub(super) fn modeled(hid: &query_session::Binding) -> Result<Self, String> {
        let bus = u8::try_from(hid.usb_bus_number).map_err(|e| e.to_string())?;
        let address = u8::try_from(hid.usb_device_number).map_err(|e| e.to_string())?;
        if bus == 0 || !(1..=127).contains(&address) {
            return Err("invalid modeled USB address".into());
        }
        let revision = match hid.usb_release_bcd {
            2 => boot_bank::Revision::Original2,
            3 => boot_bank::Revision::Prepared3,
            _ => return Err("unsupported modeled boot USB revision".into()),
        };
        Ok(Self {
            transport: Transport::UsbControl,
            boot_revision: revision,
            usb_parent: hid.usb_parent.clone(),
            usb_interface_path: hid.usb_interface_path.clone(),
            bus_number: bus,
            device_address: address,
            port_numbers: topology(&hid.usb_parent, bus)?,
            major_minor: format!(
                "189:{}",
                (u32::from(bus) - 1) * 128 + u32::from(address) - 1
            ),
            descriptor_sha256: sha256(&descriptors(revision)),
            report_descriptor_sha256: hid.descriptor_sha256.clone(),
        })
    }
    fn capture(parent_name: &str, sysfs: &Path, expected: Ownership) -> Result<Self, String> {
        let parent = mapped(parent_name, sysfs)?;
        let attr = |name: &str| text(&parent.join(name), &parent);
        let revision = match attr("bcdDevice")?.as_str() {
            "0002" => boot_bank::Revision::Original2,
            "0003" => boot_bank::Revision::Prepared3,
            _ => return Err("unsupported cached boot USB revision".into()),
        };
        if attr("idVendor")? != "09da"
            || attr("idProduct")? != "d023"
            || attr("bConfigurationValue")? != "1"
        {
            return Err("USB device is not the exact configured original bootloader".into());
        }
        let bus = attr("busnum")?.parse::<u8>().map_err(|e| e.to_string())?;
        let address = attr("devnum")?.parse::<u8>().map_err(|e| e.to_string())?;
        if bus == 0 || !(1..=127).contains(&address) {
            return Err("invalid assigned boot USB address".into());
        }
        let expected_dev = format!(
            "189:{}",
            (u32::from(bus) - 1) * 128 + u32::from(address) - 1
        );
        let dev = attr("dev")?;
        if dev != expected_dev {
            return Err("boot USB character-device identity differs".into());
        }
        let usb = bytes(&parent.join("descriptors"), &parent, 512)?;
        if usb != descriptors(revision) {
            return Err("boot USB device/configuration descriptors differ".into());
        }
        let name = parent
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("missing USB name")?;
        let interface = parent.join(format!("{name}:1.0"));
        for (field, want) in [
            ("bInterfaceNumber", "00"),
            ("bInterfaceClass", "03"),
            ("bInterfaceSubClass", "00"),
            ("bInterfaceProtocol", "00"),
            ("bAlternateSetting", "0"),
            ("bNumEndpoints", "01"),
        ] {
            if text(&interface.join(field), &parent)? != want {
                return Err(format!("boot USB interface {field} differs"));
            }
        }
        let root = sysfs.canonicalize().map_err(|e| e.to_string())?;
        ownership(driver(&interface, &root)?, expected)?;
        Ok(Self {
            transport: Transport::UsbControl,
            boot_revision: revision,
            usb_parent: parent_name.into(),
            usb_interface_path: format!("{parent_name}/{name}:1.0"),
            bus_number: bus,
            device_address: address,
            port_numbers: topology(parent_name, bus)?,
            major_minor: dev,
            descriptor_sha256: sha256(&usb),
            report_descriptor_sha256: sha256(report_descriptor()),
        })
    }
    pub(super) fn validate(&self, original: &query_session::Binding) -> Result<(), String> {
        original.validate()?;
        if self.usb_parent != original.usb_parent
            || u32::from(self.bus_number) != original.usb_bus_number
            || self.device_address == 0
            || self.device_address > 127
            || self.bus_number == 0
            || self.port_numbers != topology(&self.usb_parent, self.bus_number)?
            || self.major_minor
                != format!(
                    "189:{}",
                    (u32::from(self.bus_number) - 1) * 128 + u32::from(self.device_address) - 1
                )
            || self.descriptor_sha256 != sha256(&descriptors(self.boot_revision))
            || self.report_descriptor_sha256 != sha256(report_descriptor())
            || self.usb_interface_path
                != format!(
                    "{}/{}:1.0",
                    self.usb_parent,
                    Path::new(&self.usb_parent)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or("invalid USB parent")?
                )
        {
            return Err(
                "boot USB binding differs from the original port or supported loader".into(),
            );
        }
        Ok(())
    }
    pub(super) fn discover(
        original: &query_session::Binding,
        root: &Path,
    ) -> Result<Option<Self>, String> {
        original.validate()?;
        let parent = match mapped(&original.usb_parent, root) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        if text(&parent.join("idProduct"), &parent)? != "d023" {
            return Ok(None);
        }
        let result = Self::capture(&original.usb_parent, root, Ownership::Available)?;
        result.validate(original)?;
        Ok(Some(result))
    }
    pub(super) fn revalidate(&self, root: &Path, expected: Ownership) -> Result<(), String> {
        if Self::capture(&self.usb_parent, root, expected)? != *self {
            return Err("boot USB cached binding changed".into());
        }
        Ok(())
    }
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    pub(super) fn node(&self) -> PathBuf {
        Path::new("/dev/bus/usb")
            .join(format!("{:03}", self.bus_number))
            .join(format!("{:03}", self.device_address))
    }
    #[cfg(all(target_os = "linux", feature = "linux-query"))]
    fn check_node(&self) -> Result<(), String> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = fs::symlink_metadata(self.node()).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_char_device()
            || rustix::fs::major(metadata.rdev()) != 189
            || rustix::fs::minor(metadata.rdev())
                != (u32::from(self.bus_number) - 1) * 128 + u32::from(self.device_address) - 1
        {
            return Err("boot USB node type or device number differs".into());
        }
        Ok(())
    }
}
