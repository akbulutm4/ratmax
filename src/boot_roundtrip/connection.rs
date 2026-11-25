use crate::{boot_bank, discovery::DiscoveryReport, firmware::sha256, query_session::Binding};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Normal,
    Boot,
    Target(crate::model::Core),
}

/// HID records retain their historical JSON shape; USB records carry an
/// explicit transport discriminator and contain no invented hidraw node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum DeviceBinding {
    Hid(Binding),
    Usb(super::boot_usb::Binding),
}
impl From<Binding> for DeviceBinding {
    fn from(binding: Binding) -> Self {
        Self::Hid(binding)
    }
}
impl DeviceBinding {
    pub(super) fn product_id(&self) -> u16 {
        match self {
            Self::Hid(b) => b.product_id,
            Self::Usb(_) => 0xd023,
        }
    }
    pub(super) fn released(&self, report: &DiscoveryReport) -> Result<(), String> {
        match self {
            Self::Hid(b) => b.revalidate_control(report),
            Self::Usb(b) => b.revalidate(
                std::path::Path::new("/sys"),
                super::boot_usb::Ownership::Released,
            ),
        }
    }
}
pub(super) fn validate_connection(
    mode: Mode,
    current: &DeviceBinding,
    original: &Binding,
) -> Result<(), String> {
    match current {
        DeviceBinding::Hid(binding) => validate(mode, binding, original),
        DeviceBinding::Usb(binding) if mode == Mode::Boot => binding.validate(original),
        _ => Err("USB control binding is restricted to boot mode".into()),
    }
}

pub(crate) fn target_descriptor(core: crate::model::Core) -> &'static str {
    match core.firmware_index().get() {
        0 => "8af1935dc5c5ece3ba36ffa495244f8c1dcce5695bd3c61c8cd7e867a76be3c4",
        1 => "24a77e45469aef49774fd72181ba68daebbcc52e544c722881e5689a2b6cc3a2",
        2 => "2d4e61b554de9095489ab600ffc81e35f2cc3b62653039afa2c1cd8c2ab3589e",
        _ => "a4fc70e1648716690a8989efb837f907447bc0ced5e68e906a53615fb7890d24",
    }
}

pub(super) fn validate(mode: Mode, current: &Binding, original: &Binding) -> Result<(), String> {
    current.validate()?;
    if current.usb_parent != original.usb_parent
        || current.usb_bus_number != original.usb_bus_number
    {
        return Err("round-trip device appeared at a different USB port".into());
    }
    match mode {
        Mode::Target(core) => {
            if current.vendor_id != 0x09da
                || current.product_id != 0x712f
                || current.usb_release_bcd != 0x34
                || current.usb_interface_number != 2
                || current.descriptor_bytes != 180
                || current.descriptor_sha256 != target_descriptor(core)
            {
                return Err("returned metadata differs from the selected 0034 image".into());
            }
            // Strings/serial may change with firmware. They are captured in the
            // new exact binding and revalidated on every subsequent operation.
        }
        Mode::Normal => {
            if current.vendor_id != original.vendor_id
                || current.product_id != original.product_id
                || current.usb_interface_number != original.usb_interface_number
                || current.usb_release_bcd != original.usb_release_bcd
                || current.manufacturer != original.manufacturer
                || current.product != original.product
                || current.serial != original.serial
                || current.hid_unique != original.hid_unique
                || current.descriptor_bytes != original.descriptor_bytes
                || current.descriptor_sha256 != original.descriptor_sha256
            {
                return Err("normal return metadata differs from the original device".into());
            }
        }
        Mode::Boot => {
            let descriptor = &boot_bank::BOOT_HID_REPORT_DESCRIPTOR;
            if current.vendor_id != 0x09da
                || current.product_id != 0xd023
                || current.usb_release_bcd != 2
                || current.usb_interface_number != 0
                || current.serial.is_some()
                || !current.manufacturer.is_empty()
                || !current.product.is_empty()
                || current.descriptor_bytes != descriptor.len()
                || current.descriptor_sha256 != sha256(descriptor)
            {
                return Err("boot metadata differs from the verified loader descriptor".into());
            }
        }
    }
    Ok(())
}

/// Select one matching control interface at the original physical port.
pub fn select_binding(
    report: &DiscoveryReport,
    original: &Binding,
    mode: Mode,
) -> Result<Option<Binding>, String> {
    if !report.complete() || report.sysfs_root != "/sys" {
        return Err("mode discovery requires a complete real cached snapshot".into());
    }
    let pid = if mode == Mode::Boot {
        0xd023
    } else {
        original.product_id
    };
    let candidates: Vec<_> = report
        .matching_interfaces
        .iter()
        .filter(|interface| {
            interface.usb_parent.as_deref() == Some(original.usb_parent.as_str())
                && interface.vendor_id == 0x09da
                && interface.product_id == pid
                && (mode == Mode::Boot || interface.candidate_for_later_query)
        })
        .collect();
    if candidates.len() > 1 {
        return Err("ambiguous control interfaces at the original USB port".into());
    }
    let Some(interface) = candidates.first() else {
        return Ok(None);
    };
    let binding = Binding::from_control_interface(interface)?;
    validate(mode, &binding, original)?;
    Ok(Some(binding))
}

/// Classify a normal interface against each exact supported descriptor.
/// A mismatch with one firmware is expected while trying the other modes.
pub(crate) fn select_normal_mode(
    report: &DiscoveryReport,
    original: &Binding,
) -> Result<Option<(Mode, Binding)>, String> {
    let mut rejected = Vec::new();
    for mode in [Mode::Normal]
        .into_iter()
        .chain(crate::model::Core::ALL.map(Mode::Target))
    {
        match select_binding(report, original, mode) {
            Ok(Some(binding)) => return Ok(Some((mode, binding))),
            // These modes share the same physical-port/control-interface filter.
            Ok(None) => return Ok(None),
            Err(error) => rejected.push(error),
        }
    }
    Err(format!(
        "No supported normal firmware matches cached metadata: {}",
        rejected.join("; ")
    ))
}
