use super::{
    Binding, Ownership,
    control::{self, ControlIo, Setup},
};
use crate::transport::LocalFeatureTransport;
use rusb::UsbContext;
use std::{path::Path, time::Duration};
struct Io {
    handle: rusb::DeviceHandle<rusb::Context>,
}
impl ControlIo for Io {
    fn read(&mut self, setup: Setup, bytes: &mut [u8]) -> Result<usize, String> {
        self.handle
            .read_control(
                setup.request_type,
                setup.request,
                setup.value,
                setup.index,
                bytes,
                Duration::from_secs(2),
            )
            .map_err(|e| format!("boot USB control read: {e}"))
    }
    fn write(&mut self, setup: Setup, bytes: &[u8]) -> Result<usize, String> {
        self.handle
            .write_control(
                setup.request_type,
                setup.request,
                setup.value,
                setup.index,
                bytes,
                Duration::from_secs(2),
            )
            .map_err(|e| format!("boot USB control write: {e}"))
    }
}
pub(in crate::boot_roundtrip) fn open(
    binding: &Binding,
) -> Result<Box<dyn LocalFeatureTransport>, String> {
    binding.revalidate(Path::new("/sys"), Ownership::Available)?;
    binding.check_node()?;
    let context = rusb::Context::new().map_err(|e| e.to_string())?;
    let devices = context.devices().map_err(|e| e.to_string())?;
    let candidates: Vec<_> = devices
        .iter()
        .filter(|d| d.bus_number() == binding.bus_number && d.address() == binding.device_address)
        .collect();
    if candidates.len() != 1 {
        return Err("one exact boot USB address is required".into());
    }
    let device = &candidates[0];
    let descriptor = device.device_descriptor().map_err(|e| e.to_string())?;
    if descriptor.vendor_id() != 0x09da
        || descriptor.product_id() != 0xd023
        || descriptor.device_version()
            != rusb::Version::from_bcd(binding.boot_revision.usb_release())
        || device.port_numbers().map_err(|e| e.to_string())? != binding.port_numbers
    {
        return Err("libusb boot device identity or port differs".into());
    }
    let handle = device.open().map_err(|e| e.to_string())?;
    binding.revalidate(Path::new("/sys"), Ownership::Available)?;
    binding.check_node()?;
    // This only claims interface zero of the exact validated boot device.
    // No set-configuration, reset-device or interrupt API is used.
    handle
        .set_auto_detach_kernel_driver(true)
        .map_err(|e| e.to_string())?;
    handle.claim_interface(0).map_err(|e| e.to_string())?;
    binding.revalidate(Path::new("/sys"), Ownership::Claimed)?;
    let device = control::Device::checked(Io { handle })?;
    binding.revalidate(Path::new("/sys"), Ownership::Claimed)?;
    Ok(Box::new(device))
}
