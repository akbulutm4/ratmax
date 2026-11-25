//! A bounded boot readback followed by separate checked zero-record return.
use super::*;

pub fn available() -> bool {
    PHYSICAL_BOOT_READBACK_RELEASED && boot_control_available()
}
pub fn run(reference: &Path, backup: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical boot readback is disabled in this build".into());
    }
    executor::run_readback(reference, backup, output)
}
pub fn worker(reference: &Path, backup: &Path) -> Result<(), String> {
    if !available() {
        return Err("physical boot readback worker is disabled in this build".into());
    }
    executor::worker_readback(reference, backup)
}
pub fn prepare(
    reference: &Path,
    backup: &Path,
    output: &Path,
    simulate: bool,
) -> Result<serde_json::Value, String> {
    let reference = load(reference)?;
    let plan = crate::backup_restore::Plan::load(backup)?;
    let output = crate::access_session::create_output(output)?;
    let scope = serde_json::json!({"firmware_records":0,"normal_entry":true,"first_boot_address":"0500","image_bytes_per_pass":65536,"bank_bytes_per_pass":3072,"passes":2,"entry_return_limit":96,"entry_return_seconds":120,"capture_limit":50000,"capture_seconds":2400});
    executor::save_json(&output.join("boot-readback-plan.json"), &scope)?;
    if !simulate {
        return Ok(
            serde_json::json!({"mode":"offline_boot_readback_plan","scope":scope,"physical_execution_available":false}),
        );
    }
    simulation::run_readback(&reference, &plan, &output)
}
