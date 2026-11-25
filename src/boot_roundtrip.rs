//! Fixed FEFC entry, same-port boot discovery, restoration and normal return.
mod boot_usb;
mod connection;
mod engine;
mod entry_return;
mod executor;
pub(crate) mod lease;
pub mod pipeline;
pub mod readback;
mod simulation;
pub mod target_return;

pub(crate) use connection::select_normal_mode;
pub use connection::{Mode, select_binding};
pub use simulation::Scenario;

use crate::{
    access_job::{AccessBaseline, AccessJob, CaptureScope},
    boot_bank,
    preview::read_file,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PHYSICAL_ROUNDTRIP_RELEASED: bool = false;
const PHYSICAL_FIRMWARE_RELEASED: bool = false;
const PHYSICAL_BACKUP_RELEASED: bool = false;
const PHYSICAL_GATE_CLOSE_RELEASED: bool = false;
const PHYSICAL_RESTORE_RELEASED: bool = false;
const PHYSICAL_BOOT_READBACK_RELEASED: bool = false;
const PHYSICAL_BOOT_CONTROL_RELEASED: bool = true;
const PHYSICAL_TARGET_RETURN_RELEASED: bool = false;
pub const MAX_FEATURE_CALLS: u32 = 1600;
pub const FIRMWARE_MAX_FEATURE_CALLS: u32 = 35_000;
pub const FIRMWARE_TOTAL_SECONDS: u64 = 1800;

pub(super) fn boot_control_available() -> bool {
    PHYSICAL_BOOT_CONTROL_RELEASED && crate::query_session::live_available()
}

pub fn restore_available() -> bool {
    PHYSICAL_RESTORE_RELEASED && boot_control_available()
}
pub fn run_restore(
    reference: &Path,
    backup: &Path,
    output: &Path,
    attempts: Option<u32>,
    from_normal: bool,
) -> Result<serde_json::Value, String> {
    if !restore_available() {
        return Err("physical backup restore is disabled in this build".into());
    }
    executor::run_restore(reference, backup, output, attempts, from_normal)
}
pub fn worker_restore(reference: &Path, backup: &Path, from_normal: bool) -> Result<(), String> {
    if !restore_available() {
        return Err("physical backup restore worker is disabled in this build".into());
    }
    executor::worker_restore(reference, backup, from_normal)
}

pub fn worker_entry_return(reference: &Path, proof: &Path, mode: Mode) -> Result<(), String> {
    if !restore_available() && !readback::available() {
        return Err("physical pre-record return worker is disabled in this build".into());
    }
    if !matches!(mode, Mode::Normal | Mode::Boot) {
        return Err("invalid entry-return mode".into());
    }
    executor::worker_entry_return(reference, proof, mode)
}
pub fn prepare_restore(
    reference: &Path,
    backup: &Path,
    output: &Path,
    simulate: bool,
    failures: u32,
    attempts: Option<u32>,
    from_normal: bool,
) -> Result<serde_json::Value, String> {
    if failures > 32 || attempts == Some(0) {
        return Err(
            "restore simulation permits at most 32 injected failures and a positive attempt limit"
                .into(),
        );
    }
    let reference = load(reference)?;
    let plan = crate::backup_restore::Plan::load(backup)?;
    let output = crate::access_session::create_output(output)?;
    executor::save_json(
        &output.join("restore-plan.json"),
        &plan.summary_with_entry(from_normal),
    )?;
    executor::save(&output.join("restore-records.bin"), &plan.encoded_records())?;
    let report = if simulate {
        simulation::run_restore(&reference, &plan, &output, failures, attempts, from_normal)?
    } else {
        serde_json::json!({"mode":"offline_backup_restore_plan","plan":plan.summary_with_entry(from_normal),"max_attempts":attempts})
    };
    executor::save_json(&output.join("plan-or-simulation.json"), &report)?;
    Ok(report)
}

pub fn available() -> bool {
    PHYSICAL_ROUNDTRIP_RELEASED && boot_control_available()
}

pub fn backup_available() -> bool {
    PHYSICAL_BACKUP_RELEASED && crate::query_session::live_available()
}
pub fn gate_close_available() -> bool {
    PHYSICAL_GATE_CLOSE_RELEASED && crate::query_session::live_available()
}
pub fn run_gate_close(reference: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !gate_close_available() {
        return Err("physical gate-close job is disabled in this build".into());
    }
    executor::run_gate_close(reference, output)
}
pub fn worker_gate_close(reference: &Path) -> Result<(), String> {
    if !gate_close_available() {
        return Err("physical gate-close worker is disabled in this build".into());
    }
    executor::worker_gate_close(reference)
}
pub fn run_backup(reference: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !backup_available() {
        return Err("physical normal firmware backup is disabled in this build".into());
    }
    executor::run_backup(reference, output)
}
pub fn worker_backup(reference: &Path) -> Result<(), String> {
    if !backup_available() {
        return Err("physical normal firmware backup worker is disabled in this build".into());
    }
    executor::worker_backup(reference)
}
pub fn prepare_backup(
    reference: &Path,
    output: &Path,
    simulate: bool,
) -> Result<serde_json::Value, String> {
    let reference = load(reference)?;
    let output = crate::access_session::create_output(output)?;
    let report = if simulate {
        simulation::run_backup(&reference, &output)?
    } else {
        serde_json::json!({"mode":"offline_normal_firmware_backup_plan","physical_execution_available":backup_available(),
            "bytes":65536,"passes":2,"response_seeds":[165,90],"max_feature_calls":10000,"nominal_feature_calls":9192,
            "persistent_programs":0,"resets":0,"total_budget_seconds":900,
            "volatile_key_assignments":6,"normal_usb":"09DA:712F","entry_version":"0028"})
    };
    executor::save_json(&output.join("plan-or-simulation.json"), &report)?;
    Ok(report)
}

fn firmware_plan(assets: &Path, core: crate::model::Core) -> Result<crate::prepared::Plan, String> {
    crate::prepared::Plan::new(
        crate::assets::Manifest::embedded()
            .map_err(|e| e.to_string())?
            .inspect_file(assets, core)
            .map_err(|e| e.to_string())?,
    )
}

pub fn firmware_available() -> bool {
    PHYSICAL_FIRMWARE_RELEASED && boot_control_available()
}
pub fn run_firmware(
    reference: &Path,
    output: &Path,
    assets: &Path,
    core: crate::model::Core,
) -> Result<serde_json::Value, String> {
    if !firmware_available() {
        return Err("physical prepared firmware job is disabled in this build".into());
    }
    executor::run_firmware(reference, output, assets, core)
}
pub fn worker_firmware(
    reference: &Path,
    assets: &Path,
    core: crate::model::Core,
) -> Result<(), String> {
    if !firmware_available() {
        return Err("physical prepared firmware worker is disabled in this build".into());
    }
    executor::worker_firmware(reference, assets, core)
}

pub fn prepare_firmware(
    reference: &Path,
    output: &Path,
    assets: &Path,
    core: crate::model::Core,
    simulate: bool,
) -> Result<serde_json::Value, String> {
    let reference = load(reference)?;
    let plan = firmware_plan(assets, core)?;
    let output = crate::access_session::create_output(output)?;
    let value = if simulate {
        simulation::run_firmware(&reference, &plan, &output)?
    } else {
        serde_json::json!({"mode":"offline_supervised_firmware_plan","firmware":plan.summary(),
            "physical_execution_available":firmware_available(),"total_budget_seconds":FIRMWARE_TOTAL_SECONDS,"max_feature_calls":FIRMWARE_MAX_FEATURE_CALLS,
            "return_policy":"selected Core / version 0034, exact descriptor, same port, full flash and revision-3 bank capture",
            "configuration_policy":"stock image defaults verified byte-for-byte; FF40-FF7F saved-state changes observed; configuration semantics remain unverified"})
    };
    executor::save_json(&output.join("plan-or-simulation.json"), &value)?;
    Ok(value)
}

#[derive(Clone)]
pub(crate) struct Reference {
    pub baseline: AccessBaseline,
    pub packed: Vec<u8>,
}

pub(crate) fn load(directory: &Path) -> Result<Reference, String> {
    let report: serde_json::Value =
        serde_json::from_slice(&read_file(&directory.join("session.json"), 1_048_576)?)
            .map_err(|error| error.to_string())?;
    if report["scope"] != "boot_bank"
        || report["result"]["complete"] != true
        || report["result"]["release_lock_allowed"] != true
        || report["boot_preflight"]["comparison"]["matches_embedded_copy_and_identity"] != true
        || report["worker_stop"]["reaped"] != true
        || report["worker_stop"]["exit_success"] != true
    {
        return Err("round trip requires a completed matching boot-bank session".into());
    }
    let baseline: AccessBaseline =
        serde_json::from_value(report["baseline"].clone()).map_err(|error| error.to_string())?;
    AccessJob::with_scope(baseline.clone(), CaptureScope::BootBank)?;
    let first = read_file(
        &directory.join("boot-preflight.pass0.candidate.bin"),
        boot_bank::PASS_BYTES,
    )?;
    let second = read_file(
        &directory.join("boot-preflight.pass1.candidate.bin"),
        boot_bank::PASS_BYTES,
    )?;
    if first.len() != boot_bank::PASS_BYTES
        || first != second
        || !boot_bank::matches_known_bank(&first[..boot_bank::BANK_BYTES])
        || !boot_bank::compare(&first)
            .is_some_and(|comparison| comparison.matches_embedded_copy_and_identity)
    {
        return Err("round-trip reference bytes disagree with the verified boot copy".into());
    }
    Ok(Reference {
        baseline,
        packed: first,
    })
}

pub(crate) fn normal_binding(
    report: &crate::discovery::DiscoveryReport,
    original: &crate::query_session::Binding,
) -> Result<crate::query_session::Binding, String> {
    connection::select_binding(report, original, Mode::Normal)?
        .ok_or_else(|| "same-port original normal device absent".into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Fault {
    pub message: String,
    pub uncertain: bool,
}

impl Fault {
    pub fn known(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: false,
        }
    }
    pub fn uncertain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: true,
        }
    }
}

impl From<String> for Fault {
    fn from(message: String) -> Self {
        Self::known(message)
    }
}

pub fn prepare(
    reference: &Path,
    output: &Path,
    scenario: Option<Scenario>,
) -> Result<serde_json::Value, String> {
    let reference = load(reference)?;
    let output = crate::access_session::create_output(output)?;
    let value = match scenario {
        Some(scenario) => simulation::run(&reference, &output, scenario)?,
        None => serde_json::json!({
            "mode":"offline_boot_roundtrip_plan", "physical_execution_available":available(),
            "normal_baseline_sha256":reference.baseline.fingerprint(),
            "boot_bank_sha256":crate::firmware::sha256(&reference.packed[..boot_bank::BANK_BYTES]),
            "normal_usb":"09DA:712F", "boot_usb":"09DA:D023", "same_usb_port_required":true,
            "marker_address":0xfefc, "original_marker":"A4A4A4A4", "entry_marker":"00000000",
            "nominal_marker_programs":2, "nominal_resets":2, "max_feature_calls":MAX_FEATURE_CALLS,
            "native_entry_enabled":available(),
            "limits":["FEFC preservation and boot behavior remain unmeasured.",
                       "A verified active bank and final byte comparison are required within each job.",
                       "Uncertain calls retain the lock. Restoration needs a verified same-port identity."]
        }),
    };
    executor::save_json(&output.join("plan-or-simulation.json"), &value)?;
    Ok(value)
}

pub fn run(reference: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical boot round trip is disabled in this build".into());
    }
    executor::run(reference, output)
}

pub fn worker(reference: &Path) -> Result<(), String> {
    if !available() {
        return Err("physical boot round trip is disabled in this build".into());
    }
    executor::worker(reference)
}

pub(crate) fn workflow_transport_available() -> bool {
    boot_control_available()
}
pub(crate) fn save_artifact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    executor::save(path, bytes)
}
pub(crate) fn run_workflow(
    project: &Path,
    output: &Path,
    recover: bool,
) -> Result<serde_json::Value, String> {
    executor::pipeline::run(project, output, recover)
}

pub(crate) fn simulate_workflow(
    project: &Path,
    output: &Path,
    recover: bool,
) -> Result<serde_json::Value, String> {
    executor::pipeline::model_workflow(project, output, recover)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_native_entries_refuse_before_loading_a_baseline_or_creating_output() {
        assert!(!available());
        let missing = Path::new("missing-roundtrip-baseline");
        assert!(run(missing, missing).unwrap_err().contains("disabled"));
        assert!(worker(missing).unwrap_err().contains("disabled"));
        assert!(!missing.exists());
    }

    #[test]
    fn firmware_native_entries_are_separately_disabled_before_any_input_or_output() {
        assert!(!firmware_available());
        let missing = Path::new("missing-firmware-job-everything");
        assert!(
            run_firmware(missing, missing, missing, crate::model::Core::One)
                .unwrap_err()
                .contains("disabled")
        );
        assert!(
            worker_firmware(missing, missing, crate::model::Core::One)
                .unwrap_err()
                .contains("disabled")
        );
        assert!(!missing.exists());
    }

    #[test]
    fn backup_entries_refuse_before_loading_or_creating_files() {
        assert!(!backup_available());
        let missing = Path::new("missing-backup-input-and-output");
        assert!(
            run_backup(missing, missing)
                .unwrap_err()
                .contains("disabled")
        );
        assert!(worker_backup(missing).unwrap_err().contains("disabled"));
        assert!(!missing.exists());
        assert!(!gate_close_available());
        assert!(
            run_gate_close(missing, missing)
                .unwrap_err()
                .contains("disabled")
        );
        assert!(worker_gate_close(missing).unwrap_err().contains("disabled"));
    }
}
