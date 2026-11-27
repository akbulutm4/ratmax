//! Safe bootloader transition, same-port USB control transport, and supervised
//! workflow/configuration execution for the Bloody W95 Max.
mod boot_usb;
mod connection;
mod engine;
mod executor;
pub(crate) mod lease;
pub mod pipeline;
mod simulation;

pub(crate) use connection::select_normal_mode;
pub use connection::{Mode, detect_connected_mouse, select_binding};

use crate::{
    access_job::{AccessBaseline, AccessJob, CaptureScope},
    boot_bank,
    preview::read_file,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const PHYSICAL_BOOT_CONTROL_RELEASED: bool = true;

pub(super) fn boot_control_available() -> bool {
    PHYSICAL_BOOT_CONTROL_RELEASED && crate::query_session::live_available()
}

pub(crate) fn workflow_transport_available() -> bool {
    boot_control_available()
}

pub(crate) fn run_workflow(
    input: &Path,
    output: &Path,
    recover: bool,
) -> Result<serde_json::Value, String> {
    executor::pipeline::run(input, output, recover)
}

pub(crate) fn simulate_workflow(
    input: &Path,
    output: &Path,
    recover: bool,
) -> Result<serde_json::Value, String> {
    executor::pipeline::model_workflow(input, output, recover)
}

pub(crate) fn save_artifact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    executor::save(path, bytes)
}

pub(crate) fn create_output(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if ["/dev", "/sys", "/proc"]
        .iter()
        .any(|p| parent.starts_with(p))
    {
        return Err("output must be a host directory outside /dev, /sys, and /proc".into());
    }
    let out = parent.join(path.file_name().ok_or("output directory required")?);
    std::fs::create_dir(&out).map_err(|e| format!("output directory must be new: {e}"))?;
    Ok(out)
}

fn firmware_plan(assets: &Path, core: crate::model::Core) -> Result<crate::prepared::Plan, String> {
    crate::prepared::Plan::new(
        crate::assets::Manifest::embedded()
            .map_err(|e| e.to_string())?
            .inspect_file(assets, core)
            .map_err(|e| e.to_string())?,
    )
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
        return Err("workspace baseline requires a completed matching boot-bank session".into());
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
        return Err("baseline boot-bank bytes disagree with the verified bootloader copy".into());
    }
    Ok(Reference {
        baseline,
        packed: first,
    })
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
