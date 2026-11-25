//! A complete preset/configuration/backup-return test with one shared read budget.
use super::Reference;
use crate::{backup_restore, firmware::sha256, model::Core, prepared};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

const PHYSICAL_PRESET_CYCLE_RELEASED: bool = false;
pub const MAX_CALLS: u32 = 20_000;
pub const TOTAL_SECONDS: u64 = 1800;
pub const PROFILE_BYTES: usize = 0x500;
pub const PROFILE_SOURCE_BYTES: usize = 0x4d8;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u8,
    pub baseline: PathBuf,
    pub backup: PathBuf,
    pub assets: PathBuf,
    pub core: Core,
    pub observation_seconds: u16,
    #[serde(default)]
    pub shooting_comparison: bool,
    #[serde(default)]
    pub workflow: Option<crate::workflow::Settings>,
}

pub(crate) struct Plan {
    pub request: Request,
    pub reference: Reference,
    pub backup: backup_restore::Plan,
    pub stock: prepared::Plan,
    pub target: Vec<u8>,
    pub configured: Vec<u8>,
    pub samples: Vec<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Verification {
    pub retry_allowed: bool,
    pub forward_records: usize,
    pub restore_records: usize,
    pub configuration_programs: usize,
    pub forward_samples_verified: bool,
    pub forward_all_flash_verified: bool,
    pub configuration_verified: bool,
    pub full_read_started: bool,
    pub full_restore_prefix_verified: bool,
    pub original_return_samples_verified: bool,
    pub original_boot_bank_verified: bool,
    pub experimental_profile_materialized: bool,
    #[serde(default)]
    pub runtime_observations: Vec<(String, crate::shooting_runtime::Snapshot)>,
    #[serde(default)]
    pub shooting_comparison_completed: bool,
    #[serde(default)]
    pub runtime_programs: u32,
    #[serde(default)]
    pub desired_configuration_kept: bool,
    #[serde(default)]
    pub inspected: bool,
}

impl Plan {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let mut request: Request = serde_json::from_slice(&crate::preview::read_file(path, 65536)?)
            .map_err(|e| e.to_string())?;
        if request.schema != 1 || request.observation_seconds > 300 {
            return Err("invalid preset-cycle request".into());
        }
        if request.shooting_comparison && request.core != Core::Three {
            return Err("shooting comparison requires ordinary W95 Max Core 3".into());
        }
        if let Some(settings) = &request.workflow {
            settings.validate(request.core)?;
            if request.shooting_comparison || request.observation_seconds != 0 {
                return Err("ordinary workflow cannot contain physical observation trials".into());
            }
        }
        let root = path.parent().unwrap_or(Path::new("."));
        request.baseline =
            std::fs::canonicalize(root.join(&request.baseline)).map_err(|e| e.to_string())?;
        request.backup =
            std::fs::canonicalize(root.join(&request.backup)).map_err(|e| e.to_string())?;
        request.assets =
            std::fs::canonicalize(root.join(&request.assets)).map_err(|e| e.to_string())?;
        let reference = super::load(&request.baseline)?;
        if let Some(settings) = &mut request.workflow
            && let Some(budget) = &mut settings.budget
        {
            *budget = std::fs::canonicalize(root.join(&*budget)).map_err(|e| e.to_string())?;
        }
        if let Some(settings) = &mut request.workflow
            && let Some(entry) = &mut settings.model_entry
        {
            *entry = std::fs::canonicalize(root.join(&*entry)).map_err(|e| e.to_string())?;
            let report: serde_json::Value = serde_json::from_slice(&crate::preview::read_file(
                &entry.join("cycle.json"),
                1_048_576,
            )?)
            .map_err(|e| e.to_string())?;
            let image = crate::preview::read_file(&entry.join("model-state.bin"), 65536)?;
            if report["native"] != false
                || report["complete"] != true
                || report["desired_configuration_kept"] != true
                || report["result"]["mode"]
                    != serde_json::to_value(settings.entry).map_err(|e| e.to_string())?
                || report["model_state_sha256"] != sha256(&image)
            {
                return Err("model entry state/proof differs".into());
            }
        }
        let backup = backup_restore::Plan::load(&request.backup)?;
        let stock = super::firmware_plan(&request.assets, request.core)?;
        let mut target = backup.original.clone();
        for record in stock.image_records() {
            let at = record.address().get() as usize;
            target[at..at + 32].copy_from_slice(&record.decoded_payload());
        }
        target[0xfee0..0xfee4].copy_from_slice(&backup.original[0xfee0..0xfee4]);
        let configured = configure(
            &target,
            &backup.original,
            &stock,
            request.workflow.is_none(),
        )?;
        let mut samples: BTreeSet<usize> = [
            0, 0x20, 0x100, 0x4e0, 0x500, 0x800, 0x1000, 0x2000, 0x3000, 0x4000, 0x5460, 0x6000,
            0x7fc0, 0x7fe0, 0x8000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xdfe0, 0xfe80, 0xfea0,
            0xfec0, 0xfee0, 0xff00, 0xff20, 0xff40, 0xff60, 0xff80, 0xffa0, 0xffc0, 0xffe0,
        ]
        .into_iter()
        .collect();
        samples.extend((0xe000..0xe100).step_by(32));
        samples.extend((0xe180..0xe200 + PROFILE_BYTES).step_by(32));
        Ok(Self {
            request,
            reference,
            backup,
            stock,
            target,
            configured,
            samples: samples.into_iter().collect(),
        })
    }
    pub fn summary(&self) -> serde_json::Value {
        let mut summary = serde_json::json!({"mode":"bounded_preset_configuration_cycle_plan","core":self.request.core,"version":52,"source_sha256":self.stock.summary().source_sha256,
        "original_backup_sha256":self.backup.sha256(),"target_expected_sha256":sha256(&self.target),"configured_expected_sha256":sha256(&self.configured),
        "forward_records":self.stock.image_records().len(),"return_records":self.backup.records.len(),"sample_addresses":self.samples,"sample_bytes":self.samples.len()*32,
        "full_device_read_budget_for_entire_test":1,"full_read_reserved_for_original_restore_prefix":true,"forward_verification":"record acknowledgments plus critical-code/configuration/unit samples and complete active loader; not whole-image verification",
        "configuration_program_pages":[[0xe000,0xe100],[0xe200,0xe700]],"configuration_programs":if self.request.shooting_comparison {132} else {50},"runtime_slot_applications":if self.request.shooting_comparison {vec![0,1,0]} else {vec![]},"configuration_policy":"reapply original sensitivity block; copy self-contained stock ROM main profile; preserve primary buttons; Core 3 side Back precision-hold and side Forward double-click selector",
        "profile_source_bytes":PROFILE_SOURCE_BYTES,"main_checksum_scope":"copied main vector; additional marker must remain invalid/unallocated; no NOR vector allocated","profile_materialization_physically_qualified":false,
        "shooting_comparison":self.request.shooting_comparison,"observations":self.observation_phases(),"observation_seconds":self.request.observation_seconds,"max_feature_calls_per_worker":MAX_CALLS,"total_seconds_per_worker":TOTAL_SECONDS,"resume_supported":false,"physical_execution_available":available(),
        "remaining_physical_questions":["stock-program reference and shooting-selector activation", "precision and click behavior", "sampled preset verification under the read budget"]});
        if let Some(settings) = &self.request.workflow {
            summary["mode"] = "w95max_workflow_plan".into();
            summary["workflow"] = serde_json::to_value(settings).expect("settings");
            summary["configured_expected_sha256"] = serde_json::Value::Null;
            summary["exact_candidate_available_after_bounded_preflight"] = true.into();
            summary["configuration_policy"]="preserve fresh owned settings and profile bytes, apply only the selected CPI/rate and side assignments".into();
            summary["physical_execution_available"] = crate::workflow::available().into();
            summary["forward_records"] =
                serde_json::json!(if settings.operation == crate::workflow::Operation::Flash {
                    self.stock.image_records().len()
                } else {
                    0
                });
            summary["configuration_programs"] = serde_json::Value::Null;
            summary["configuration_program_pages"] =
                if settings.operation == crate::workflow::Operation::Inspect {
                    serde_json::json!([])
                } else {
                    serde_json::json!([
                        [0xe000, 0xe100],
                        [
                            0xe200,
                            if settings.operation == crate::workflow::Operation::Configure
                                && settings.entry == super::Mode::Normal
                            {
                                0xe300
                            } else {
                                0xe700
                            }
                        ]
                    ])
                };
            summary["return_records"] = serde_json::json!(if settings.restore_after {
                self.backup.records.len()
            } else {
                0
            });
            summary["backup_restore_records_on_request_or_failure"] =
                serde_json::json!(self.backup.records.len());
            summary["remaining_physical_questions"] = serde_json::json!([
                "new TUI leave-installed/configure/restore acceptance",
                "Core 2/4 input behavior remains unqualified"
            ]);
            summary["observations"] = serde_json::json!([]);
            summary["full_reads_on_success"] =
                serde_json::json!(if settings.restore_after { 1 } else { 0 });
            summary["backup_policy"] =
                "verified original backup is frozen locally; no redundant device backup capture"
                    .into();
        }
        summary
    }
    pub(crate) fn images(&self, mode: super::Mode) -> Result<(Vec<u8>, Vec<u8>), String> {
        if mode == super::Mode::Normal {
            return Ok((self.backup.original.clone(), self.backup.original.clone()));
        }
        let super::Mode::Target(core) = mode else {
            return Err("boot mode has no intact configuration template".into());
        };
        let stock = super::firmware_plan(&self.request.assets, core)?;
        let mut image = self.backup.original.clone();
        for r in stock.image_records() {
            let at = r.address().get() as usize;
            image[at..at + 32].copy_from_slice(&r.decoded_payload());
        }
        image[0xfee0..0xfee4].copy_from_slice(&self.backup.original[0xfee0..0xfee4]);
        let canonical = configure(
            &image,
            &self.backup.original,
            &stock,
            self.request.workflow.is_none(),
        )?;
        Ok((image, canonical))
    }

    pub(super) fn observation_phases(&self) -> Vec<&'static str> {
        if self.request.shooting_comparison {
            vec![
                "target-stock",
                "shoot-baseline",
                "shoot-selector",
                "shoot-applied",
                "shoot-direct-double",
                "shoot-direct-triple",
                "original-restored",
            ]
        } else {
            vec!["target-stock", "target-configured", "original-restored"]
        }
    }

    pub(super) fn direct_profile(&self, clicks: usize) -> Result<Vec<u8>, String> {
        if self.request.core != Core::Three || !matches!(clicks, 2 | 3) {
            return Err("direct stock click test requires Core 3 and 2 or 3 clicks".into());
        }
        let mut goal = self.configured.clone();
        let table = usize::from(u16::from_le_bytes(goal[0xe216..0xe218].try_into().unwrap()));
        let entry = 0xe200 + 2 * (table + clicks - 1);
        let reference = u16::from_le_bytes(goal[entry..entry + 2].try_into().unwrap());
        let at = 0xe200 + 2 * usize::from(reference & 0x3fff);
        let mut expected = Vec::new();
        for i in 0..clicks {
            expected.extend([0x2501_u16, 0x2819, 0x2401]);
            expected.push(if i + 1 == clicks { 0x262f } else { 0x2855 });
        }
        let bytes: Vec<_> = expected.iter().flat_map(|w| w.to_le_bytes()).collect();
        if reference & 0xc000 != 0xc000 || goal.get(at..at + bytes.len()) != Some(bytes.as_slice())
        {
            return Err("stock click reference/program differs".into());
        }
        goal[0xe2c0..0xe2c2].copy_from_slice(&reference.to_le_bytes());
        let words: Vec<_> = goal[0xe200..0xe200 + PROFILE_SOURCE_BYTES]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
            .collect();
        let c = crate::profile::checksums(&words, &[], &[]);
        goal[0xe204..0xe206].copy_from_slice(&c.sum.to_le_bytes());
        goal[0xe206..0xe208].copy_from_slice(&c.weighted.to_le_bytes());
        Ok(goal)
    }
}

fn configure(
    target: &[u8],
    original: &[u8],
    stock: &prepared::Plan,
    test_defaults: bool,
) -> Result<Vec<u8>, String> {
    let mut configured = target.to_vec();
    if target[0xfe9c..0xfea0] != [0xff; 4] || target[0xfea0..0xfec0].iter().any(|b| *b != 0) {
        return Err(
            "materialization requires the stock unallocated additional-profile area".into(),
        );
    }
    let base = if stock.core().firmware_index().get() < 2 {
        0xb56c
    } else {
        0xb564
    };
    let blob = &stock.decoded[base..base + PROFILE_SOURCE_BYTES];
    if blob[..4] != [0xa4; 4] || u16::from_le_bytes(blob[14..16].try_into().unwrap()) != 0x4038 {
        return Err("stock main-profile layout changed".into());
    }
    for off in (0x70..0x7e).step_by(2) {
        if u16::from_le_bytes(blob[off..off + 2].try_into().unwrap()) != 88 {
            return Err("stock button aliases changed".into());
        }
    }
    let primary = [
        0x01, 0x25, 0x01, 0x24, 0x02, 0x25, 0x02, 0x24, 0x04, 0x25, 0x04, 0x24,
    ];
    if blob[176..188] != primary {
        return Err("stock primary actions differ".into());
    }
    configured[0xe000..0xe100].copy_from_slice(&original[0xe000..0xe100]);
    configured[0xe200..0xe200 + PROFILE_SOURCE_BYTES].copy_from_slice(blob);
    // ROM table flags are not carried into the writable profile. All stored
    // header pointers remain inside the copied, self-contained main vector.
    for index in 7..16 {
        let at = 0xe200 + 2 * index;
        let value = u16::from_le_bytes(configured[at..at + 2].try_into().unwrap()) & 0x3fff;
        if usize::from(value) * 2 >= PROFILE_SOURCE_BYTES {
            return Err("stock profile pointer escapes materialized data".into());
        }
        configured[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for word in blob[8..]
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
    {
        if word & 0xf000 == 0xb000 {
            return Err("stock profile requires an external NOR program".into());
        }
        if word & 0xf000 == 0xc000 && usize::from(word & 0xfff) * 2 >= PROFILE_SOURCE_BYTES {
            return Err("stock program reference escapes copied data".into());
        }
    }
    let edits: [u16; 4] = if stock.core() == Core::Three {
        [0x2628, 0x2629, 0x2611, 0x262e]
    } else {
        [0x2510, 0x2410, 0x2508, 0x2408]
    };
    for (i, word) in edits.into_iter().enumerate().filter(|_| test_defaults) {
        let at = 0xe200 + 176 + 12 + 2 * i;
        configured[at..at + 2].copy_from_slice(&word.to_le_bytes());
    }
    let words: Vec<u16> = configured[0xe200..0xe200 + PROFILE_SOURCE_BYTES]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let c = crate::profile::checksums(&words, &[], &[]);
    configured[0xe204..0xe206].copy_from_slice(&c.sum.to_le_bytes());
    configured[0xe206..0xe208].copy_from_slice(&c.weighted.to_le_bytes());
    Ok(configured)
}

pub fn available() -> bool {
    PHYSICAL_PRESET_CYCLE_RELEASED && super::boot_control_available()
}
pub fn prepare(project: &Path, output: &Path, simulate: bool) -> Result<serde_json::Value, String> {
    let plan = Plan::load(project)?;
    let output = crate::access_session::create_output(output)?;
    super::executor::save_json(&output.join("plan.json"), &plan.summary())?;
    if simulate {
        super::simulation::run_pipeline(&plan, &output)
    } else {
        Ok(plan.summary())
    }
}
pub fn run(project: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical preset cycle is disabled in this build".into());
    }
    super::executor::pipeline::run(project, output, false)
}
pub fn restore(session: &Path, output: &Path) -> Result<serde_json::Value, String> {
    if !available() {
        return Err("physical preset restoration is disabled in this build".into());
    }
    super::executor::pipeline::run(session, output, true)
}
pub fn worker(source: &Path) -> Result<(), String> {
    if !available() && !crate::workflow::available() {
        return Err("physical preset worker is disabled in this build".into());
    }
    super::executor::pipeline::worker(source)
}
