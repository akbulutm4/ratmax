//! Immutable offline plans. JSON is a preview, not an executable/importable job.

use serde::Serialize;

use crate::{
    assets::{Inspection, ValidatedImage},
    firmware::{self, EncodedRecord},
    protocol::GENERIC_LOCAL_LEN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    InspectTarget,
    SnapshotConfiguration,
    EnterUpgrade,
    ResetForBoot,
    AwaitBoot,
    ReadDeviceValue,
    InitializeDeviceValue,
    TransferRecords,
    ReadFinalBlock,
    FinalizeIdentity,
    ResetForNormal,
    AwaitNormal,
    VerifyReturn,
    ApplyConfiguration,
    VerifyConfiguration,
}

#[derive(Debug, Clone, Serialize)]
pub struct Blocker {
    pub gap: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutStatus {
    NoReport,
    KnownLocalLayout,
    KnownLayoutUnknownValue,
    Unresolved,
    NotImplemented,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanStage {
    pub stage: Stage,
    pub local_layout: LayoutStatus,
    pub detail: &'static str,
    pub required_gaps: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct PlanSummary {
    pub schema_version: u32,
    pub mode: &'static str,
    pub live_execution_available: bool,
    pub target_device_identity: Option<String>,
    pub baseline_configuration_sha256: Option<String>,
    pub physical_erase_ranges: Option<Vec<(u32, u32)>>,
    pub firmware: Inspection,
    pub generic_local_buffer_length: usize,
    pub stages: Vec<PlanStage>,
    pub blockers: Vec<Blocker>,
}

#[derive(Debug)]
pub struct FirmwarePlan {
    image: ValidatedImage,
    summary: PlanSummary,
    id: String,
}

impl FirmwarePlan {
    pub fn new(image: ValidatedImage) -> Self {
        use LayoutStatus::*;
        use Stage::*;
        let specifications = [
            (
                InspectTarget,
                Unresolved,
                "Bind a physical unit and establish model/Core/version",
                vec!["G1", "G2", "G5"],
            ),
            (
                SnapshotConfiguration,
                NotImplemented,
                "Read/preserve all configuration affected by the operation",
                vec!["G6", "G7"],
            ),
            (
                EnterUpgrade,
                KnownLocalLayout,
                "07 28 01 with a zero DWORD at +8 is measured for 0028/revision-2; compose the supervised job",
                vec!["G3", "G10"],
            ),
            (
                ResetForBoot,
                KnownLocalLayout,
                "07 00: 64-byte reset and same-port re-enumeration measured for the current firmware",
                vec!["G1", "G3", "G10"],
            ),
            (
                AwaitBoot,
                NoReport,
                "Correlate the same unit in boot mode",
                vec!["G2"],
            ),
            (
                ReadDeviceValue,
                KnownLocalLayout,
                "07 29: query eight bytes without implicit initialization",
                vec!["G1", "G4"],
            ),
            (
                InitializeDeviceValue,
                Unresolved,
                "Conditional on U=FFFFFFFF; no initialization policy or write emitted",
                vec!["G4"],
            ),
            (
                TransferRecords,
                KnownLocalLayout,
                "Original ordered records, one Set/Get pair per acknowledgment",
                vec!["G1", "G10"],
            ),
            (
                ReadFinalBlock,
                KnownLocalLayout,
                "07 2B: preserve the six post-replay DWORDs, including the target version",
                vec!["G1", "G4"],
            ),
            (
                FinalizeIdentity,
                KnownLocalLayout,
                "Default 441560 mapping matches 09DA712F for historical U; prepared replay requires fresh equality and readback",
                vec!["G4"],
            ),
            (
                ResetForNormal,
                KnownLocalLayout,
                "07 00 after successful finalization only",
                vec!["G1", "G5", "G10"],
            ),
            (
                AwaitNormal,
                NoReport,
                "Bounded same-unit reconnect; never select the first matching model",
                vec!["G2"],
            ),
            (
                VerifyReturn,
                Unresolved,
                "Compare unit identity, model, Core and version at an explicit verification level",
                vec!["G2", "G5"],
            ),
            (
                ApplyConfiguration,
                NotImplemented,
                "Compile/reapply target-compatible profile and sensitivity",
                vec!["G6", "G7"],
            ),
            (
                VerifyConfiguration,
                NotImplemented,
                "Check readable state and behavior; no assumed full firmware readback",
                vec!["G5", "G6", "G7"],
            ),
        ];
        let summary = PlanSummary {
            schema_version: 1,
            mode: "offline_plan",
            live_execution_available: false,
            target_device_identity: None,
            baseline_configuration_sha256: None,
            physical_erase_ranges: None,
            firmware: image.inspection().clone(),
            generic_local_buffer_length: GENERIC_LOCAL_LEN,
            stages: specifications
                .into_iter()
                .map(|(stage, local_layout, detail, required_gaps)| PlanStage {
                    stage,
                    local_layout,
                    detail,
                    required_gaps,
                })
                .collect(),
            blockers: vec![
                Blocker {
                    gap: "G1",
                    reason: "Native record replay and its decoded-response checks remain unmeasured",
                },
                Blocker {
                    gap: "G2",
                    reason: "Current same-port cycle is verified; target-version return policy needs integration",
                },
                Blocker {
                    gap: "G3",
                    reason: "Current entry is verified; target startup replaces revision-2 boot code with revision 3",
                },
                Blocker {
                    gap: "G4",
                    reason: "Fresh identity policy is implemented offline; live finalization and erased-U initialization remain unverified",
                },
                Blocker {
                    gap: "G5",
                    reason: "Return/version verification and complete session evidence missing",
                },
                Blocker {
                    gap: "G6",
                    reason: "Complete profile preservation/compiler unavailable",
                },
                Blocker {
                    gap: "G7",
                    reason: "Complete sensitivity preservation/compiler unavailable",
                },
                Blocker {
                    gap: "G10",
                    reason: "Interrupted-update recovery unproven for the daily driver",
                },
            ],
        };
        // Only primitive values and ordered structs/vectors are serialized.
        let serialized = serde_json::to_vec(&summary).expect("plan consists of JSON primitives");
        Self {
            image,
            summary,
            id: firmware::sha256(&serialized),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn summary(&self) -> &PlanSummary {
        &self.summary
    }
    pub fn inspection(&self) -> &Inspection {
        self.image.inspection()
    }
    pub(crate) fn records(&self) -> &[EncodedRecord] {
        self.image.records().records()
    }

    pub fn text(&self) -> String {
        let info = self.inspection();
        let mut text = format!(
            "ratmax | OFFLINE PLAN | LIVE EXECUTION BLOCKED\nPlan SHA-256: {}\n{} | {} | {} records\nSource SHA-256: {}\nAsset-only plan: no target binding or baseline; physical erase footprint unresolved.\nUse prepared-plan for the concrete replay segment; legacy simulate retains abstract transitions.\n\n",
            self.id, info.model_id, info.core, info.record_count, info.source_sha256
        );
        for stage in &self.summary.stages {
            text.push_str(&format!(
                "{:?}: {} [{}]\n",
                stage.stage,
                stage.detail,
                stage.required_gaps.join(", ")
            ));
        }
        text.push_str("\nLive blockers:\n");
        for blocker in &self.summary.blockers {
            text.push_str(&format!("{}: {}\n", blocker.gap, blocker.reason));
        }
        text
    }

    pub fn json(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct Document<'a> {
            plan_sha256: &'a str,
            plan: &'a PlanSummary,
        }
        serde_json::to_string_pretty(&Document {
            plan_sha256: self.id(),
            plan: self.summary(),
        })
    }
}
