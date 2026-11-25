//! W95 Max assets/codecs/plans, mock simulations and passive cached discovery.
//! An optional Linux worker supports audited information queries and a separate
//! baseline-gated descriptor/header sessions and bounded sensitivity captures.
//! A separate temporary-access executor is type-checked but physically disabled
//! pending review; its plan/simulation commands use local files only.
//! There is no enabled device configuration or flashing API.

pub mod access_job;
pub mod access_session;
pub mod access_simulation;
pub mod assets;
pub mod backup_restore;
pub mod boot_bank;
pub mod boot_roundtrip;
pub mod button_cycle;
pub mod button_plan;
pub mod descriptor;
pub mod discovery;
pub mod error;
pub mod firmware;
pub mod lighting;
pub mod model;
pub mod plan;
pub mod prepared;
pub mod preview;
pub mod profile;
pub mod program;
pub mod protocol;
pub mod queries;
pub mod query_session;
pub mod readback;
pub mod recovery;
pub mod sensitivity_block;
pub mod sensitivity_body;
pub mod settings;
pub mod settings_cycle;
pub mod shooting_runtime;
pub mod simulation;
pub mod transport;
pub mod tui;
pub mod w1;
pub mod workflow;

pub mod macros;
