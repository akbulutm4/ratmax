//! Open-source Linux configuration, macro, RGB lighting, and firmware tooling
//! for the Bloody W95 Max (model `0x0578`).

pub mod access_job;
pub mod assets;
pub mod backup_restore;
pub mod boot_bank;
pub mod boot_roundtrip;
pub mod descriptor;
pub mod discovery;
pub mod error;
pub mod firmware;
pub mod init;
pub mod lighting;
pub mod macros;
pub mod model;
pub mod prepared;
pub mod preview;
pub mod profile;
pub mod program;
pub mod protocol;
pub mod queries;
pub mod query_session;
pub mod readback;
pub mod sensitivity_block;
pub mod sensitivity_body;
pub mod settings;
pub mod shooting_runtime;
pub mod transport;
pub mod tui;
pub mod workflow;
