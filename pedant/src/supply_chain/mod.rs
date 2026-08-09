//! Cargo supply-chain baselines: vendor, attest, compare, report.

mod attestation;
mod baseline;
mod capability_text;
mod commands;
mod compare;
mod completeness;
mod debug_output;
mod dir;
mod discovery;
mod error;
mod github_output;
#[cfg(feature = "resolution-test-support")]
mod receipt;
mod report;
mod selection;
mod source_input;
mod vendor;

pub(crate) use commands::{run_init, run_update, run_verify};
