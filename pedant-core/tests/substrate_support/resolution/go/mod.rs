//! Go resolution-substrate cases declared by `tests/substrate.rs`.
//!
//! The whole tree compiles only with `go-resolution`, because every case names a
//! type that feature selects. It is declared with `#[path]` from the root for
//! the reason stated there: cargo builds one test executable per `tests/*.rs`,
//! so a support tree must not become a root.

mod conditions;
mod fixture;
mod host_state;
mod limits;
mod owners;
mod ownership;
mod policy;
mod policy_model;
mod project;
mod project_fixtures;
mod recovery;
mod refusal;
mod registration;
mod registration_model;
mod resolution_calls;
mod resolution_fixtures;
mod resolution_imports;
mod resolution_interface_dispatch;
mod resolution_interface_fixtures;
mod resolution_interface_gaps;
mod resolution_interface_order;
mod resolution_interface_ownership;
mod resolution_interfaces;
mod resolution_limits;
mod resolution_method_facts;
mod resolution_methods;
mod resolution_ownership;
mod resolution_refusal;
mod resolution_scopes;
mod resolution_views;
mod resolution_wrapper;
mod scan;
mod snapshot;
mod snapshot_fixtures;
mod snapshot_limits;
mod snapshot_ownership;
mod snapshot_reading;
mod snapshot_views;
mod support_trees;
mod surface;
mod views;

/// The observed half of the security boundary needs the production probe, which
/// only the proof feature compiles.
#[cfg(feature = "resolution-test-support")]
mod boundary;

/// The package walk's escape rows prove the sentinel outside the root was never
/// opened, which is an observation and needs the same probe.
#[cfg(feature = "resolution-test-support")]
mod discovery;

/// The observed source, parse, and fact-walk streams need the same probe.
#[cfg(feature = "resolution-test-support")]
mod observation;

/// The fingerprint coverage table and the case reading it need the proof-only
/// claim adapter.
#[cfg(feature = "resolution-test-support")]
mod snapshot_claims;
#[cfg(feature = "resolution-test-support")]
mod snapshot_fingerprint;
