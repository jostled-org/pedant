//! Go resolution-substrate cases declared by `tests/substrate.rs`.
//!
//! The whole tree compiles only with `go-resolution`, because every case names a
//! type that feature selects. It is declared with `#[path]` from the root for
//! the reason stated there: cargo builds one test executable per `tests/*.rs`,
//! so a support tree must not become a root.

mod fixture;
mod limits;
mod owners;
mod ownership;
mod project;
mod project_fixtures;
mod refusal;
mod scan;
mod views;

/// The observed half of the security boundary needs the production probe, which
/// only the proof feature compiles.
#[cfg(feature = "resolution-test-support")]
mod boundary;
