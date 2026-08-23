//! Resolution-substrate cases declared by `tests/substrate.rs`.
//!
//! Each file below owns one resolution concern. The tree is declared with
//! `#[path]` from the root for the reason stated there: cargo builds one test
//! executable per `tests/*.rs`, so a support tree must not become a root.

// The `authority*` modules hold the committed source tree to its declared
// ownership model. `authority_asserts` is a different subject — refused target
// identities — and carries the feature because only the probe can construct
// one.
mod authority;
#[cfg(feature = "resolution-test-support")]
mod authority_asserts;
#[cfg(feature = "resolution-test-support")]
mod authority_invalidation;
mod authority_model;
// `read_text` is shared by the committed-tree authority and release checks.
pub(crate) mod authority_scan;
mod closure_asserts;
mod closure_fixtures;
mod fingerprint;
// The claim table and the cases that read it are split for the source-file
// budget alone, the way `closure_fixtures` sits beside `closure_asserts`.
#[cfg(feature = "resolution-test-support")]
mod fingerprint_claims;
mod fixture;
/// The Go module project cases, which name types only `go-resolution` compiles.
#[cfg(feature = "go-resolution")]
mod go;
mod inline_path_cases;
mod inline_path_fixtures;
mod limits;
mod project;
mod project_fixtures;
mod report_views;
pub(crate) mod root_inventory;
#[cfg(feature = "resolution-test-support")]
mod selection_chain;
#[cfg(feature = "resolution-test-support")]
mod selection_chain_fixtures;
#[cfg(feature = "semantic")]
mod semantic;
/// The handshake refusal table, which only the probe-gated handshake case
/// reads. It carries the same pair of gates as its one consumer, so a build
/// with `semantic` but no probe does not compile a table nothing runs.
#[cfg(all(feature = "semantic", feature = "resolution-test-support"))]
mod semantic_asserts;
#[cfg(feature = "semantic")]
mod semantic_expectations;
#[cfg(feature = "semantic")]
mod semantic_fixtures;
#[cfg(feature = "semantic")]
mod semantic_pairing;
mod snapshot;
mod syntactic;
mod syntactic_asserts;
mod syntactic_expectations;
mod syntactic_fixtures;
#[cfg(feature = "resolution-test-support")]
mod syntactic_probe;
mod unit_asserts;
mod unit_fixtures;
mod views;
