//! Resolution-substrate cases declared by `tests/substrate.rs`.
//!
//! Each file below owns one resolution concern. The tree is declared with
//! `#[path]` from the root for the reason stated there: cargo builds one test
//! executable per `tests/*.rs`, so a support tree must not become a root.

// The `authority*` modules are the indexed tree-shape proof, split by what a
// clone can read. `authority`, `authority_model`, and `authority_scan` index
// committed sources alone, so they compile everywhere and their case runs in
// the ordinary `[ci]` matrix — the only place a reintroduced identifier or a
// returned test root can fail before the freeze.
//
// `authority_acceptance`, `authority_documents`, `authority_keys`,
// `authority_proofs`, and `authority_runner` read `.manifest.toml`, the
// plan-loop scripts, and the spec/guide set — none of which a published
// checkout carries — and they panic rather than skip when one is missing.
// `resolution-test-support` is what keeps that panic out of the `[ci]` test
// matrix: no configuration there selects the feature, and
// `run_resolution_proof.sh` selects it for every mode that names them.
//
// `authority_asserts` is a different subject — refused target identities — and
// carries the feature because only the probe can construct one.
mod authority;
#[cfg(feature = "resolution-test-support")]
mod authority_acceptance;
#[cfg(feature = "resolution-test-support")]
mod authority_asserts;
#[cfg(feature = "resolution-test-support")]
mod authority_documents;
#[cfg(feature = "resolution-test-support")]
mod authority_invalidation;
#[cfg(feature = "resolution-test-support")]
mod authority_keys;
mod authority_model;
#[cfg(feature = "resolution-test-support")]
mod authority_proofs;
#[cfg(feature = "resolution-test-support")]
mod authority_runner;
mod authority_scan;
mod closure_asserts;
mod closure_fixtures;
mod fixture;
mod limits;
mod project;
mod project_fixtures;
mod report_views;
mod root_inventory;
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
