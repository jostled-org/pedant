//! The indexed proof that the finished tree has the shape this plan claims.
//!
//! Two cases, split on one line: what a clone can read, and what only this
//! working copy holds.
//!
//! [`first_party_authorities_removed_names_and_migrated_cases_are_exact`] reads
//! committed sources alone, so it compiles in every configuration and runs in
//! the ordinary `[ci]` matrix. That is where a reintroduced
//! `resolve_workspace_members` or a returned `tests/workspace_members.rs` has
//! to fail: a proof of absence that only a feature nobody selects can run is a
//! proof nothing executes.
//!
//! [`resolution_authority_shape_and_root_inventory_are_exact`] states the whole
//! claim — those scans plus the manifest, proof-runner, and owner-document
//! tables — because a completion statement is only worth what its least-checked
//! half is. It indexes files a published checkout does not carry
//! (`.manifest.toml`, the plan-loop scripts, the specs and guides) and panics
//! rather than skips when one is missing, so a proof that ran on a clone would
//! fail for the absence of local tooling rather than for a regression.
//! `resolution-test-support` decides where it runs, never whether a missing
//! document reads as a satisfied clause. Local acceptance and
//! `run_resolution_proof.sh` execute the case. GitHub compiles the feature with
//! Clippy without executing this local-document case, and runs the
//! committed-tree companion through its ordinary test matrix.
//!
//! Everything either case compares comes from [`super::authority_model`],
//! [`super::authority_keys`], [`super::authority_documents`], and
//! [`super::authority_proofs`], which are written down. A discovered count
//! would agree with whatever the repository contains and could never reject a
//! regression.

#[cfg(feature = "resolution-test-support")]
use crate::resolution::authority_acceptance::{
    assert_ci_keys, assert_committed_ci_scripts, assert_resolution_check_coverage,
    assert_workflow_mirrors_manifest,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::authority_documents::assert_document_clauses;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::authority_runner::assert_proof_runner;
use crate::resolution::authority_scan::{
    assert_authorities, assert_migrated_predicates, assert_removed_authorities_are_absent,
    first_party_sources,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::root_inventory::assert_exact_integration_roots;

#[test]
fn first_party_authorities_removed_names_and_migrated_cases_are_exact() {
    let sources = first_party_sources();

    assert_authorities(sources);
    assert_removed_authorities_are_absent(sources);
    assert_migrated_predicates();
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn resolution_authority_shape_and_root_inventory_are_exact() {
    let sources = first_party_sources();

    assert_authorities(sources);
    assert_removed_authorities_are_absent(sources);
    assert_migrated_predicates();
    assert_ci_keys();
    assert_committed_ci_scripts();
    assert_workflow_mirrors_manifest();
    assert_resolution_check_coverage();
    assert_proof_runner();
    assert_document_clauses();
    assert_exact_integration_roots();
}
