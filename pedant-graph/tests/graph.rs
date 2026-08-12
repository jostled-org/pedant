//! The public boundary of `pedant-graph`.
//!
//! Testing this crate as an external consumer from `pedant-core` would create a
//! dependency cycle, and another crate's root would not exercise the published
//! graph API, so the crate owns one integration executable.
//!
//! Every registered `#[test]` lives here with its bare libtest identity;
//! `graph_support` owns fixtures, cases, assertions, and source scanners and
//! declares no test of its own. The `#[path]` is required: default resolution
//! would place the tree in `tests/graph/`, which pedant's
//! `conflicting-module-root` rule rejects beside `graph.rs`, and folding the
//! root into `graph/mod.rs` would stop cargo building this executable.
#[path = "graph_support/mod.rs"]
mod graph_support;

use graph_support::{contract, defensive, evidence, isolation, ownership, topology, wire};

#[test]
fn graph_public_reading_surface_is_complete() {
    contract::assert_reading_surface_is_complete();
}

#[test]
fn graph_public_identity_defaults_and_schema_are_exact() {
    contract::assert_identity_defaults_and_schema();
}

#[test]
fn graph_public_lifecycle_surface_is_closed() {
    ownership::assert_lifecycle_surface_is_closed();
}

#[test]
fn graph_ids_languages_and_limits_are_dense_checked_and_atomic() {
    contract::assert_dense_checked_and_atomic();
}

#[test]
fn graph_projection_uses_only_supplied_resolution_facts() {
    ownership::assert_pure_projection_sources();
    ownership::assert_public_builders_delegate();
}

#[test]
fn graph_identity_checks_dominate_projection_state_construction() {
    ownership::assert_identity_checks_dominate();
}

#[test]
fn graph_id_capacity_uses_one_checked_insertion_owner() {
    ownership::assert_one_checked_insertion_owner();
}

#[test]
fn graph_defensive_error_paths_are_complete_and_wired() {
    ownership::assert_defensive_paths_are_wired();
}

#[test]
fn graph_defensive_malformed_inputs_return_exact_errors() {
    defensive::assert_malformed_joins_refuse();
}

#[test]
fn rust_graph_rejects_identity_mismatch_before_capacity_checks() {
    defensive::assert_identity_refusals_dominate();
}

#[test]
fn rust_graph_qualifies_unit_roots_and_shared_source_files() {
    topology::assert_unit_roots_and_shared_sources();
}

#[test]
fn rust_graph_maps_every_rust_symbol_kind_exactly_once() {
    topology::assert_symbol_kinds_map_once();
}

#[test]
fn rust_graph_containment_is_a_unit_local_forest() {
    topology::assert_containment_is_a_unit_local_forest();
}

#[test]
fn rust_graph_separates_logical_parentage_from_source_location() {
    topology::assert_parentage_is_separate_from_location();
}

#[test]
fn rust_graph_retains_enclosed_top_level_and_candidate_free_references() {
    evidence::assert_references_are_retained();
}

#[test]
fn rust_graph_edges_retain_candidate_certainty_and_evidence() {
    evidence::assert_candidate_edges_retain_evidence();
}

#[test]
fn rust_graph_maps_every_rust_reference_kind_exactly() {
    evidence::assert_reference_kinds_map_exactly();
}

#[test]
fn rust_graph_preserves_cargo_dependency_evidence() {
    evidence::assert_dependency_evidence_is_preserved();
}

#[test]
fn rust_graph_tiers_change_only_resolution_evidence() {
    wire::assert_tiers_change_only_evidence();
}

#[test]
fn rust_graph_json_v1_is_exact_compact_and_deterministic() {
    wire::assert_json_is_exact_and_deterministic();
}

#[test]
fn rust_graph_json_v1_covers_every_graph_owned_variant() {
    wire::assert_json_covers_every_variant();
}

#[test]
fn rust_graph_builds_and_serializes_after_fixture_teardown() {
    isolation::assert_projection_survives_teardown();
}
