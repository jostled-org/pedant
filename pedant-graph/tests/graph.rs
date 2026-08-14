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

use graph_support::{
    analysis_centrality, analysis_components, analysis_derived_bounds,
    analysis_derived_determinism, analysis_determinism, analysis_divergence, analysis_layout,
    analysis_ownership, analysis_ownership_bounds, analysis_partition, analysis_selection,
    analysis_source_boundary, analysis_traversal, contract, defensive, evidence, isolation,
    ownership, topology, wire,
};

#[test]
fn graph_analysis_selection_is_explicit_and_shared() {
    analysis_selection::assert_selection_is_explicit_and_shared();
}

#[test]
fn graph_analysis_limits_refuse_before_work() {
    analysis_selection::assert_admission_limits_refuse();
    analysis_traversal::assert_query_limits_refuse();
}

#[test]
fn graph_analysis_limit_checks_dominate_allocations() {
    analysis_ownership_bounds::assert_analysis_limit_checks_dominate();
}

#[test]
fn graph_neighbors_are_bounded_directed_and_ordered() {
    analysis_traversal::assert_neighbors_are_bounded_directed_and_ordered();
}

#[test]
fn graph_path_is_shortest_directed_and_deterministic() {
    analysis_traversal::assert_path_is_shortest_directed_and_deterministic();
}

#[test]
fn graph_subgraph_is_exact_induced_selection() {
    analysis_traversal::assert_subgraph_is_exact_induced_selection();
}

#[test]
fn graph_declared_partition_follows_nearest_container() {
    analysis_partition::assert_partition_follows_nearest_container();
}

#[test]
fn graph_traversal_consumes_shared_analysis_indexes() {
    analysis_ownership_bounds::assert_traversal_consumes_shared_indexes();
}

#[test]
fn graph_analysis_public_boundary_is_exact() {
    analysis_ownership::assert_analysis_public_boundary_is_exact();
}

#[test]
fn graph_degree_and_betweenness_match_directed_oracles() {
    analysis_centrality::assert_degree_and_betweenness_match_oracles();
}

#[test]
fn graph_metric_selection_reuses_analysis_indexes() {
    analysis_centrality::assert_metric_selection_reuses_indexes();
    analysis_components::assert_component_selection_reuses_indexes();
}

#[test]
fn graph_betweenness_refuses_work_before_source_state() {
    analysis_centrality::assert_betweenness_refuses_work();
    analysis_ownership_bounds::assert_betweenness_work_checks_dominate();
}

#[test]
fn graph_components_and_condensation_are_exact() {
    analysis_components::assert_components_and_condensation_are_exact();
}

#[test]
fn graph_analysis_results_are_deterministic() {
    analysis_determinism::assert_analysis_results_are_deterministic();
}

#[test]
fn graph_traversal_and_components_are_iterative() {
    analysis_components::assert_traversal_and_components_are_iterative();
    analysis_ownership_bounds::assert_traversal_and_components_do_not_recurse();
}

#[test]
fn graph_metrics_and_components_consume_shared_indexes() {
    analysis_ownership_bounds::assert_metrics_and_components_consume_shared_indexes();
}

#[test]
fn graph_divergence_selection_reuses_analysis_indexes() {
    analysis_divergence::assert_divergence_selection_reuses_indexes();
    analysis_layout::assert_layout_selection_reuses_indexes();
}

#[test]
fn graph_divergence_matches_declared_partition_arithmetic() {
    analysis_divergence::assert_divergence_matches_declared_partition_arithmetic();
}

#[test]
fn graph_layout_assist_is_complete_and_coordinate_free() {
    analysis_layout::assert_layout_is_complete_and_coordinate_free();
}

#[test]
fn graph_divergence_and_layout_are_deterministic() {
    analysis_derived_determinism::assert_divergence_and_layout_are_deterministic();
}

#[test]
fn graph_derived_consumers_reuse_analysis_results() {
    analysis_derived_bounds::assert_derived_consumers_reuse_analysis_results();
}

#[test]
fn graph_analysis_source_boundary_is_exact() {
    analysis_source_boundary::assert_analysis_source_boundary_is_exact();
}

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
