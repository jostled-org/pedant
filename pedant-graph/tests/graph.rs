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
    analysis_ownership, analysis_ownership_bounds, analysis_ownership_sharing, analysis_partition,
    analysis_selection, analysis_source_boundary, analysis_traversal, cache_analysis,
    cache_analysis_lifetime, cache_analysis_retention, cache_analysis_sharing, cache_exact,
    cache_ownership, cache_ownership_path, cache_ownership_state, cache_projection,
    cache_remapping, cache_revision, cache_source_boundary, contract, defensive, evidence,
    isolation, ownership, projection_exactness, projection_ownership, topology, wire,
};

#[test]
fn cached_graph_analysis_matches_every_direct_operation() {
    cache_analysis::assert_cached_analysis_matches_every_direct_operation();
}

#[test]
fn cached_graph_analysis_rechecks_every_limit_before_hits() {
    cache_analysis::assert_cached_analysis_rechecks_every_limit_before_hits();
}

#[test]
fn cached_graph_analysis_reuses_exact_arc_products_and_none() {
    cache_analysis_sharing::assert_cached_analysis_reuses_exact_arc_products_and_none();
}

#[test]
fn cached_graph_analysis_retention_is_bounded_lru() {
    cache_analysis_retention::assert_cached_analysis_retention_is_bounded_lru();
}

#[test]
fn graph_cache_clear_eviction_and_drop_keep_live_handles_valid() {
    cache_analysis_lifetime::assert_clear_eviction_and_drop_keep_live_handles_valid();
}

#[test]
fn cached_graph_analysis_is_thread_shareable_and_deterministic() {
    cache_analysis_lifetime::assert_cached_analysis_is_thread_shareable_and_deterministic();
}

#[test]
fn graph_cache_poison_recovery_is_explicit_and_total() {
    cache_ownership_state::assert_poison_recovery_is_explicit_and_total();
}

#[test]
fn graph_cache_counter_updates_are_saturating_and_single_owned() {
    cache_analysis_retention::assert_derived_counter_deltas_are_exact();
    cache_ownership_state::assert_counter_updates_are_saturating_and_single_owned();
}

#[test]
fn graph_cache_source_boundary_is_exact() {
    cache_source_boundary::assert_cache_source_boundary_is_exact();
}

#[test]
fn graph_cache_public_boundary_is_exact() {
    cache_ownership::assert_cache_public_boundary_is_exact();
}

#[test]
fn graph_cache_projection_has_one_planner_and_assembler() {
    cache_ownership_path::assert_projection_has_one_planner_and_assembler();
}

#[test]
fn graph_projection_has_one_language_neutral_assembler() {
    projection_ownership::assert_projection_has_one_language_neutral_assembler();
}

#[test]
fn rust_direct_and_cached_projection_bytes_stay_exact_after_neutral_assembly() {
    projection_exactness::assert_rust_projection_bytes_stay_exact();
}

#[test]
fn graph_cache_remains_rust_only_after_neutral_assembly() {
    projection_exactness::assert_cache_remains_rust_only();
}

#[test]
fn graph_cache_rejects_invalid_pairs_before_observation() {
    cache_exact::assert_invalid_pairs_are_refused_before_observation();
}

#[test]
fn graph_cache_exact_identity_guards_the_complete_resolution_claim() {
    cache_exact::assert_exact_identity_guards_the_claim();
}

#[test]
fn graph_cache_exact_hits_share_graph_and_short_circuit_work() {
    cache_exact::assert_exact_hits_share_graph_and_short_circuit();
}

#[test]
fn graph_cache_hits_reapply_graph_limits_in_direct_order() {
    cache_exact::assert_hits_reapply_graph_limits();
}

#[test]
fn graph_cache_exact_retention_is_bounded_lru() {
    cache_exact::assert_exact_retention_is_bounded_lru();
}

#[test]
fn graph_cache_exact_build_matches_direct_graph_and_json() {
    cache_exact::assert_exact_build_matches_direct();
}

#[test]
fn graph_cache_reuses_only_exact_source_unit_claims() {
    cache_projection::assert_reuses_only_exact_source_unit_claims();
    cache_projection::assert_reuse_is_decided_before_derivation();
}

#[test]
fn graph_cache_revision_matrix_matches_direct_graph_and_json() {
    cache_revision::assert_revision_matrix_matches_direct();
}

#[test]
fn graph_cache_tied_definition_identities_survive_dense_remapping() {
    cache_remapping::assert_tied_definitions_survive_remapping();
    cache_remapping::assert_retained_projections_hold_no_dense_identity();
}

#[test]
fn graph_cache_source_projection_retention_is_bounded_lru() {
    cache_projection::assert_source_projection_retention_is_bounded_lru();
}

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
    analysis_ownership_sharing::assert_traversal_consumes_shared_indexes();
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
    analysis_ownership_sharing::assert_metrics_and_components_consume_shared_indexes();
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
