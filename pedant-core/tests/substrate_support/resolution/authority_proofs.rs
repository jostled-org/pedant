//! The written-down model of the final-proof runner.
//!
//! Every inventory below is complete, not a sample. A sample would let a
//! predicate be deleted from the runner's array without failing anything: the
//! runner sizes its own pass bar from that array's length, so a shorter array
//! is a lower bar, and a model that only spot-checks nine names would agree
//! with the shortened runner. The comparison in [`super::authority_runner`] is
//! therefore an equality between this table and the arrays the script declares.

/// The final-proof runner, which this model reads as a text.
pub const PROOF_RUNNER: &str = "docs/scripts/run_resolution_proof.sh";

/// The seven modes it accepts, and no eighth.
pub const PROOF_MODES: &[&str] = &[
    "resolution-tier1",
    "resolution-tier2",
    "resolution-tier1-dependency-closure",
    "supply-chain-snapshot-reuse",
    "mcp-resolution-receipt",
    "resolution-authority-shape",
    "resolution-owner-registration",
];

/// The refusals this runner owns, beside the ones its shared library owns.
///
/// `cargo_capture`, `verify_registration`, `run_exact`, and
/// `run_registered_target` moved into `check_lib.sh` when the graph runner
/// began sharing them, and `graph_proof_model::PROOF_LIBRARY_REJECTIONS` states
/// the refusals that went with them. What stays here is what only this runner
/// does: the guarded set, the dependency capture, the receipt, and the dispatch.
///
/// The guarded-set rows model equality, not a floor: `cargo test --list` prints
/// an `#[ignore]`d test the same way it prints a live one, so a run that
/// registers every modelled predicate and then ignores two of them would
/// satisfy `passed -ge modelled` while proving two fewer. The three rows naming
/// summaries, passed/failed/ignored, and the graph's own content are what turn
/// "at least this much ran" into "exactly this ran".
pub const PROOF_REJECTIONS: &[&str] = &[
    "fewer than the ${modelled} modelled",
    "the registration list could not be counted, so nothing was proved",
    "the guarded set produced ${lines:-0} test summaries, not one",
    "${passed} passed, ${failed} failed and ${ignored} ignored",
    "names no pedant-core root, so nothing was inspected",
    "already exists, so it is not unique to this run",
    "the adapter wrote no receipt at",
    "is not one of the seven accepted modes",
];

/// Every shell scalar the runner must declare, with the exact value it holds.
///
/// A configuration is as much of the claim as the predicate is: the same test
/// name under `--features semantic` proves a different tree.
pub const PROOF_SCALARS: &[(&str, &str)] = &[
    (
        "TIER1_CONFIG",
        "-p pedant-core --no-default-features --features resolution-test-support --test substrate",
    ),
    (
        "TIER2_CONFIG",
        "-p pedant-core --no-default-features --features semantic,resolution-test-support --test substrate",
    ),
    (
        "AUTHORITY_PREDICATE",
        "resolution::authority::resolution_authority_shape_and_root_inventory_are_exact",
    ),
    (
        "TRACKED_AUTHORITY_PREDICATE",
        "resolution::authority::first_party_authorities_removed_names_and_migrated_cases_are_exact",
    ),
    (
        "SUPPLY_CHAIN_CONFIG",
        "-p pedant --features resolution-test-support --test supply_chain",
    ),
    (
        "SUPPLY_CHAIN_PREDICATE",
        "snapshot_capability_projection_reuses_stored_file_ir",
    ),
    (
        "COMPLETION_CONFIG",
        "-p pedant-mcp --features completion-proof-support --test integration",
    ),
    (
        "COMPLETION_PREDICATE",
        "completion_receipt_binds_typed_queries_to_final_tree",
    ),
];

/// The complete parse-only inventory, in the runner's declared order.
pub const TIER1_PREDICATES: &[&str] = &[
    "resolution::project::cargo_project_is_complete_unique_deterministic_and_versioned",
    "resolution::project::cargo_project_rejects_missing_inherited_and_invalid_versions",
    "resolution::project::workspace_member_cases_run_from_substrate_root",
    "resolution::project::testing_contract_tracks_exact_34_root_transition",
    "resolution::snapshot::snapshots_reject_invalid_target_authority_before_source_reads",
    "resolution::snapshot::target_snapshot_contains_only_root_target_module_closure",
    "resolution::snapshot::package_primary_snapshots_reject_invalid_package_authority_before_source_reads",
    "resolution::snapshot::package_primary_snapshot_reuses_one_store_across_target_views",
    "resolution::snapshot::package_primary_snapshot_refuses_a_later_incomplete_target",
    "resolution::snapshot::resolution_snapshot_selects_only_target_scoped_dependency_library_units",
    "resolution::snapshot::snapshots_accept_bare_callable_traits_only_for_legacy_editions",
    "resolution::selection_chain::branching_deep_selection_extends_once_per_edge_without_copying_history",
    "resolution::selection_chain::a_cycle_precedes_the_depth_refusal_and_keeps_ordered_evidence",
    "resolution::selection_chain::dependency_depth_accepts_the_ceiling_and_refuses_the_next_edge",
    "resolution::limits::project_and_snapshot_limits_report_each_owner",
    "resolution::limits::candidate_limit_is_typed_and_never_truncates",
    "resolution::syntactic::target_resolution_rejects_mapping_file_and_coordinate_mismatch",
    "resolution::syntactic::tier1_probe_reads_only_the_repository_and_invokes_no_process_path",
    "resolution::syntactic::tier1_parses_a_source_two_units_share_exactly_once",
    "resolution::syntactic::shared_semantic_source_warns_without_reducing_tier_one",
    "resolution::syntactic::cross_package_shared_source_warning_gives_valid_remediation",
    "resolution::syntactic::syntactic_resolution_gives_a_shared_source_one_identity_per_unit",
    "resolution::syntactic::syntactic_inventory_preserves_import_shape_scope_and_occurrence_identity",
    "resolution::syntactic::syntactic_resolution_resolves_each_supported_unique_target_kind",
    "resolution::syntactic::syntactic_resolution_propagates_every_cfg_owner_into_possible_candidates",
    "resolution::syntactic::resolution_json_is_byte_identical_after_enumeration_order_changes",
];

/// The complete set promotion adds, and all it may add.
pub const TIER2_PREDICATES: &[&str] = &[
    "resolution::semantic::semantic_resolution_changes_only_candidates_gaps_and_tier",
    "resolution::semantic::semantic_resolution_refuses_shared_physical_source_before_query",
    "resolution::semantic::semantic_resolution_returns_unit_qualified_definition_targets",
    "resolution::semantic::semantic_handshake_rejects_every_identity_mismatch_before_query",
    "resolution::semantic::semantic_resolution_reuses_verified_workspace_and_cached_file_setup",
    "resolution::semantic::semantic_handshake_reuses_retained_snapshot_fingerprint",
];

/// What the Tier 1 substrate configuration owns beside the resolution set.
///
/// Both authority cases are named. The committed-tree one runs in every
/// ordinary configuration, and a predicate no model names is a predicate a
/// later edit can delete with nothing turning red.
pub const SUBSTRATE_EXTRA_PREDICATES: &[&str] = &[
    "release_contract::published_versions_and_requirements_form_releaseable_graph",
    "release_contract::unpublished_dev_dependencies_never_become_registry_requirements",
    "release_contract::process_guard_windows_features_cover_job_creation_types",
    "release_contract::dependency_policy_allows_only_path_wildcards",
    "release_contract::verification_commands_are_build_lease_wrapped_and_classifier_backed",
    "release_contract::ci_installs_every_proof_runner_tool_before_execution",
    "release_contract::graph_release_and_verification_owners_are_exact",
    "resolution::authority::first_party_authorities_removed_names_and_migrated_cases_are_exact",
    "resolution::authority::resolution_authority_shape_and_root_inventory_are_exact",
];

/// One owner-registration row: a cargo configuration and every predicate the
/// runner must find registered exactly once under it.
pub struct RegistrationRow {
    /// The cargo arguments, before `-- --list`.
    pub config: &'static str,
    /// Every predicate that configuration owns, in the runner's order.
    pub predicates: &'static [&'static str],
}

/// The complete per-root registration table, matching the plan's inventory.
///
/// The three substrate/supply-chain configurations and the feature-gated
/// completion adapter are not rows here: the runner reaches them through the
/// scalars and arrays above, and duplicating them would let the two copies
/// disagree.
pub const REGISTRATION_ROWS: &[RegistrationRow] = &[
    RegistrationRow {
        config: "-p pedant-types --test serialization",
        predicates: &[
            "resolution_builder_rejects_every_same_index_foreign_handle_without_mutation",
            "resolution_handle_and_identifier_kinds_remain_nominally_distinct",
            "resolution_identifiers_keep_the_transparent_u32_wire_shape",
            "resolution_report_decode_limits_bound_every_top_level_collection",
            "resolution_report_decode_limits_preserve_default_and_valid_behavior",
            "resolution_report_bounded_decode_preserves_map_field_errors",
            "resolution_report_bounded_decode_ignores_hostile_sequence_size_hints",
            "resolution_builder_enforces_configured_and_id_ceiling_capacities_without_mutation",
            "resolution_report_validation_rejects_every_malformed_invariant_family",
            "resolution_report_enforces_unit_parent_candidate_and_certainty_rules",
            "rust_language_serializes_as_rust_and_resolution_records_use_it",
        ],
    },
    RegistrationRow {
        config: "-p pedant-syntax --features rust --test enclosing_unit",
        predicates: &["rust_language_conversion_preserves_existing_rust_extraction"],
    },
    RegistrationRow {
        config: "-p pedant-lang --test detection",
        predicates: &["rust_file_classification_remains_detection_exempt"],
    },
    RegistrationRow {
        config: "-p pedant-lang --test capability",
        predicates: &["direct_rust_analysis_returns_empty_profile"],
    },
    RegistrationRow {
        config: "-p pedant-snippet --test interfaces",
        predicates: &["rust_snippet_interfaces_remain_unchanged"],
    },
    RegistrationRow {
        config: "-p pedant-core --features semantic --test semantic",
        predicates: &[
            "test_call_graph_direct_call",
            "test_call_graph_no_calls",
            "test_semantic_public_queries_match_pre_cache_behavior",
            "test_semantic_file_analysis_public_queries_match_existing_behavior",
            "test_call_graph_and_reachability_reuse_cached_state",
        ],
    },
    RegistrationRow {
        config: "-p pedant --test supply_chain",
        predicates: &[
            "supply_chain_workspace_discovery_uses_project_members_and_validated_versions",
            "supply_chain_accepts_legacy_bare_callable_traits_without_moving_later_facts",
            "supply_chain_snapshot_journey_is_root_only_complete_and_failure_atomic",
            "supply_chain_process_guard_reaps_descendants_on_success_timeout_and_early_error",
            "supply_chain_ignores_invalid_fixture_rust_outside_workspace_targets",
            "supply_chain_init_and_verify_ignore_unselected_vendored_parse_failures",
            "supply_chain_upgrade_rejects_selected_parse_failure_without_baseline_mutation",
            "supply_chain_upgrade_preserves_msrv_context_on_selected_parse_failure",
        ],
    },
    RegistrationRow {
        config: "-p pedant-mcp --test index",
        predicates: &["mcp_project_discovery_uses_shared_members_and_preserves_recursive_index"],
    },
    RegistrationRow {
        config: "-p pedant-mcp --test watcher",
        predicates: &["mcp_watcher_cutover_preserves_incremental_reindex_and_removal"],
    },
    RegistrationRow {
        config: "-p pedant-mcp --test tools",
        predicates: &["rust_language_token_is_refused_without_tool_surface_change"],
    },
    RegistrationRow {
        config: "-p pedant-mcp --test integration",
        predicates: &[
            "completion_receipt_contract_rejects_missing_or_mismatched_fields",
            "mcp_stdio_receipt_round_trip_with_synthetic_identity",
            "mcp_stdio_guard_reaps_descendants_on_success_timeout_and_early_error",
        ],
    },
];
