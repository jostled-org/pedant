//! What the Go work registered, written down.
//!
//! Every table here is stated rather than discovered. A predicate list taken
//! from the tree names whatever the tree happens to hold, so it could not reject
//! a case that was renamed out of its plan identity, one that was written twice
//! under two roots, or a feature configuration nothing runs. The comparison runs
//! both ways in [`super::registration`]: a modelled entry that is absent fails,
//! and a Go owner the model does not name fails the same assertion.

/// One registered predicate: the name a plan bullet states, and the tracked
/// file that declares it.
///
/// The file rather than only the root, because "this predicate is registered"
/// and "this predicate lives where its owner says" are two claims, and a case
/// that moved between support modules satisfies the first while breaking the
/// second.
pub const REGISTERED_PREDICATES: &[(&str, &str)] = &[
    // Step 1 — the shared report vocabulary.
    (
        "go_resolution_vocabulary_has_exact_wire_spellings",
        "pedant-types/tests/serialization.rs",
    ),
    (
        "rust_resolution_rejects_go_only_kinds",
        "pedant-core/tests/substrate_support/resolution/syntactic.rs",
    ),
    // Step 2 and Step 7 — the one Go fact inventory and its two consumers.
    (
        "go_file_facts_are_complete_ordered_and_source_bound",
        "pedant-syntax/tests/enclosing_unit_support/go_facts.rs",
    ),
    (
        "go_fact_limits_refuse_before_descent_or_insertion",
        "pedant-syntax/tests/enclosing_unit_support/go_fact_limits.rs",
    ),
    (
        "go_fact_limit_checks_dominate_descent_and_insertion",
        "pedant-syntax/tests/enclosing_unit_support/ownership/go_facts.rs",
    ),
    (
        "go_file_facts_state_every_written_type_and_initializer",
        "pedant-syntax/tests/enclosing_unit_support/go_type_facts.rs",
    ),
    (
        "go_capability_output_and_recovery_are_byte_exact_after_fact_migration",
        "pedant-lang/tests/capability_support/go_fact_cases.rs",
    ),
    (
        "go_capability_without_grammar_retains_text_findings_and_unavailable_attribution",
        "pedant-lang/tests/capability_support/go_fact_cases.rs",
    ),
    (
        "go_capability_uses_unbounded_compatibility_fact_limits",
        "pedant-lang/tests/capability_support/go_fact_cases.rs",
    ),
    (
        "go_capability_and_resolution_share_one_fact_authority",
        "pedant-lang/tests/capability_support/go_ownership.rs",
    ),
    (
        "go_capability_uses_one_parse_and_fact_inventory",
        "pedant-lang/tests/capability_support/go_ownership.rs",
    ),
    // Step 3 — bounded module project authority.
    (
        "go_module_directive_authority_and_precedence_are_exact",
        "pedant-core/tests/substrate_support/resolution/go/project.rs",
    ),
    (
        "go_project_refuses_conflicts_missing_manifests_mismatches_and_root_escape",
        "pedant-core/tests/substrate_support/resolution/go/refusal.rs",
    ),
    (
        "go_project_load_limits_refuse_every_first_excess",
        "pedant-core/tests/substrate_support/resolution/go/limits.rs",
    ),
    (
        "go_project_limit_checks_dominate_manifest_and_dependency_retention",
        "pedant-core/tests/substrate_support/resolution/go/ownership.rs",
    ),
    (
        "go_project_and_snapshot_are_in_root_and_parse_only",
        "pedant-core/tests/substrate_support/resolution/go/boundary.rs",
    ),
    // Step 4 — the host-independent package snapshot.
    (
        "go_snapshot_stores_each_source_and_fact_inventory_once",
        "pedant-core/tests/substrate_support/resolution/go/observation.rs",
    ),
    (
        "go_shared_source_has_one_store_entry_and_two_unit_instances",
        "pedant-core/tests/substrate_support/resolution/go/snapshot.rs",
    ),
    (
        "go_package_discovery_excludes_reserved_trees_and_retains_generated_go_sources",
        "pedant-core/tests/substrate_support/resolution/go/discovery.rs",
    ),
    (
        "go_build_conditions_are_host_independent_possible_evidence",
        "pedant-core/tests/substrate_support/resolution/go/conditions.rs",
    ),
    (
        "go_snapshot_and_resolver_read_no_host_selection_state",
        "pedant-core/tests/substrate_support/resolution/go/host_state.rs",
    ),
    (
        "go_capability_fallback_and_snapshot_recovery_contract_is_exact",
        "pedant-core/tests/substrate_support/resolution/go/recovery.rs",
    ),
    (
        "go_snapshot_limits_refuse_every_first_excess",
        "pedant-core/tests/substrate_support/resolution/go/snapshot_limits.rs",
    ),
    (
        "go_snapshot_limit_checks_dominate_source_and_unit_retention",
        "pedant-core/tests/substrate_support/resolution/go/snapshot_ownership.rs",
    ),
    (
        "go_snapshot_fingerprint_covers_every_resolution_and_graph_claim",
        "pedant-core/tests/substrate_support/resolution/go/snapshot_fingerprint.rs",
    ),
    // Steps 5 to 8 — scopes, calls, method sets, and the published wrapper.
    (
        "go_import_bindings_are_file_scoped_and_form_exact",
        "pedant-core/tests/substrate_support/resolution/go/resolution_imports.rs",
    ),
    (
        "go_lexical_shadowing_blocks_package_and_import_claims",
        "pedant-core/tests/substrate_support/resolution/go/resolution_scopes.rs",
    ),
    (
        "go_function_calls_resolve_only_in_snapshot_targets",
        "pedant-core/tests/substrate_support/resolution/go/resolution_calls.rs",
    ),
    (
        "go_conversions_and_runtime_function_values_are_not_static_calls",
        "pedant-core/tests/substrate_support/resolution/go/resolution_calls.rs",
    ),
    (
        "go_concrete_method_sets_resolve_unique_and_promoted_receivers",
        "pedant-core/tests/substrate_support/resolution/go/resolution_methods.rs",
    ),
    (
        "go_project_resolution_validates_every_snapshot_binding_and_kind",
        "pedant-core/tests/substrate_support/resolution/go/resolution_wrapper.rs",
    ),
    (
        "go_resolution_limits_refuse_every_first_excess",
        "pedant-core/tests/substrate_support/resolution/go/resolution_limits.rs",
    ),
    (
        "go_resolution_limit_checks_dominate_candidate_retention",
        "pedant-core/tests/substrate_support/resolution/go/resolution_ownership.rs",
    ),
    // Step 10 — structural interface resolution.
    (
        "go_structural_implementations_require_complete_method_sets",
        "pedant-core/tests/substrate_support/resolution/go/resolution_interfaces.rs",
    ),
    (
        "go_interface_dispatch_is_always_possible",
        "pedant-core/tests/substrate_support/resolution/go/resolution_interface_dispatch.rs",
    ),
    (
        "go_interface_incompleteness_keeps_bounded_gaps",
        "pedant-core/tests/substrate_support/resolution/go/resolution_interface_gaps.rs",
    ),
    (
        "go_interface_limit_checks_dominate_candidate_retention",
        "pedant-core/tests/substrate_support/resolution/go/resolution_interface_ownership.rs",
    ),
    (
        "go_interface_resolution_is_order_independent",
        "pedant-core/tests/substrate_support/resolution/go/resolution_interface_order.rs",
    ),
    // Step 12 — the snapshot-bound graph projection. Every graph predicate is
    // declared in the root itself, which is where that root keeps its cases.
    (
        "go_graph_projects_one_package_and_definition_node_per_report_claim",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_containment_is_total_acyclic_and_relation_free",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_shared_source_has_one_store_entry_and_two_unit_file_nodes",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_copies_every_reference_candidate_certainty_and_gap",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_local_replacement_projects_one_resolved_dependency_edge",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_refuses_stale_resolution_before_allocation",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_limits_refuse_before_partial_records",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_validation_and_limits_dominate_draft_allocation",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_is_deterministic_and_rust_graph_bytes_stay_exact",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_uses_schema_v1_without_new_wire_branches",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_graph_uses_existing_queries_and_rust_cache_answers_stay_exact",
        "pedant-graph/tests/graph.rs",
    ),
    (
        "go_and_rust_public_graph_api_shapes_are_parallel_and_language_specific",
        "pedant-graph/tests/graph.rs",
    ),
    // Step 13 — this step's own two claims.
    (
        "go_test_and_feature_ownership_is_exact",
        "pedant-core/tests/substrate_support/resolution/go/registration.rs",
    ),
    (
        "go_production_structure_and_error_ownership_are_exact",
        "pedant-core/tests/substrate_support/resolution/go/policy.rs",
    ),
];

/// One default-off feature and the exact set it selects.
pub struct FeatureEdge {
    /// The manifest that declares it.
    pub package: &'static str,
    /// The feature name.
    pub feature: &'static str,
    /// Everything the feature turns on, in manifest order.
    pub selects: &'static [&'static str],
}

/// The two Go features, and the only things they may select.
///
/// `pedant-graph/go` forwards to exactly one feature. A second entry here would
/// mean the graph adapter had learned to turn something else on, which is the
/// shape a `checks` or `semantic` edge would arrive in.
pub const GO_FEATURES: &[FeatureEdge] = &[
    FeatureEdge {
        package: "pedant-core",
        feature: "go-resolution",
        selects: &["dep:pedant-syntax"],
    },
    FeatureEdge {
        package: "pedant-graph",
        feature: "go",
        selects: &["pedant-core/go-resolution"],
    },
];

/// The one optional versioned edge `go-resolution` selects, and the grammar it
/// asks for.
pub const GO_GRAMMAR_EDGE: (&str, &str, &str) = ("pedant-core", "pedant-syntax", "ts-go");

/// Each tracked Go check: the `[ci]` identity that names it, and the script.
pub const GO_CHECKS: &[(&str, &str)] = &[
    (
        "go_dependency_closure",
        ".github/scripts/check_go_dependency_closure.sh",
    ),
    (
        "go_source_capabilities",
        ".github/scripts/check_go_capabilities.sh",
    ),
    (
        "go_configurations",
        ".github/scripts/check_go_configurations.sh",
    ),
];

/// Every cargo test configuration the matrix check must state, as the arguments
/// one row hands cargo.
///
/// Written here as well as in the check because they are two authorities: the
/// check runs the configurations, and this states which configurations exist. A
/// row deleted from the shell script would still run a clean matrix.
pub const GO_CONFIGURATIONS: &[(&str, &str)] = &[
    (
        "core-default-off",
        "-p pedant-core --no-default-features --test substrate",
    ),
    ("graph-default-off", "-p pedant-graph --test graph"),
    (
        "syntax-default-off",
        "-p pedant-syntax --no-default-features --test enclosing_unit",
    ),
    (
        "core-go-only",
        "-p pedant-core --no-default-features --features go-resolution --test substrate",
    ),
    (
        "core-go-and-probe",
        "-p pedant-core --no-default-features --features go-resolution,resolution-test-support --test substrate",
    ),
    (
        "graph-go-only",
        "-p pedant-graph --no-default-features --features go --test graph",
    ),
    (
        "syntax-go-only",
        "-p pedant-syntax --no-default-features --features ts-go --test enclosing_unit",
    ),
    (
        "lang-go-only",
        "-p pedant-lang --no-default-features --features ts-go --test capability",
    ),
    (
        "lang-default-off",
        "-p pedant-lang --no-default-features --test capability",
    ),
    (
        "graph-all-features",
        "-p pedant-graph --all-features --test graph",
    ),
    (
        "core-unified",
        "-p pedant-core --features go-resolution,resolution-test-support --test substrate",
    ),
    (
        "graph-core-go-without-adapter",
        "-p pedant-graph --no-default-features --features pedant-core/go-resolution --test graph",
    ),
];

/// The lint and documentation commands only the matrix check reaches.
pub const GO_LINT_COMMANDS: &[&str] = &[
    "cargo clippy --locked -p pedant-core --no-default-features --features go-resolution -- -D warnings",
    "cargo clippy --locked -p pedant-core --no-default-features --features go-resolution,resolution-test-support --all-targets -- -D warnings",
    "cargo clippy --locked -p pedant-graph --all-features --all-targets -- -D warnings",
    "cargo doc --locked --no-deps -p pedant-core --no-default-features --features go-resolution",
    "cargo doc --locked --no-deps -p pedant-graph --all-features",
];

/// The tracked documents each Go check must be registered in.
pub const CI_WORKFLOW: &str = ".github/workflows/ci.yml";
pub const SHELLCHECK_INVENTORY: &str = ".github/scripts/run_shellcheck.sh";
pub const MANIFEST: &str = ".manifest.toml";

/// The exact sentences the documentation contract holds each document to.
pub const DOCUMENTATION_CONTRACT: &[(&str, &str)] = &[
    (
        "docs/design-rationale.md",
        "GoFileFacts is the sole Go grammar inventory for capability attribution and Go resolution.",
    ),
    (
        "docs/testing.md",
        "Go graph tests extend existing roots and add no integration executable.",
    ),
    (
        "docs/internal/seamslike-integration-roadmap.md",
        "S8 is implemented through GoProject, GoResolver, and build_go_graph.",
    ),
];
