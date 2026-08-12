#!/usr/bin/env bash
#
# run_resolution_proof.sh — the closed owner of the rust-symbol-resolution
# plan's final-tree proofs.
#
# Seven modes, no more. Each names a fixed inventory of fully qualified test
# predicates, obtains the registered list for its exact cargo configuration,
# requires every modelled predicate exactly once against a non-zero total, and
# only then executes them. The order matters: cargo reports success for a
# filter that selected nothing, so a proof that ran tests without first proving
# they exist would pass a tree in which they had been renamed away.
#
#   resolution-tier1                     parse-only resolver, no semantic build
#   resolution-tier2                     the same inventory plus promotion
#   resolution-tier1-dependency-closure  no rust-analyzer in the Tier 1 graph
#   supply-chain-snapshot-reuse          the child-written projection receipt
#   mcp-resolution-receipt               the final-tree completion receipt
#   resolution-authority-shape           the indexed authority/root proof
#   resolution-owner-registration        every owner, every configuration
#
# Environment: `PROOF_OUTPUT_DIR` is required and is the only directory this
# script writes to. The completion modes additionally require `PLAN_HEAD_SHA`,
# `PLAN_TEST_SCOPE`, and `PLAN_TERMINAL_SUMMARY`; a missing one is a failure,
# never a skip, because a receipt validated against absent identity proves
# nothing.
#
# The build lease and `CARGO_TARGET_DIR` belong to the caller. Cargo-output
# classification, the 75 infrastructure status, and the aggregate-exit priority
# belong to cargo_infrastructure.sh, which verify_step.sh and verify_affected.sh
# source too. The list-before-run machinery — `cargo_capture`,
# `verify_registration`, `run_exact`, `run_registered_target`, and their match
# counters — belongs to check_lib.sh, which run_graph_proof.sh reuses, and so do
# the rendered-root test and the closure forbid checks both runners apply to a
# `cargo tree` capture. Only the guarded-set and receipt rules below are this
# runner's own.
#
# Exit code: 0 = proved, 75 = infrastructure unavailable, 64 = unknown mode,
# other non-zero = the proof failed.

set -uo pipefail

# `set -e` is deliberately off, so a failed `cd` here would leave `script_dir`
# empty, turn both `.` lines into silent no-ops, and reduce every helper below
# to "command not found" — a proof that never ran, reported as a code failure.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=check_lib.sh
. "${script_dir}/check_lib.sh"

cd_repo_root
REPO_ROOT="$(pwd)"
# `sort` is named because the shared rust-analyzer report pipes to it. A tool a
# pipeline needs and the guard never demands yields an empty result on an image
# that lacks it, which is the one answer a forbid check must never read as clean.
require_tools cargo jq rg sort

# ---------------------------------------------------------------------------
# Fixed model
# ---------------------------------------------------------------------------

# The substrate configuration that compiles Tier 1 and its observation probe.
TIER1_CONFIG="-p pedant-core --no-default-features --features resolution-test-support --test substrate"

# The same substrate plus rust-analyzer promotion.
TIER2_CONFIG="-p pedant-core --no-default-features --features semantic,resolution-test-support --test substrate"

# The parse-only inventory. Tier 2 owes every one of these unchanged.
TIER1_PREDICATES=(
    resolution::project::cargo_project_is_complete_unique_deterministic_and_versioned
    resolution::project::cargo_project_rejects_missing_inherited_and_invalid_versions
    resolution::project::workspace_member_cases_run_from_substrate_root
    resolution::project::testing_contract_tracks_exact_34_root_transition
    resolution::snapshot::snapshots_reject_invalid_target_authority_before_source_reads
    resolution::snapshot::target_snapshot_contains_only_root_target_module_closure
    resolution::snapshot::package_primary_snapshots_reject_invalid_package_authority_before_source_reads
    resolution::snapshot::package_primary_snapshot_reuses_one_store_across_target_views
    resolution::snapshot::package_primary_snapshot_refuses_a_later_incomplete_target
    resolution::snapshot::resolution_snapshot_selects_only_target_scoped_dependency_library_units
    resolution::snapshot::snapshots_accept_bare_callable_traits_only_for_legacy_editions
    resolution::selection_chain::branching_deep_selection_extends_once_per_edge_without_copying_history
    resolution::selection_chain::a_cycle_precedes_the_depth_refusal_and_keeps_ordered_evidence
    resolution::selection_chain::dependency_depth_accepts_the_ceiling_and_refuses_the_next_edge
    resolution::limits::project_and_snapshot_limits_report_each_owner
    resolution::limits::candidate_limit_is_typed_and_never_truncates
    resolution::syntactic::target_resolution_rejects_mapping_file_and_coordinate_mismatch
    resolution::syntactic::tier1_probe_reads_only_the_repository_and_invokes_no_process_path
    resolution::syntactic::tier1_parses_a_source_two_units_share_exactly_once
    resolution::syntactic::shared_semantic_source_warns_without_reducing_tier_one
    resolution::syntactic::cross_package_shared_source_warning_gives_valid_remediation
    resolution::syntactic::syntactic_resolution_gives_a_shared_source_one_identity_per_unit
    resolution::syntactic::syntactic_inventory_preserves_import_shape_scope_and_occurrence_identity
    resolution::syntactic::syntactic_resolution_resolves_each_supported_unique_target_kind
    resolution::syntactic::syntactic_resolution_propagates_every_cfg_owner_into_possible_candidates
    resolution::syntactic::resolution_json_is_byte_identical_after_enumeration_order_changes
)

# What promotion adds, and all it may add.
TIER2_PREDICATES=(
    resolution::semantic::semantic_resolution_changes_only_candidates_gaps_and_tier
    resolution::semantic::semantic_resolution_refuses_shared_physical_source_before_query
    resolution::semantic::semantic_resolution_returns_unit_qualified_definition_targets
    resolution::semantic::semantic_handshake_rejects_every_identity_mismatch_before_query
    resolution::semantic::semantic_resolution_reuses_verified_workspace_and_cached_file_setup
    resolution::semantic::semantic_handshake_reuses_retained_snapshot_fingerprint
)

# The indexed authority proof.
AUTHORITY_PREDICATE="resolution::authority::resolution_authority_shape_and_root_inventory_are_exact"

# Its committed-tree half, which every ordinary configuration compiles and the
# `[ci]` matrix therefore runs.
TRACKED_AUTHORITY_PREDICATE="resolution::authority::first_party_authorities_removed_names_and_migrated_cases_are_exact"

# The child-written projection receipt.
SUPPLY_CHAIN_CONFIG="-p pedant --features resolution-test-support --test supply_chain"
SUPPLY_CHAIN_PREDICATE="snapshot_capability_projection_reuses_stored_file_ir"

# The final-tree completion adapter, and the only configuration that compiles it.
COMPLETION_CONFIG="-p pedant-mcp --features completion-proof-support --test integration"
COMPLETION_PREDICATE="completion_receipt_binds_typed_queries_to_final_tree"

# The typed queries a completion receipt must carry for every package in scope.
COMPLETION_TOOLS='["query_capabilities","query_gate_verdicts","query_violations"]'

# Every owner, in its own configuration: `<cargo arguments>|<predicates>`.
# Broad cargo success cannot substitute for a name being registered here.
REGISTRATION_ROWS=(
    "-p pedant-types --test serialization|resolution_builder_rejects_every_same_index_foreign_handle_without_mutation resolution_handle_and_identifier_kinds_remain_nominally_distinct resolution_identifiers_keep_the_transparent_u32_wire_shape resolution_report_decode_limits_bound_every_top_level_collection resolution_report_decode_limits_preserve_default_and_valid_behavior resolution_report_bounded_decode_preserves_map_field_errors resolution_report_bounded_decode_ignores_hostile_sequence_size_hints resolution_builder_enforces_configured_and_id_ceiling_capacities_without_mutation resolution_report_validation_rejects_every_malformed_invariant_family resolution_report_enforces_unit_parent_candidate_and_certainty_rules rust_language_serializes_as_rust_and_resolution_records_use_it"
    "-p pedant-syntax --features rust --test enclosing_unit|rust_language_conversion_preserves_existing_rust_extraction"
    "-p pedant-lang --test detection|rust_file_classification_remains_detection_exempt"
    "-p pedant-lang --test capability|direct_rust_analysis_returns_empty_profile"
    "-p pedant-snippet --test interfaces|rust_snippet_interfaces_remain_unchanged"
    "-p pedant-core --features semantic --test semantic|test_call_graph_direct_call test_call_graph_no_calls test_semantic_public_queries_match_pre_cache_behavior test_semantic_file_analysis_public_queries_match_existing_behavior test_call_graph_and_reachability_reuse_cached_state"
    "-p pedant --test supply_chain|supply_chain_workspace_discovery_uses_project_members_and_validated_versions supply_chain_accepts_legacy_bare_callable_traits_without_moving_later_facts supply_chain_snapshot_journey_is_root_only_complete_and_failure_atomic supply_chain_process_guard_reaps_descendants_on_success_timeout_and_early_error supply_chain_ignores_invalid_fixture_rust_outside_workspace_targets supply_chain_init_and_verify_ignore_unselected_vendored_parse_failures supply_chain_upgrade_rejects_selected_parse_failure_without_baseline_mutation supply_chain_upgrade_preserves_msrv_context_on_selected_parse_failure"
    "-p pedant-mcp --test index|mcp_project_discovery_uses_shared_members_and_preserves_recursive_index"
    "-p pedant-mcp --test watcher|mcp_watcher_cutover_preserves_incremental_reindex_and_removal"
    "-p pedant-mcp --test tools|rust_language_token_is_refused_without_tool_surface_change"
    "-p pedant-mcp --test integration|completion_receipt_contract_rejects_missing_or_mismatched_fields mcp_stdio_receipt_round_trip_with_synthetic_identity mcp_stdio_guard_reaps_descendants_on_success_timeout_and_early_error"
)

# The release and authority predicates the Tier 1 substrate configuration owns
# alongside the resolution inventory.
SUBSTRATE_EXTRA_PREDICATES=(
    release_contract::published_versions_and_requirements_form_releaseable_graph
    release_contract::unpublished_dev_dependencies_never_become_registry_requirements
    release_contract::process_guard_windows_features_cover_job_creation_types
    release_contract::dependency_policy_allows_only_path_wildcards
    release_contract::verification_commands_are_build_lease_wrapped_and_classifier_backed
    release_contract::ci_installs_every_proof_runner_tool_before_execution
    release_contract::graph_release_and_verification_owners_are_exact
    "${TRACKED_AUTHORITY_PREDICATE}"
    "${AUTHORITY_PREDICATE}"
)

# ---------------------------------------------------------------------------
# Output ownership
# ---------------------------------------------------------------------------

if [ -z "${PROOF_OUTPUT_DIR:-}" ] || [ ! -d "${PROOF_OUTPUT_DIR}" ]; then
    echo "error: PROOF_OUTPUT_DIR must name an existing directory" >&2
    exit 1
fi
PROOF_OUTPUT_DIR="$(cd -- "${PROOF_OUTPUT_DIR}" && pwd)" || {
    echo "error: cannot resolve PROOF_OUTPUT_DIR ${PROOF_OUTPUT_DIR}" >&2
    exit 75
}
export PROOF_OUTPUT_DIR
PROOF_WORK_DIR="${PROOF_OUTPUT_DIR}/resolution-proof"
mkdir -p "${PROOF_WORK_DIR}" || exit 75

# Fail unless every named variable holds a non-empty value.
require_env() {
    local name
    for name in "$@"; do
        if [ -z "${!name:-}" ]; then
            fail "${name} is not set, so the final tree is unproven" || return 1
        fi
    done
}

# Execute the whole guarded resolution set, once its registration is exact.
#
# `--list` prints an `#[ignore]`d test exactly the way it prints a runnable one,
# so the registration proof above cannot see an ignore. Only the run's own
# summary can, and only if it is read whole. A floor cannot: the filter selects
# more names than this script models, so under `passed -ge modelled` a modelled
# predicate could be ignored away and its unmodelled siblings would keep the
# count satisfied. So the summary must account for every `resolution::` name the
# same configuration registered — all passed, none failed, none ignored.
run_guarded_set() {
    local label="$1" config="$2" modelled="$3"
    local -a config_args
    read -r -a config_args <<< "${config}"

    if [ -z "${REGISTRATION_LIST_PATH}" ]; then
        fail "${label}: the guarded set has no registration list to be counted against"
        return 1
    fi
    # Unanchored, because cargo's filter is a substring match on the whole test
    # name: every line this counts is a line `resolution::` selects.
    local registered
    registered=$(match_count 'resolution::.*: test$' "${REGISTRATION_LIST_PATH}")
    if [ "${registered}" = "matcher-failed" ]; then
        fail "${label}: the registration list could not be counted, so nothing was proved"
        return 1
    fi
    if [ "${registered}" -lt "${modelled}" ]; then
        fail "${label}: ${registered} resolution:: names are registered, fewer than the ${modelled} modelled"
        return 1
    fi

    cargo_capture "set-${label}" cargo test "${config_args[@]}" resolution:: || return 1
    local summary lines passed failed ignored
    summary=$(rg --only-matching --replace '$1 $2 $3' \
        'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored' \
        "${CAPTURE_PATH}" 2>/dev/null)
    # Exactly one summary, or the numbers below describe one binary out of
    # several and the rest went uncounted.
    lines=$(printf '%s\n' "${summary}" | rg --count '^[0-9]+ [0-9]+ [0-9]+$' || true)
    if [ "${lines:-0}" != "1" ]; then
        fail "${label}: the guarded set produced ${lines:-0} test summaries, not one"
        return 1
    fi
    read -r passed failed ignored <<< "${summary}"
    if [ "${passed}" -ne "${registered}" ] || [ "${failed}" -ne 0 ] || [ "${ignored}" -ne 0 ]; then
        fail "${label}: the guarded set reported ${passed} passed, ${failed} failed and ${ignored} ignored against ${registered} registered resolution:: names"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

mode_tier1() {
    verify_registration tier1 "${TIER1_CONFIG}" "${TIER1_PREDICATES[@]}" || return 1
    run_guarded_set tier1 "${TIER1_CONFIG}" "${#TIER1_PREDICATES[@]}"
}

mode_tier2() {
    verify_registration tier2 "${TIER2_CONFIG}" \
        "${TIER1_PREDICATES[@]}" "${TIER2_PREDICATES[@]}" || return 1
    run_guarded_set tier2 "${TIER2_CONFIG}" \
        $((${#TIER1_PREDICATES[@]} + ${#TIER2_PREDICATES[@]}))
}

# Tier 1 states it has no rust-analyzer dependency. The normal graph is where
# that is decided: a dev or build edge would not link into the parse-only
# surface, and excluding them is what keeps the claim about Tier 1 rather than
# about the test harness around it.
mode_dependency_closure() {
    cargo_capture tier1-tree cargo tree -p pedant-core --no-default-features \
        --features resolution-test-support --edges normal --prefix none || return 1
    local tree="${CAPTURE_PATH}"
    # The capture holds cargo's stderr as well, so `Updating` and `Blocking`
    # progress lines alone make it non-empty. Emptiness therefore proves
    # nothing; the forbid grep below would match a graph nobody printed and
    # report the absence as a result. Name the root instead: `--prefix none`
    # prints it as `pedant-core v<version> (<path>)`, and if that line is
    # missing the graph was never rendered. `check_lib.sh` owns the test, which
    # `run_graph_proof.sh` makes about two roots of its own; the claim it proves
    # is this runner's, so this runner writes the refusal.
    if ! tree_names_root "${tree}" pedant-core; then
        fail "the Tier 1 dependency graph names no pedant-core root, so nothing was inspected"
        return 1
    fi
    # `check_lib.sh` owns both forbid checks. Reading ripgrep's output without
    # its status is what turned a broken matcher into a clean report here, and
    # one owner of that distinction serves both runners.
    assert_no_forbidden_packages tier1 "${tree}" line-index || return 1
    assert_no_rust_analyzer_edges tier1 "${tree}" || return 1
    echo "[run_resolution_proof] tier1 dependency closure: no ra_ap_* or line-index edge"
}

mode_supply_chain() {
    verify_registration supply-chain "${SUPPLY_CHAIN_CONFIG}" "${SUPPLY_CHAIN_PREDICATE}" || return 1
    run_exact supply-chain "${SUPPLY_CHAIN_CONFIG}" "${SUPPLY_CHAIN_PREDICATE}"
}

mode_authority() {
    verify_registration authority "${TIER1_CONFIG}" "${AUTHORITY_PREDICATE}" || return 1
    run_exact authority "${TIER1_CONFIG}" "${AUTHORITY_PREDICATE}"
}

mode_mcp() {
    verify_registration completion "${COMPLETION_CONFIG}" "${COMPLETION_PREDICATE}" || return 1
    completion_journey mcp
}

# Create a path no earlier run wrote, run the adapter against it, and hold the
# document it left to the identity this runner stated.
#
# The path is fresh on every call, so the owner-registration mode cannot pass on
# the receipt the MCP mode already validated.
completion_journey() {
    local label="$1"
    require_env PLAN_HEAD_SHA PLAN_TEST_SCOPE PLAN_TERMINAL_SUMMARY || return 1

    local receipt="${PROOF_WORK_DIR}/completion-receipt-${label}-$$-${RANDOM}.json"
    if [ -e "${receipt}" ]; then
        fail "${label}: ${receipt} already exists, so it is not unique to this run"
        return 1
    fi

    export PLAN_COMPLETION_RECEIPT="${receipt}"
    run_exact "completion-${label}" "${COMPLETION_CONFIG}" "${COMPLETION_PREDICATE}"
    local status=$?
    unset PLAN_COMPLETION_RECEIPT
    [ "${status}" -eq 0 ] || return 1

    validate_receipt "${label}" "${receipt}"
}

validate_receipt() {
    local label="$1" receipt="$2"
    if [ ! -f "${receipt}" ]; then
        fail "${label}: the adapter wrote no receipt at ${receipt}"
        return 1
    fi
    local document predicate
    document="$(cat "${receipt}")"
    # `$root`, `$head`, `$summary`, `$scope`, and `$tools` are jq variables the
    # `--arg` bindings below supply; the shell must not expand them.
    # shellcheck disable=SC2016
    predicate='
.receipt_version == 1
and .root == $root
and .head_sha == $head
and .terminal_summary == $summary
and .test_scope == ($scope | split(" "))
and (.queries | length) == (($scope | split(" ") | length) * ($tools | length))
and ([.queries[] | .package] == [$scope | split(" ") | .[] as $package | $tools[] | $package])
and ([.queries[] | .tool] == [$scope | split(" ") | .[] | $tools[]])
'
    assert_jq "${document}" "${predicate}" \
        --arg root "${REPO_ROOT}" \
        --arg head "${PLAN_HEAD_SHA}" \
        --arg summary "${PLAN_TERMINAL_SUMMARY}" \
        --arg scope "${PLAN_TEST_SCOPE}" \
        --argjson tools "${COMPLETION_TOOLS}" \
        -- \
        "error: ${label}: the completion receipt does not describe this tree." \
        "It must name ${REPO_ROOT}, HEAD ${PLAN_HEAD_SHA}, the exact package set" \
        "'${PLAN_TEST_SCOPE}', this run's terminal summary, and one record for" \
        "each of ${COMPLETION_TOOLS} per package." \
        "Receipt: ${receipt}"
    echo "[run_resolution_proof] ${label}: completion receipt validated at ${receipt}"
}

# Every owner, in its own configuration, listed then executed as part of its
# complete target. A target invocation is shared by its owners so semantic
# workspace setup is paid once rather than once per predicate.
mode_owner_registration() {
    local row config predicates index=0
    local -a predicate_list
    for row in "${REGISTRATION_ROWS[@]}"; do
        index=$((index + 1))
        config="${row%%|*}"
        predicates="${row#*|}"
        read -r -a predicate_list <<< "${predicates}"
        registration_row "row${index}" "${config}" "${predicate_list[@]}" || return 1
    done

    registration_row substrate-tier1 "${TIER1_CONFIG}" \
        "${TIER1_PREDICATES[@]}" "${SUBSTRATE_EXTRA_PREDICATES[@]}" || return 1
    registration_row substrate-tier2 "${TIER2_CONFIG}" \
        "${TIER2_PREDICATES[@]}" || return 1
    registration_row supply-chain "${SUPPLY_CHAIN_CONFIG}" \
        "${SUPPLY_CHAIN_PREDICATE}" || return 1

    verify_registration completion "${COMPLETION_CONFIG}" "${COMPLETION_PREDICATE}" \
        && completion_journey registration
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

case "${1:-}" in
    resolution-tier1) mode_tier1 ;;
    resolution-tier2) mode_tier2 ;;
    resolution-tier1-dependency-closure) mode_dependency_closure ;;
    supply-chain-snapshot-reuse) mode_supply_chain ;;
    mcp-resolution-receipt) mode_mcp ;;
    resolution-authority-shape) mode_authority ;;
    resolution-owner-registration) mode_owner_registration ;;
    *)
        echo "error: '${1:-}' is not one of the seven accepted modes:" >&2
        echo "  resolution-tier1 resolution-tier2 resolution-tier1-dependency-closure" >&2
        echo "  supply-chain-snapshot-reuse mcp-resolution-receipt" >&2
        echo "  resolution-authority-shape resolution-owner-registration" >&2
        exit 64
        ;;
esac

exit "$(cargo_worst)"
