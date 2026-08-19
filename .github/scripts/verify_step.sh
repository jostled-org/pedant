#!/usr/bin/env bash
# verify_step.sh — repository-owned per-step verification for pedant.
#
# Invoked by plan_loop.sh's `run_plan_loop_phase step` with these env vars:
#   PLAN_PATH                 — path to the plan file
#   PLAN_STEP                 — 1-indexed step number
#   PLAN_BASE_SHA             — commit SHA at plan start
#   PLAN_HEAD_SHA             — current commit SHA
#   CHANGED_FILES_PATH        — file listing paths changed since PLAN_BASE_SHA
#   PROOF_OUTPUT_DIR          — per-invocation directory for phase artifacts
#   PLAN_TEST_SCOPE           — verbatim `test_scope:` frontmatter entries joined
#                               with single spaces (empty when absent). Every
#                               entry names a Rust crate in the workspace; an
#                               unknown crate is a plan authoring bug (exit 64).
#   PLAN_ATTESTATION_BASELINE — pedant baseline attestation path
#   PLAN_ATTESTATION_CURRENT  — path the phase may write its current attestation to
#
# Set `VERIFY_STEP_LIST_ONLY=1` to print the route a plan and step select and
# run none of it. The listing is the route: every command is printed as
# `[verify_step] command: …` by the one function that would otherwise run it, so
# an operator reading a plan's matrix and the run executing it cannot disagree.
#
# Routing precedence:
#   0. `PLAN_PATH` resolves inside this repository to a plan with its own route
#      → that route, selected by the plan's repository-relative identity and
#      `PLAN_STEP`. A `PLAN_PATH` that names no file, or that resolves outside
#      the repository, is a plan/config error (exit 64) rather than a silent
#      fall-through to the generic route.
#   1. `PLAN_TEST_SCOPE` non-empty → fmt + clippy + test scoped to those crates.
#   2. `PLAN_TEST_SCOPE` empty but `CHANGED_FILES_PATH` shows Rust-relevant
#      changes → full workspace run.
#   3. Both empty (first step, or no diff yet) → full workspace run, so the plan
#      cannot slip a regression through by opening with a rename.
#   4. Scope empty and only non-Rust files changed (docs, plans) → nothing to
#      verify; exit 0.
#
# Commands mirror the [ci] identities in .manifest.toml, which in turn mirror
# .github/workflows/ci.yml. The root Cargo.toml is a virtual manifest, so bare
# `cargo clippy`/`cargo test` already cover every workspace member; neither
# `--workspace` nor `--all-targets` is added here. A step gate stricter than
# the freeze spends fix iterations on warnings CI would never enforce.
#
# Features: the generic route runs default features only. The `semantic` feature
# pulls the ra_ap_* tree, a ~10-minute build, so it runs solely in the [ci]
# matrix at the acceptance freeze. The accepted consequence: a step can pass here
# and the freeze's clippy_semantic / doc_semantic / test_configuration_2
# identities can still reject it. Semantic-only breakage therefore surfaces at
# closeout, not at the step that introduced it. A plan route states the feature
# profiles its own predicates need, because a plan whose contract is default-off
# has no other place to prove it.
#
# The lease is the manifest command's, not this script's: the outer wrapper
# serializes heavy builds and guards the volume reserve, and plan_loop hands
# each run an isolated per-RUN_ID CARGO_TARGET_DIR that cargo honors straight
# from the environment. Adding an inner lease here would deadlock against it.
#
# Cargo-output classification, the 75 status, and the aggregate-exit priority
# belong to cargo_infrastructure.sh, which the affected-workspace runner and the
# final-proof runner source too.
#
# Exit code: 0 = pass, 64 = plan/config error, 75 = infrastructure unavailable,
# other non-zero = verification failure.

set -uo pipefail

# `set -e` is deliberately off, so a failed `cd` here would leave `script_dir`
# empty, turn the `.` line into a silent no-op, and reduce `cargo_run` and its
# siblings to "command not found" — a step that verified nothing.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ]; then
    echo "ERROR: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh"

# `cd ""` succeeds and stays put, so an empty ROOT cannot be caught by the `cd`
# alone: the step would verify whatever workspace the caller stood in and report
# that as this plan's result. Prove the path before entering it.
ROOT="$(cd -- "${script_dir}/../.." && pwd)" || ROOT=""
if [ -z "${ROOT}" ] || ! cd -- "${ROOT}"; then
    echo "ERROR: cannot enter the repository root above ${script_dir}" >&2
    exit 75
fi

# `cargo_classify` reads its captures with ripgrep. Without rg it returns 127,
# the classifier's `if` reads false, and a full disk is reported as a code
# failure — the plan blamed for the machine.
for tool in cargo rg; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "ERROR: ${tool} is not on PATH — cannot verify a Rust workspace" >&2
        exit 75
    }
done

# The exact-test helper every plan route selects its predicates through.
EXACT_TEST="${ROOT}/.github/scripts/run_exact_rust_test.sh"

# The one plan whose steps carry their own verification matrix.
GO_PLAN_IDENTITY="docs/plans/go-graph-extraction.md"

# Rust-relevant path prefixes for the scope-empty fallback: every workspace
# member, the manifests that change resolution for all of them, and the config
# file whose precedence rules are themselves under test.
RUST_PATHS=(
    pedant/
    pedant-core/
    pedant-graph/
    pedant-lang/
    pedant-mcp/
    pedant-snippet/
    pedant-syntax/
    pedant-types/
    Cargo.toml
    Cargo.lock
    .pedant.toml
)

# ---------- one route command, listed and then run ----------

# Print one command of the selected route, and run it unless listing only.
#
# The listing and the run are one statement rather than two tables that can
# drift: a command an operator reads in the matrix is the argv this function
# hands to the classifier.
plan_command() {
    local label="$1"
    shift
    printf '[verify_step] command: %s\n' "$*"
    if [ -n "${VERIFY_STEP_LIST_ONLY:-}" ]; then
        return 0
    fi
    cargo_run "${label}" "$@"
}

# ---------- resolve the plan's repository-relative identity ----------

# The canonical repository-relative identity of PLAN_PATH, or empty when the
# caller supplied none.
#
# Both accepted spellings — an absolute path and a repository-relative one —
# must reach the same identity, or one plan would get two routes. The resolved
# path is proved to sit inside this repository before its identity is read: a
# plan outside the tree describes another repository's steps, and answering it
# with this repository's matrix would report a step as verified that nothing
# here ever ran.
plan_identity=""
if [ -n "${PLAN_PATH:-}" ]; then
    case "${PLAN_PATH}" in
        /*) plan_candidate="${PLAN_PATH}" ;;
        *) plan_candidate="${ROOT}/${PLAN_PATH}" ;;
    esac
    if [ ! -f "${plan_candidate}" ]; then
        echo "ERROR: PLAN_PATH names no file: ${PLAN_PATH}" >&2
        exit 64
    fi
    plan_dir="$(cd -- "$(dirname -- "${plan_candidate}")" && pwd -P)" || plan_dir=""
    root_real="$(cd -- "${ROOT}" && pwd -P)" || root_real=""
    if [ -z "${plan_dir}" ] || [ -z "${root_real}" ]; then
        echo "ERROR: cannot resolve PLAN_PATH against the repository root: ${PLAN_PATH}" >&2
        exit 64
    fi
    plan_real="${plan_dir}/$(basename -- "${plan_candidate}")"
    case "${plan_real}" in
        "${root_real}"/*) plan_identity="${plan_real#"${root_real}"/}" ;;
        *)
            echo "ERROR: PLAN_PATH resolves outside this repository: ${PLAN_PATH}" >&2
            exit 64
            ;;
    esac
fi

# ---------- the Go plan's per-step matrix ----------

# Every command one Go step verifies, one specification per line.
#
# `exact <package> <target> <profile> <predicate>` selects one registered test
# through the exact-test helper; `root <package> <target> <profile>` runs a whole
# integration root; `crate <package>` runs a package's whole test set; and
# `check <path>` runs one tracked repository check. The profile vocabulary is the
# helper's: `default`, `none`, or a feature list.
#
# A step this plan does not have returns 1, which the caller reports as a plan
# authoring error rather than routing to a generic run that proves none of the
# step's predicates.
go_route_specs() {
    local core_go="go-resolution,resolution-test-support"
    case "$1" in
        1)
            cat <<SPECS
exact pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
exact pedant-types serialization default legacy_rust_resolution_wire_bytes_stay_exact
exact pedant-core substrate default rust_resolution_rejects_go_only_kinds
root pedant-types serialization default
root pedant-core substrate default
root pedant-graph graph default
check .github/scripts/run_exact_rust_test_test.sh
check .github/scripts/verify_step_selftest.sh
SPECS
            ;;
        2)
            cat <<SPECS
exact pedant-syntax enclosing_unit ts-go go_file_facts_are_complete_ordered_and_source_bound
exact pedant-syntax enclosing_unit ts-go go_fact_limits_refuse_before_descent_or_insertion
exact pedant-syntax enclosing_unit rust,ts-go go_fact_limit_checks_dominate_descent_and_insertion
exact pedant-lang capability ts-go go_capability_output_and_recovery_are_byte_exact_after_fact_migration
exact pedant-lang capability none go_capability_without_grammar_retains_text_findings_and_unavailable_attribution
exact pedant-lang capability ts-go go_capability_uses_unbounded_compatibility_fact_limits
exact pedant-lang capability ts-go go_capability_and_resolution_share_one_fact_authority
exact pedant-lang capability ts-go go_capability_uses_one_parse_and_fact_inventory
root pedant-syntax enclosing_unit default
root pedant-syntax enclosing_unit none
root pedant-lang capability default
root pedant-lang capability none
SPECS
            ;;
        3)
            cat <<SPECS
exact pedant-core substrate ${core_go} go_module_directive_authority_and_precedence_are_exact
exact pedant-core substrate ${core_go} go_project_refuses_conflicts_missing_manifests_mismatches_and_root_escape
exact pedant-core substrate ${core_go} go_project_load_limits_refuse_every_first_excess
exact pedant-core substrate ${core_go} go_project_limit_checks_dominate_manifest_and_dependency_retention
exact pedant-core substrate ${core_go} go_project_and_snapshot_are_in_root_and_parse_only
root pedant-core substrate ${core_go}
root pedant-core substrate none
root pedant-core substrate default
SPECS
            ;;
        4)
            cat <<SPECS
exact pedant-core substrate ${core_go} go_snapshot_stores_each_source_and_fact_inventory_once
exact pedant-core substrate ${core_go} go_shared_source_has_one_store_entry_and_two_unit_instances
exact pedant-core substrate ${core_go} go_package_discovery_excludes_reserved_trees_and_retains_generated_go_sources
exact pedant-core substrate ${core_go} go_build_conditions_are_host_independent_possible_evidence
exact pedant-core substrate ${core_go} go_snapshot_and_resolver_read_no_host_selection_state
exact pedant-core substrate ${core_go} go_capability_fallback_and_snapshot_recovery_contract_is_exact
exact pedant-core substrate ${core_go} go_snapshot_limits_refuse_every_first_excess
exact pedant-core substrate ${core_go} go_snapshot_limit_checks_dominate_source_and_unit_retention
exact pedant-core substrate ${core_go} go_snapshot_fingerprint_covers_every_resolution_and_graph_claim
root pedant-core substrate ${core_go}
root pedant-syntax enclosing_unit default
root pedant-core substrate default
SPECS
            ;;
        5)
            cat <<SPECS
exact pedant-core substrate ${core_go} go_import_bindings_are_file_scoped_and_form_exact
exact pedant-core substrate ${core_go} go_lexical_shadowing_blocks_package_and_import_claims
exact pedant-core substrate ${core_go} go_function_calls_resolve_only_in_snapshot_targets
exact pedant-core substrate ${core_go} go_conversions_and_runtime_function_values_are_not_static_calls
exact pedant-core substrate ${core_go} go_concrete_method_sets_resolve_unique_and_promoted_receivers
exact pedant-core substrate ${core_go} go_project_resolution_validates_every_snapshot_binding_and_kind
exact pedant-core substrate ${core_go} go_resolution_limits_refuse_every_first_excess
exact pedant-core substrate ${core_go} go_resolution_limit_checks_dominate_candidate_retention
root pedant-core substrate ${core_go}
root pedant-types serialization default
root pedant-core substrate default
SPECS
            ;;
        6)
            cat <<SPECS
exact pedant-core substrate ${core_go} go_structural_implementations_require_complete_method_sets
exact pedant-core substrate ${core_go} go_interface_dispatch_is_always_possible
exact pedant-core substrate ${core_go} go_interface_incompleteness_keeps_bounded_gaps
exact pedant-core substrate ${core_go} go_interface_limit_checks_dominate_candidate_retention
exact pedant-core substrate ${core_go} go_interface_resolution_is_order_independent
root pedant-core substrate ${core_go}
root pedant-types serialization default
root pedant-core substrate default
SPECS
            ;;
        7)
            cat <<SPECS
exact pedant-graph graph default graph_projection_has_one_language_neutral_assembler
exact pedant-graph graph default rust_direct_and_cached_projection_bytes_stay_exact_after_neutral_assembly
exact pedant-graph graph default graph_cache_remains_rust_only_after_neutral_assembly
root pedant-graph graph default
root pedant-core substrate default
SPECS
            ;;
        8)
            cat <<SPECS
exact pedant-graph graph go go_graph_projects_one_package_and_definition_node_per_report_claim
exact pedant-graph graph go go_graph_containment_is_total_acyclic_and_relation_free
exact pedant-graph graph go go_shared_source_has_one_store_entry_and_two_unit_file_nodes
exact pedant-graph graph go go_graph_copies_every_reference_candidate_certainty_and_gap
exact pedant-graph graph go go_local_replacement_projects_one_resolved_dependency_edge
exact pedant-graph graph go go_graph_refuses_stale_resolution_before_allocation
exact pedant-graph graph go go_graph_limits_refuse_before_partial_records
exact pedant-graph graph go go_graph_validation_and_limits_dominate_draft_allocation
exact pedant-graph graph go go_graph_is_deterministic_and_rust_graph_bytes_stay_exact
exact pedant-graph graph go go_graph_uses_schema_v1_without_new_wire_branches
exact pedant-graph graph go go_graph_uses_existing_queries_and_rust_cache_answers_stay_exact
exact pedant-graph graph go go_and_rust_public_graph_api_shapes_are_parallel_and_language_specific
root pedant-graph graph go
root pedant-graph graph default
root pedant-core substrate ${core_go}
SPECS
            ;;
        9)
            cat <<SPECS
exact pedant-core substrate ${core_go} go_test_and_feature_ownership_is_exact
exact pedant-core substrate ${core_go} go_production_structure_and_error_ownership_are_exact
check .github/scripts/check_go_dependency_closure.sh
check .github/scripts/check_go_capabilities.sh
check .github/scripts/check_go_configurations.sh
check .github/scripts/run_shellcheck.sh
SPECS
            ;;
        10)
            cat <<SPECS
exact pedant-core substrate default published_versions_and_requirements_form_releaseable_graph
exact pedant-core substrate default go_release_and_archive_owners_are_exact
exact pedant supply_chain default packaged_workspace_go_dependency_order_models_release_protocol
crate pedant-types
crate pedant-syntax
crate pedant-core
crate pedant-graph
crate pedant-snippet
crate pedant-lang
crate pedant-mcp
crate pedant
SPECS
            ;;
        *) return 1 ;;
    esac
}

# Every package one step's specifications name, first appearance first.
#
# The lint gate is derived from the matrix rather than written down beside it,
# so a step that grows a package cannot keep an unlinted one.
go_route_packages() {
    local spec kind package seen=" "
    while IFS= read -r spec; do
        [ -n "${spec}" ] || continue
        kind="${spec%% *}"
        case "${kind}" in
            exact | root | crate) ;;
            *) continue ;;
        esac
        package="${spec#* }"
        package="${package%% *}"
        case "${seen}" in
            *" ${package} "*) continue ;;
        esac
        seen="${seen}${package} "
        printf '%s\n' "${package}"
    done <<< "$1"
}

# Run one step of the Go plan's matrix, listing every command it selects.
go_route() {
    local step="$1" specs packages package spec
    specs="$(go_route_specs "${step}")" || {
        echo "ERROR: ${GO_PLAN_IDENTITY} has no step ${step}" >&2
        echo "       Fix PLAN_STEP, or add the step's matrix to verify_step.sh." >&2
        exit 64
    }
    printf '[verify_step] plan: %s step %s route: go-graph-extraction\n' \
        "${GO_PLAN_IDENTITY}" "${step}"

    plan_command fmt cargo fmt --check
    packages="$(go_route_packages "${specs}")"
    while IFS= read -r package; do
        [ -n "${package}" ] || continue
        plan_command "clippy_${package}" cargo clippy -p "${package}" -- -D warnings
    done <<< "${packages}"

    while IFS= read -r spec; do
        [ -n "${spec}" ] || continue
        # Word splitting is the point: a specification is fixed, space-separated
        # fields, and none of them may contain a space.
        # shellcheck disable=SC2086
        set -- ${spec}
        case "$1" in
            exact) plan_command "exact_$2_$3_$5" "${EXACT_TEST}" "$2" "$3" "$4" "$5" ;;
            root)
                case "$4" in
                    default) plan_command "root_$2_$3" cargo test -p "$2" --test "$3" ;;
                    none)
                        plan_command "root_$2_$3_none" \
                            cargo test -p "$2" --test "$3" --no-default-features
                        ;;
                    *)
                        plan_command "root_$2_$3_$4" \
                            cargo test -p "$2" --test "$3" --no-default-features --features "$4"
                        ;;
                esac
                ;;
            crate) plan_command "test_$2" cargo test -p "$2" ;;
            check) plan_command "check_$(basename -- "$2")" "${ROOT}/$2" ;;
            *)
                echo "ERROR: ${GO_PLAN_IDENTITY} step ${step} states an unknown route entry: $1" >&2
                exit 64
                ;;
        esac
    done <<< "${specs}"

    exit "$(cargo_worst)"
}

if [ "${plan_identity}" = "${GO_PLAN_IDENTITY}" ]; then
    go_route "${PLAN_STEP:-}"
fi

# ---------- parse and validate PLAN_TEST_SCOPE ----------
scope_rust=()
if [ -n "${PLAN_TEST_SCOPE:-}" ]; then
    # Verbatim test_scope: entries joined by single spaces
    # (plan_loop_test_scope_raw in plan_loop_verification.sh). Word-split on
    # IFS whitespace.
    for entry in ${PLAN_TEST_SCOPE}; do
        scope_rust+=("$entry")
    done
fi
if [ ${#scope_rust[@]} -gt 0 ]; then
    missing=()
    for pkg in "${scope_rust[@]}"; do
        cargo pkgid -p "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: PLAN_TEST_SCOPE names unknown Rust crate(s): ${missing[*]}" >&2
        echo "       Fix the test_scope frontmatter in ${PLAN_PATH:-the plan file}." >&2
        exit 64
    fi
fi

# ---------- changed-files signal (scope-empty fallback) ----------
changed_rust=false
if [ -n "${CHANGED_FILES_PATH:-}" ] && [ -f "${CHANGED_FILES_PATH}" ]; then
    # `|| [ -n "$path" ]` keeps a final line that carries no trailing newline.
    # This loop is the only writer of `changed_rust`, so dropping that line
    # would route a one-entry unterminated list to "nothing to verify" and the
    # step would pass having compiled nothing.
    while IFS= read -r path || [ -n "$path" ]; do
        for prefix in "${RUST_PATHS[@]}"; do
            case "$path" in
                "$prefix"*) changed_rust=true ;;
            esac
        done
    done < "${CHANGED_FILES_PATH}"
fi

# ---------- routing ----------
if [ ${#scope_rust[@]} -eq 0 ]; then
    if [ "${PLAN_STEP:-1}" = "1" ] || [ ! -f "${CHANGED_FILES_PATH:-/nonexistent}" ] || [ "$changed_rust" = true ]; then
        printf '[verify_step] plan: %s step %s route: generic (workspace, no scope)\n' \
            "${plan_identity:-<unset>}" "${PLAN_STEP:-1}"
        plan_command fmt cargo fmt --check
        plan_command clippy cargo clippy -- -D warnings
        plan_command test cargo test
    else
        printf '[verify_step] plan: %s step %s route: generic (nothing to verify)\n' \
            "${plan_identity:-<unset>}" "${PLAN_STEP:-1}"
    fi
    exit "$(cargo_worst)"
fi

# ---------- scoped run ----------
printf '[verify_step] plan: %s step %s route: generic (scoped: %s)\n' \
    "${plan_identity:-<unset>}" "${PLAN_STEP:-1}" "${scope_rust[*]}"
# fmt --check does not build, so the workspace check is cheap and matches what
# the freeze runs; cargo fmt has no useful per-package scoping here.
plan_command fmt cargo fmt --check
for pkg in "${scope_rust[@]}"; do
    plan_command "clippy_${pkg}" cargo clippy -p "$pkg" -- -D warnings
    plan_command "test_${pkg}" cargo test -p "$pkg"
done

exit "$(cargo_worst)"
