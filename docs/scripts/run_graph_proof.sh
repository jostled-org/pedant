#!/usr/bin/env bash
#
# run_graph_proof.sh — local graph verification adapter.
#
# Three modes, no more:
#
#   graph-dependency-closure   the production and test closures of pedant-graph
#   graph-source-capabilities  zero read, write, and spawn sites in its source
#   graph-owner-registration   every graph and core owner, every configuration
#
# The first two modes capture the standalone repository checks that GitHub also
# executes. The third lists and runs a fixed test inventory for local lifecycle
# verification. Repository checks own their rules; this adapter does not copy
# them.
#
# Environment: `PROOF_OUTPUT_DIR` is optional. When it is set it must name an
# existing directory, and every command capture is written beneath it under a
# unique name. When it is unset this script creates one `mktemp -d` directory of
# its own and removes it on every exit. No mode writes inside the repository or
# chooses a Cargo target directory; the build lease and `CARGO_TARGET_DIR`
# belong to the caller.
#
# Cargo-output classification, infrastructure status 75, and aggregate-exit
# priority belong to cargo_infrastructure.sh. check_lib.sh owns capture and
# list-before-run registration for local orchestration.
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
require_tools cargo rg mktemp

# ---------------------------------------------------------------------------
# Fixed model
# ---------------------------------------------------------------------------
# The owner-registration inventory is local orchestration. The two repository
# checks below are standalone CI authorities and this runner delegates to them
# rather than restating their rules.
GRAPH_REGISTRATION_ROWS=(
    "-p pedant-core --no-default-features --test substrate|release_contract::published_versions_and_requirements_form_releaseable_graph resolution::fingerprint::snapshot_fingerprint_is_retained_and_redacted resolution::fingerprint::snapshot_fingerprint_production_claim_mapping_is_complete resolution::fingerprint::snapshot_fingerprint_has_one_production_hash_owner resolution::project::testing_contract_tracks_exact_34_root_transition"
    "-p pedant-core --no-default-features --features resolution-test-support --test substrate|resolution::fingerprint::snapshot_fingerprint_covers_every_projection_claim"
    "-p pedant-graph --test graph|graph_defensive_error_paths_are_complete_and_wired graph_defensive_malformed_inputs_return_exact_errors graph_id_capacity_uses_one_checked_insertion_owner graph_identity_checks_dominate_projection_state_construction graph_ids_languages_and_limits_are_dense_checked_and_atomic graph_projection_uses_only_supplied_resolution_facts graph_public_identity_defaults_and_schema_are_exact graph_public_lifecycle_surface_is_closed graph_public_reading_surface_is_complete rust_graph_builds_and_serializes_after_fixture_teardown rust_graph_containment_is_a_unit_local_forest rust_graph_edges_retain_candidate_certainty_and_evidence rust_graph_json_v1_covers_every_graph_owned_variant rust_graph_json_v1_is_exact_compact_and_deterministic rust_graph_maps_every_rust_reference_kind_exactly rust_graph_maps_every_rust_symbol_kind_exactly_once rust_graph_preserves_cargo_dependency_evidence rust_graph_qualifies_unit_roots_and_shared_source_files rust_graph_rejects_identity_mismatch_before_capacity_checks rust_graph_retains_enclosed_top_level_and_candidate_free_references rust_graph_separates_logical_parentage_from_source_location rust_graph_tiers_change_only_resolution_evidence"
)

# ---------------------------------------------------------------------------
# Output ownership
# ---------------------------------------------------------------------------

# Directories this run created and must remove, whatever exit path it takes.
# One trap and one list, because bash keeps one EXIT handler and a second
# `trap ... EXIT` would silently replace the first.
owned_directories=()

# Reached through the EXIT trap below rather than by a call site.
# shellcheck disable=SC2329
remove_owned_directories() {
    local directory
    for directory in ${owned_directories[@]+"${owned_directories[@]}"}; do
        rm -rf "${directory}"
    done
}
trap remove_owned_directories EXIT

if [ -n "${PROOF_OUTPUT_DIR:-}" ]; then
    if [ ! -d "${PROOF_OUTPUT_DIR}" ]; then
        echo "error: PROOF_OUTPUT_DIR is set but ${PROOF_OUTPUT_DIR} is not a directory" >&2
        exit 1
    fi
    resolved="$(cd -- "${PROOF_OUTPUT_DIR}" && pwd)" || resolved=""
    if [ -z "${resolved}" ]; then
        echo "error: cannot resolve PROOF_OUTPUT_DIR ${PROOF_OUTPUT_DIR}" >&2
        exit 75
    fi
    PROOF_WORK_DIR="${resolved}/graph-proof-$$"
    mkdir -p "${PROOF_WORK_DIR}" || exit 75
else
    PROOF_WORK_DIR="$(mktemp -d)" || exit 75
    owned_directories+=("${PROOF_WORK_DIR}")
fi

# ---------------------------------------------------------------------------
# Repository checks
# ---------------------------------------------------------------------------

mode_dependency_closure() {
    cargo_capture graph-dependency-closure \
        "${script_dir}/check_graph_dependency_closure.sh"
}

mode_source_capabilities() {
    cargo_capture graph-source-capabilities \
        "${script_dir}/check_graph_capabilities.sh"
}

# ---------------------------------------------------------------------------
# Owner registration
# ---------------------------------------------------------------------------

# Every owner, in its own configuration, listed then executed as part of its
# complete target.
#
# One loop over the rows, the shape `run_resolution_proof.sh` already uses. The
# three hardcoded calls this replaced were the only thing binding a
# configuration to its predicates, and nothing read those call sites: deleting
# one stopped twenty-two predicates being proved while both of its declarations
# stood and every model of them passed.
#
# This mode belongs to local orchestration and is not a CI step.
mode_owner_registration() {
    local row config predicates index=0
    local -a predicate_list
    for row in "${GRAPH_REGISTRATION_ROWS[@]}"; do
        index=$((index + 1))
        config="${row%%|*}"
        predicates="${row#*|}"
        read -r -a predicate_list <<< "${predicates}"
        registration_row "graph-row${index}" "${config}" "${predicate_list[@]}" || return 1
    done
    echo "[run_graph_proof] graph owner registration: every modelled predicate" \
        "listed once and observed passing once"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

case "${1:-}" in
    graph-dependency-closure) mode_dependency_closure ;;
    graph-source-capabilities) mode_source_capabilities ;;
    graph-owner-registration) mode_owner_registration ;;
    *)
        echo "error: '${1:-}' is not one of the three accepted modes:" >&2
        echo "  graph-dependency-closure graph-source-capabilities" >&2
        echo "  graph-owner-registration" >&2
        exit 64
        ;;
esac

exit "$(cargo_worst)"
