#!/usr/bin/env bash
#
# run_graph_proof.sh — the closed owner of the code-structure-graph plan's
# repository-boundary proofs.
#
# Three modes, no more:
#
#   graph-dependency-closure   the production and test closures of pedant-graph
#   graph-source-capabilities  zero read, write, and spawn sites in its source
#   graph-owner-registration   every graph and core owner, every configuration
#
# Each mode refuses an empty result. A `cargo tree` that printed nothing, a
# capability scan of a tree nobody opened, and a test filter that selected no
# test all succeed on their own terms and say nothing, so every mode below
# proves its evidence exists before it reads that evidence for violations.
#
# Environment: `PROOF_OUTPUT_DIR` is optional. When it is set it must name an
# existing directory, and every command capture is written beneath it under a
# unique name. When it is unset this script creates one `mktemp -d` directory of
# its own and removes it on every exit. No mode writes inside the repository or
# chooses a Cargo target directory; the build lease and `CARGO_TARGET_DIR`
# belong to the caller.
#
# Cargo-output classification, the 75 infrastructure status, and the
# aggregate-exit priority belong to cargo_infrastructure.sh. check_lib.sh owns
# what more than one caller needs: the list-before-run registration machinery,
# the rendered-root test, and the closure assertions run_resolution_proof.sh
# shares; the Rust-source listing, sentinel mirror, reach predicate, and pedant
# command check_syntax_capabilities.sh shares; and the workspace member list
# both derived forbid sets come from. Cargo reports success for a filter that
# selected nothing and ripgrep reports a broken matcher the way a caller could
# read as "no match", so one owner of each guard is one place for it to stay
# strict.
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
require_tools cargo jq rg find mktemp dirname sort

# ---------------------------------------------------------------------------
# Fixed model
# ---------------------------------------------------------------------------

# The library closure. `--edges features` is what makes a feature edge visible
# at all, and separating this capture from the test one below is the whole
# point: dev-only feature unification would otherwise let the harness's
# `resolution-test-support` selection read as the library's own shape.
PRODUCTION_TREE_COMMAND="cargo tree -p pedant-graph --no-default-features --edges normal,build,features --prefix none"

# The same closure plus dev edges, which is what `cargo test -p pedant-graph`
# actually builds.
TEST_TREE_COMMAND="cargo tree -p pedant-graph --no-default-features --edges normal,build,dev,features --prefix none"

# Every pedant-core feature edge, whatever its name.
CORE_FEATURE_PATTERN='^pedant-core feature "'

# The one core feature the test closure may add, and the only one.
ALLOWED_TEST_CORE_FEATURE='pedant-core feature "resolution-test-support"'

# The workspace members either closure may reach. Every other member is
# forbidden, derived from `cargo metadata --no-deps` rather than restated.
#
# A hand-written forbid list is the wrong shape, and this one had already gone
# stale: it named four packages and omitted `pedant-lang`, `pedant-snippet`, and
# `pedant-syntax`, three members the graph must not reach and none of which any
# check here rejected. `check_syntax_dependency_closure.sh` derives its forbid
# set the same way and for the same reason, so a member added to this workspace
# is closed to the graph the day it joins.
GRAPH_CLOSURE_MEMBERS=(
    pedant-graph
    pedant-core
    pedant-types
)

# The forbidden packages no member list can supply. `line-index` is a crates.io
# package rust-analyzer pulls in, and the process guard is an unpublished
# path dependency outside this workspace, so neither appears in `.packages[]`.
FORBIDDEN_NON_MEMBERS=(
    line-index
    pedant-process-guard
)

# The derived set, resolved once per dependency-closure run.
FORBIDDEN_PACKAGES=()

# Feature edges neither closure may contain, under any package.
FORBIDDEN_FEATURES=(
    checks
    semantic
)

# The roots `--prefix none` prints for both captures. Naming them is what tells
# a rendered graph from a capture holding only cargo's progress lines.
GRAPH_TREE_ROOTS=(
    pedant-graph
    pedant-core
)

# The graph production source tree, and the only tree the capability mode reads.
GRAPH_SOURCE_TREE="pedant-graph/src"

# The graph must hold none of `check_lib.sh`'s `SENTINEL_CAPABILITIES`, network
# included: this is the crate whose whole point is that it opens nothing, and a
# `std::net::TcpStream::connect` in its source would otherwise pass. That list
# is also what the mirror proves pedant still detects, so the reach guard and
# the forbid half below range over one set rather than two.

# Every owner, in its own configuration: `<cargo arguments>|<predicates>`.
#
# One row per configuration, not one array of configurations beside one array of
# predicates. The pairing is the claim, and two declarations state both halves
# and bind them nowhere: the loop below would have been three hardcoded calls,
# and deleting one of them stopped a whole inventory being proved while both
# declarations survived and every model of them still passed. A row cannot be
# read without its configuration, and the loop cannot skip a row without losing
# the row.
#
# The lists are complete, not indicative: a mode that only spot-checked them
# would agree with a tree that had renamed the rest away.
#
# The second row's owners are the local-tooling ones. `.manifest.toml`, the
# plan-loop scripts, and the spec and guide set are not in a published checkout,
# and their readers panic rather than skip when one is missing, so
# `resolution-test-support` is what decides where they run — and why this mode
# is local acceptance rather than a CI step.
GRAPH_REGISTRATION_ROWS=(
    "-p pedant-core --no-default-features --test substrate|release_contract::published_versions_and_requirements_form_releaseable_graph resolution::fingerprint::snapshot_fingerprint_is_retained_and_redacted resolution::fingerprint::snapshot_fingerprint_production_claim_mapping_is_complete resolution::fingerprint::snapshot_fingerprint_has_one_production_hash_owner resolution::project::testing_contract_tracks_exact_34_root_transition"
    "-p pedant-core --no-default-features --features resolution-test-support --test substrate|release_contract::graph_release_and_verification_owners_are_exact release_contract::ci_installs_every_proof_runner_tool_before_execution resolution::authority::resolution_authority_shape_and_root_inventory_are_exact resolution::fingerprint::snapshot_fingerprint_covers_every_projection_claim"
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
# Dependency closure
# ---------------------------------------------------------------------------

mode_dependency_closure() {
    local production test_closure
    resolve_forbidden_packages || return 1

    capture_tree production "${PRODUCTION_TREE_COMMAND}" || return 1
    production="${CAPTURE_PATH}"
    capture_tree test "${TEST_TREE_COMMAND}" || return 1
    test_closure="${CAPTURE_PATH}"

    assert_tree_is_rendered production "${production}" || return 1
    assert_tree_is_rendered test "${test_closure}" || return 1

    assert_no_forbidden_edges production "${production}" || return 1
    assert_no_forbidden_edges test "${test_closure}" || return 1

    assert_production_core_features "${production}" || return 1
    assert_test_core_features "${test_closure}" || return 1

    echo "[run_graph_proof] graph dependency closure: production reaches pedant-core"
    echo "[run_graph_proof] with no feature; the test closure adds only" \
        "resolution-test-support"
}

capture_tree() {
    local label="$1" command="$2"
    local -a argv
    read -r -a argv <<< "${command}"
    cargo_capture "graph-${label}-tree" "${argv[@]}"
}

# Every workspace member the graph may not reach, plus the two non-members.
#
# Derived, never restated. `check_lib.sh` owns the reader, because a second
# reader of one `cargo metadata` document is a second place for it to be read
# under the wrong meaning. The result is asserted longer than the non-member
# list it starts from: a member list that failed to load, or that named only the
# three reachable members, would leave a forbid set that forbids nothing and
# every check below would report the emptiness as a clean closure.
resolve_forbidden_packages() {
    local listing package
    listing="$(workspace_members_excluding "${GRAPH_CLOSURE_MEMBERS[@]}")" || {
        fail "the workspace member list could not be read, so the forbid set is underived"
        return 1
    }
    FORBIDDEN_PACKAGES=("${FORBIDDEN_NON_MEMBERS[@]}")
    while IFS= read -r package; do
        [ -n "${package}" ] || continue
        FORBIDDEN_PACKAGES+=("${package}")
    done <<<"${listing}"
    if [ "${#FORBIDDEN_PACKAGES[@]}" -le "${#FORBIDDEN_NON_MEMBERS[@]}" ]; then
        fail "the member list forbids no workspace package, so the closure checks would constrain nothing"
        return 1
    fi
}

# Both roots are named, because a capture holds cargo's stderr too and its
# progress lines alone make it non-empty. `check_lib.sh` owns the test — both
# runners make it, and reading ripgrep's output without its status is what turns
# a broken matcher into a clean report — and this runner states which roots its
# own closures must render, and what their absence means.
assert_tree_is_rendered() {
    local label="$1" capture="$2" root
    for root in "${GRAPH_TREE_ROOTS[@]}"; do
        if ! tree_names_root "${capture}" "${root}"; then
            fail "${label}: the closure capture names no ${root} root, so nothing was inspected"
            return 1
        fi
    done
}

# The three forbid checks `check_lib.sh` owns, over this runner's own model.
assert_no_forbidden_edges() {
    local label="$1" capture="$2"
    assert_no_forbidden_packages "${label}" "${capture}" "${FORBIDDEN_PACKAGES[@]}" || return 1
    assert_no_forbidden_features "${label}" "${capture}" "${FORBIDDEN_FEATURES[@]}" || return 1
    assert_no_rust_analyzer_edges "${label}" "${capture}"
}

# The library resolves pedant-core with no feature at all.
assert_production_core_features() {
    local capture="$1" count
    count=$(match_count "${CORE_FEATURE_PATTERN}" "${capture}")
    case "${count}" in
        matcher-failed)
            fail "production: the pedant-core feature matcher failed, so the closure is unproven"
            return 1
            ;;
        0) ;;
        *)
            fail "production: the library closure enables ${count} pedant-core feature edges, not none"
            return 1
            ;;
    esac
}

# The harness adds exactly one, and it is the modelled one.
#
# Cargo prints an already-expanded subtree again with a `(*)` suffix, so the
# allowed line is matched with that suffix optional rather than counted once and
# assumed unique.
assert_test_core_features() {
    local capture="$1" total allowed
    total=$(match_count "${CORE_FEATURE_PATTERN}" "${capture}")
    allowed=$(match_count "^${ALLOWED_TEST_CORE_FEATURE}( \\(\\*\\))?\$" "${capture}")
    if [ "${total}" = "matcher-failed" ] || [ "${allowed}" = "matcher-failed" ]; then
        fail "test: the pedant-core feature matcher failed, so the closure is unproven"
        return 1
    fi
    if [ "${allowed}" -eq 0 ]; then
        fail "test: the dev closure never selects ${ALLOWED_TEST_CORE_FEATURE}, so this capture is not the graph's test graph"
        return 1
    fi
    if [ "${total}" != "${allowed}" ]; then
        fail "test: the dev closure enables ${total} pedant-core feature edges, and only the ${allowed} modelled ones are permitted"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Source capabilities
# ---------------------------------------------------------------------------

mode_source_capabilities() {
    local sources sentinels mirror reach profile

    if [ ! -d "${GRAPH_SOURCE_TREE}" ]; then
        fail "${GRAPH_SOURCE_TREE} is missing from the repository"
        return 1
    fi
    # `check_lib.sh` owns the listing and its count, because the sentinel mirror
    # this feeds is held to that count and `check_syntax_capabilities.sh` feeds
    # the same mirror from a listing of its own. Counting it here through a
    # ripgrep matcher read a broken matcher as a count of zero, and the refusal
    # below then stated that this repository holds no graph source.
    read_rust_sources "${GRAPH_SOURCE_TREE}" || {
        fail "cannot list the Rust sources under ${GRAPH_SOURCE_TREE}"
        return 1
    }
    sources="${RUST_SOURCE_LISTING}"
    sentinels="${RUST_SOURCE_COUNT}"
    if [ "${sentinels}" -eq 0 ]; then
        fail "${GRAPH_SOURCE_TREE} holds no Rust source, so a clean profile would constrain nothing"
        return 1
    fi

    # pedant is built before it is run, so an unavailable toolchain or a full
    # disk reaches the classifier as infrastructure rather than arriving as a
    # capability result nobody could produce.
    cargo_capture graph-pedant-build cargo build --quiet -p pedant || return 1

    mirror="$(mktemp -d)" || {
        fail "cannot create the sentinel mirror directory"
        return 1
    }
    owned_directories+=("${mirror}")
    mirror_sentinels "${mirror}" "${sources}" "${sentinels}" || {
        fail "the sentinel mirror of ${GRAPH_SOURCE_TREE} is incomplete"
        return 1
    }

    # The returning forms, not the exiting ones. Every other failure this runner
    # can reach is folded into one aggregate exit through `fail`, and a helper
    # that exits on its own leaves that aggregate unrecorded and the runner with
    # two failure protocols.
    scan_capabilities graph-mirror "${mirror}/${GRAPH_SOURCE_TREE}" || return 1
    reach="$(cat "${DOCUMENT_PATH}")"
    check_sentinel_reach "${reach}" "${sentinels}" "${GRAPH_SOURCE_TREE}" || {
        fail "the sentinel mirror of ${GRAPH_SOURCE_TREE} did not report every capability, so a clean profile would be vacuous"
        return 1
    }

    scan_capabilities graph-source "${GRAPH_SOURCE_TREE}" || return 1
    profile="$(cat "${DOCUMENT_PATH}")"
    # shellcheck disable=SC2016
    check_jq "${profile}" '
.findings as $findings
| $capabilities
| all(. as $capability
      | ([$findings[] | select(.capability == $capability)] | length) == 0)
' \
        --argjson capabilities "${SENTINEL_CAPABILITIES}" \
        -- \
        "error: ${GRAPH_SOURCE_TREE} reports a direct file-read, file-write," \
        "process-execution, or network site. Graph projection consumes already" \
        "validated in-memory facts and opens nothing." || {
        fail "${GRAPH_SOURCE_TREE} reports a forbidden capability site"
        return 1
    }

    echo "[run_graph_proof] graph source capabilities: ${sentinels} sources," \
        "no read, write, spawn, or connect site"
}

# Scan one tree's capabilities, leaving the profile at `DOCUMENT_PATH`.
#
# Every other cargo invocation here goes through the shared capture, and this
# one must too: a contended package-cache lock then reaches the classifier and
# returns 75 rather than arriving as an unparseable document, and the run leaves
# a capture under `PROOF_WORK_DIR` like every other command this script issues.
# `cargo_capture_document` keeps cargo's own messages out of the JSON, so a
# `Blocking waiting for file lock` line cannot corrupt it.
#
# The caller reads the document rather than this function printing it: a command
# substitution would run the capture in a subshell, where the recorded exit code
# dies with it and the replayed transcript would land in the caller's variable.
scan_capabilities() {
    local label="$1" tree="$2"
    cargo_capture_document "${label}-capabilities" \
        "${PEDANT_CAPABILITIES_COMMAND[@]}" "${tree}" || {
        fail "pedant could not scan ${tree}, so its capability profile is unproven"
        return 1
    }
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
# This mode is local acceptance, not a CI step. It runs the complete
# `resolution-test-support` substrate target, whose owners read `.manifest.toml`
# and the untracked guides, and those readers panic rather than skip on an
# absent path. `resolution-owner-registration` is local-only for the same
# reason.
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
