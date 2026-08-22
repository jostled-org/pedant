#!/usr/bin/env bash
#
# verify_step_selftest.sh — the routing table for `verify_step.sh`.
#
# From Step 1 on, the manifest-supplied `[verification].step` phase is the
# indexed step authority for the Go plan: what a step verified is what its route
# ran, not what the executor said it ran. That makes the route selection itself
# a contract — a plan identity read loosely would give an unrelated plan the Go
# matrix, and an unknown step number that fell through to the generic route would
# report a step as verified having run none of its predicates.
#
# Every row below drives the real `verify_step.sh` in this repository. The
# listing rows use the script's own list-only mode, so no row compiles anything;
# the one execution row stubs `cargo` on `PATH` and proves an unavailable machine
# still leaves with 75. One trap removes the whole temporary tree.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || SCRIPT_DIR=""
if [ -z "${SCRIPT_DIR}" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi

ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)" || ROOT=""
if [ -z "${ROOT}" ]; then
    echo "error: cannot resolve the repository root above ${SCRIPT_DIR}" >&2
    exit 75
fi

VERIFIER="${SCRIPT_DIR}/verify_step.sh"
GO_PLAN="docs/plans/go-graph-extraction.md"
UNRELATED_PLAN="docs/plans/complete/analysis-surface-split.md"

for required in "${VERIFIER}" "${ROOT}/${GO_PLAN}" "${ROOT}/${UNRELATED_PLAN}"; do
    test -f "${required}" || {
        echo "error: ${required} is missing; the routing table cannot run" >&2
        exit 75
    }
done

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/verify-step-selftest.XXXXXX")" || exit 75
cleanup() { rm -rf -- "${TEST_ROOT}"; }
interrupted() { exit 130; }
trap cleanup EXIT
trap interrupted HUP INT TERM

failures=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# Run the verifier for one row and leave its status and output behind.
#
# `PLAN_TEST_SCOPE` is empty on every row, so the generic fallback rows exercise
# the routing this table is about rather than crate-scope validation.
ROW_STATUS=0
ROW_OUTPUT=""
run_verifier() {
    local plan="$1" step="$2"
    shift 2
    ROW_STATUS=0
    ROW_OUTPUT="$(
        cd -- "${ROOT}" || exit 75
        env "$@" \
            PLAN_PATH="${plan}" \
            PLAN_STEP="${step}" \
            PLAN_TEST_SCOPE="" \
            CHANGED_FILES_PATH="" \
            "${VERIFIER}" 2>&1
    )" || ROW_STATUS=$?
}

# Only the ordered command lines of one listing, which is what a route is.
commands_of() {
    printf '%s\n' "$1" | rg '^\[verify_step\] command: ' || true
}

test_every_go_step_lists_a_non_empty_matrix() {
    local step listing
    for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
        run_verifier "${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        [ "${ROW_STATUS}" -eq 0 ] \
            || fail "listing Go step ${step} must succeed, got ${ROW_STATUS}"
        case "${ROW_OUTPUT}" in
            *"route: go-graph-extraction"*) ;;
            *) fail "Go step ${step} must select the Go route" ;;
        esac
        listing="$(commands_of "${ROW_OUTPUT}")"
        [ -n "${listing}" ] || fail "Go step ${step} must list at least one command"
        case "${listing}" in
            *run_exact_rust_test.sh*) ;;
            *) fail "Go step ${step} must select its predicates through the exact helper" ;;
        esac
    done
}

test_absolute_and_relative_plan_paths_give_equal_matrices() {
    local step relative absolute
    for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
        run_verifier "${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        relative="$(commands_of "${ROW_OUTPUT}")"
        run_verifier "${ROOT}/${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        absolute="$(commands_of "${ROW_OUTPUT}")"
        [ "${relative}" = "${absolute}" ] \
            || fail "Go step ${step} must route equally for both in-repo path forms"
    done
}

test_step_one_lists_its_own_predicates() {
    run_verifier "${GO_PLAN}" 1 VERIFY_STEP_LIST_ONLY=1
    local listing
    listing="$(commands_of "${ROW_OUTPUT}")"
    for expected in \
        "pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings" \
        "pedant-types serialization default legacy_rust_resolution_wire_bytes_stay_exact" \
        "pedant-core substrate default rust_resolution_rejects_go_only_kinds"; do
        case "${listing}" in
            *"${expected}"*) ;;
            *) fail "Go step 1 must select ${expected}" ;;
        esac
    done
    case "${listing}" in
        *"cargo test -p pedant-types --test serialization"*) ;;
        *) fail "Go step 1 must also run its retained default-feature root" ;;
    esac
    case "${listing}" in
        *"cargo fmt --check"*) ;;
        *) fail "the Go route must keep the formatting gate the generic route runs" ;;
    esac
}

# Step 1 widens the shared vocabulary, so it edits the graph crate's exhaustive
# matches and refusals in the same step. The generic route it replaces compiled
# the whole workspace; a Go route that named only the two wire crates would be
# narrower than what it replaced, and the step would report as verified having
# never compiled the crate whose matches it changed.
test_step_one_covers_the_graph_crate_it_changes() {
    run_verifier "${GO_PLAN}" 1 VERIFY_STEP_LIST_ONLY=1
    local listing
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"cargo test -p pedant-graph --test graph"*) ;;
        *) fail "Go step 1 must run the graph root that carries its exhaustive-match proof" ;;
    esac
    case "${listing}" in
        *"cargo clippy -p pedant-graph"*) ;;
        *) fail "Go step 1 must lint the graph crate it changes" ;;
    esac
}

# 1.T4's harness selects every predicate Steps 2–14 name, so an unowned harness
# would leave the whole plan's selection layer unproven from Step 2 onward.
test_step_one_owns_the_exact_test_harness() {
    run_verifier "${GO_PLAN}" 1 VERIFY_STEP_LIST_ONLY=1
    case "$(commands_of "${ROW_OUTPUT}")" in
        *"run_exact_rust_test_test.sh"*) ;;
        *) fail "Go step 1 must run the exact-test helper's own harness" ;;
    esac
}

test_step_one_owns_the_repository_verifier_harness() {
    run_verifier "${GO_PLAN}" 1 VERIFY_STEP_LIST_ONLY=1
    case "$(commands_of "${ROW_OUTPUT}")" in
        *"verify_step_selftest.sh"*) ;;
        *) fail "Go step 1 must run the repository verifier's own harness" ;;
    esac
}

# Step 7 consumes the written type and initializer facts while resolving
# concrete receivers. The predicate that states that complete input must be
# selected exactly, not reached only as a side effect of the syntax root.
test_step_seven_owns_the_go_type_fact_contract() {
    run_verifier "${GO_PLAN}" 7 VERIFY_STEP_LIST_ONLY=1
    case "$(commands_of "${ROW_OUTPUT}")" in
        *"pedant-syntax enclosing_unit ts-go go_file_facts_state_every_written_type_and_initializer"*) ;;
        *) fail "Go step 7 must select the written type and initializer fact contract" ;;
    esac
}

# Step 9's semantic process journey exceeded the ordinary guard before its
# localized budget was introduced. The route must execute that exact predicate
# and its owning root under the semantic feature profile.
test_step_nine_owns_the_semantic_process_budget() {
    run_verifier "${GO_PLAN}" 9 VERIFY_STEP_LIST_ONLY=1
    local listing
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"pedant gate_cli semantic project_gate_semantic_is_single_context_all_target_or_error"*) ;;
        *) fail "Go step 9 must select the semantic process-budget predicate" ;;
    esac
    case "${listing}" in
        *"cargo test -p pedant --test gate_cli --no-default-features --features semantic"*) ;;
        *) fail "Go step 9 must run the semantic gate-CLI root" ;;
    esac
}

# The lint gate is derived from each step's specifications rather than written
# beside them. A derivation that dropped a package would leave a crate the step
# tests unlinted, which is the same silent narrowing by another route.
test_every_go_step_lints_every_package_it_tests() {
    local step listing line package
    for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
        run_verifier "${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        listing="$(commands_of "${ROW_OUTPUT}")"
        while IFS= read -r line; do
            [ -n "${line}" ] || continue
            package="${line##*cargo test -p }"
            package="${package%% *}"
            case "${listing}" in
                *"cargo clippy -p ${package} "*) ;;
                *) fail "Go step ${step} tests ${package} without linting it" ;;
            esac
        done <<< "$(printf '%s\n' "${listing}" | rg 'cargo test -p ' || true)"
    done
}

test_an_unrelated_valid_plan_keeps_generic_routing() {
    run_verifier "${UNRELATED_PLAN}" 1 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 0 ] \
        || fail "an unrelated valid plan must still route, got ${ROW_STATUS}"
    case "${ROW_OUTPUT}" in
        *"route: generic"*) ;;
        *) fail "an unrelated valid plan must keep the generic route" ;;
    esac
    case "$(commands_of "${ROW_OUTPUT}")" in
        *run_exact_rust_test.sh*) fail "an unrelated valid plan must select no Go predicate" ;;
    esac
}

test_an_unrelated_plan_at_a_high_step_still_routes() {
    run_verifier "${UNRELATED_PLAN}" 11 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 0 ] \
        || fail "step numbers are the Go plan's business alone, got ${ROW_STATUS}"
}

test_unknown_go_steps_fail_closed() {
    local step
    for step in 0 15 99 one ""; do
        run_verifier "${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        [ "${ROW_STATUS}" -eq 64 ] \
            || fail "Go step '${step}' is not a step of this plan and must fail 64, got ${ROW_STATUS}"
    done
}

test_a_missing_plan_path_fails_closed() {
    run_verifier "docs/plans/no-such-plan.md" 1 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 64 ] \
        || fail "a PLAN_PATH naming no file must fail 64, got ${ROW_STATUS}"
}

test_a_plan_path_outside_the_repository_fails_closed() {
    local outside="${TEST_ROOT}/outside/go-graph-extraction.md"
    mkdir -p -- "$(dirname -- "${outside}")" || return 1
    printf 'not this repository\n' > "${outside}"

    run_verifier "${outside}" 1 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 64 ] \
        || fail "an absolute PLAN_PATH outside the repository must fail 64, got ${ROW_STATUS}"

    local escape
    escape="$(printf '%s' "${outside}" | sed "s|^/|../../../../../../../../../../|")"
    run_verifier "${escape}" 1 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 64 ] \
        || fail "a relative PLAN_PATH climbing out of the repository must fail 64, got ${ROW_STATUS}"
}

# An unavailable machine reaches the route through the same classifier every
# other cargo caller uses, so the route must leave with 75 rather than reporting
# the plan as broken.
test_infrastructure_failure_leaves_with_75() {
    local bin="${TEST_ROOT}/bin"
    mkdir -p -- "${bin}" || return 1
    cat > "${bin}/cargo" <<'FAKE'
#!/usr/bin/env bash
echo "error: No space left on device (os error 28)" >&2
exit 1
FAKE
    chmod +x "${bin}/cargo" || return 1

    run_verifier "${GO_PLAN}" 1 "PATH=${bin}:${PATH}"
    [ "${ROW_STATUS}" -eq 75 ] \
        || fail "an unavailable machine must leave the Go route with 75, got ${ROW_STATUS}"
}

test_every_go_step_lists_a_non_empty_matrix
test_absolute_and_relative_plan_paths_give_equal_matrices
test_step_one_lists_its_own_predicates
test_step_one_covers_the_graph_crate_it_changes
test_step_one_owns_the_exact_test_harness
test_step_one_owns_the_repository_verifier_harness
test_step_seven_owns_the_go_type_fact_contract
test_step_nine_owns_the_semantic_process_budget
test_every_go_step_lints_every_package_it_tests
test_an_unrelated_valid_plan_keeps_generic_routing
test_an_unrelated_plan_at_a_high_step_still_routes
test_unknown_go_steps_fail_closed
test_a_missing_plan_path_fails_closed
test_a_plan_path_outside_the_repository_fails_closed
test_infrastructure_failure_leaves_with_75

if [ "${failures}" -ne 0 ]; then
    printf 'verify_step_selftest: %s row(s) failed\n' "${failures}" >&2
    exit 1
fi

printf 'verify_step_selftest: PASS\n'
