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

# The stand-in for every `PLAN_PATH` that is not the Go plan.
#
# `verify_step.sh` reads a plan's identity and never its contents, so the
# fixture only has to be a file this repository owns — and it must be one that
# exists by construction. An archive path under `docs/plans/complete/` is the
# wrong shape: plans move there and out of there as they are filed, so the day
# one is renamed this table stops running while reporting nothing about routing.
# This file cannot move without moving the table that reads it.
UNRELATED_PLAN=".github/scripts/verify_step_selftest.sh"

# A missing fixture is this table's own failure, not an unavailable machine.
# Reported as 75 it would come back to the Step 1 caller as "retry", and the
# caller would retry forever without the missing path ever being named.
for required in "${VERIFIER}" "${ROOT}/${GO_PLAN}" "${ROOT}/${UNRELATED_PLAN}"; do
    test -f "${required}" || {
        echo "error: ${required} is missing; the routing table cannot run" >&2
        exit 1
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

# Only the lines of a capture that match a pattern.
#
# `rg` exits 1 on no match, which is an empty listing rather than a failure, and
# it exits 2 or more when the matcher itself broke. Folding the second into the
# first would let a row report success having read nothing at all — and a broken
# matcher does not fix itself on a retry, so it leaves with 1 rather than 75.
matching_lines() {
    local capture="$1" pattern="$2" found rg_status=0
    found="$(rg -e "${pattern}" <<<"${capture}")" || rg_status=$?
    case "${rg_status}" in
        0) printf '%s\n' "${found}" ;;
        1) ;;
        *)
            echo "error: rg exited ${rg_status} without answering; the row did not run." >&2
            exit 1
            ;;
    esac
}

# Only the ordered command lines of one listing, which is what a route is.
commands_of() {
    matching_lines "$1" '^\[verify_step\] command: '
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
        *"cargo test --locked -p pedant-types --test serialization"*) ;;
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
        *"cargo test --locked -p pedant-graph --test graph"*) ;;
        *) fail "Go step 1 must run the graph root that carries its exhaustive-match proof" ;;
    esac
    case "${listing}" in
        *"cargo clippy --locked -p pedant-graph -- -D warnings"*) ;;
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
        *"cargo test --locked -p pedant --test gate_cli --no-default-features --features semantic"*) ;;
        *) fail "Go step 9 must run the semantic gate-CLI root" ;;
    esac
}

# The localized ceiling is reached through the shared guard, so Step 9 also
# edits that guard and the containment helper beneath it. Both other consumers
# of the guard prove the same containment claim, and the helper lives in a crate
# the workspace excludes: a route naming only the gate CLI would leave the step
# reporting as verified having never built either.
test_step_nine_covers_every_guard_surface_it_changes() {
    run_verifier "${GO_PLAN}" 9 VERIFY_STEP_LIST_ONLY=1
    local listing
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"pedant supply_chain default supply_chain_process_guard_reaps_descendants_on_success_timeout_and_early_error"*) ;;
        *) fail "Go step 9 must run the supply-chain guard row that shares its guard" ;;
    esac
    case "${listing}" in
        *"pedant-mcp integration default mcp_stdio_guard_reaps_descendants_on_success_timeout_and_early_error"*) ;;
        *) fail "Go step 9 must run the MCP guard row that proves the same containment claim" ;;
    esac
    case "${listing}" in
        *"cargo fmt --manifest-path test-support/process-guard/Cargo.toml --check"*) ;;
        *) fail "Go step 9 must format the workspace-excluded containment helper" ;;
    esac
    case "${listing}" in
        *"cargo clippy --locked --manifest-path test-support/process-guard/Cargo.toml --all-targets -- -D warnings"*) ;;
        *) fail "Go step 9 must lint the workspace-excluded containment helper" ;;
    esac
}

# Every `<package> <profile>` pair one listing compiles, one per line.
#
# A step exercises a package under a feature profile, not a package alone. Both
# spellings of a compile carry that pair: the exact helper takes it as its first
# and third arguments, and a whole-root or whole-crate run states it in cargo's
# own flags. Reading only the package would let a default-feature lint answer for
# a default-off adapter it never compiled.
compiled_pairs() {
    local listing="$1" line rest package profile
    while IFS= read -r line; do
        case "${line}" in
            *"run_exact_rust_test.sh "*)
                rest="${line##*run_exact_rust_test.sh }"
                # Word splitting is the point: the helper's arguments are fixed,
                # space-separated fields, and none of them may contain a space.
                # shellcheck disable=SC2086
                set -- ${rest}
                printf '%s %s\n' "$1" "$3"
                ;;
            *"cargo test --locked -p "*)
                rest="${line##*cargo test --locked -p }"
                package="${rest%% *}"
                profile=default
                case "${line}" in
                    *" --no-default-features --features "*)
                        profile="${line##* --features }"
                        profile="${profile%% *}"
                        ;;
                    *" --no-default-features"*) profile=none ;;
                esac
                printf '%s %s\n' "${package}" "${profile}"
                ;;
        esac
    done <<< "${listing}"
}

# The one clippy command a `<package> <profile>` pair is linted by.
#
# `semantic` maps back to `default` for the reason `verify_step.sh` gives: it
# pulls the ra_ap_* tree and a ~10-minute build, so it is linted at the
# acceptance freeze rather than at every step that names it.
clippy_command_for() {
    local package="$1" profile="$2"
    case "${profile}" in
        default | semantic)
            printf 'cargo clippy --locked -p %s -- -D warnings' "${package}"
            ;;
        none)
            printf 'cargo clippy --locked -p %s --no-default-features -- -D warnings' "${package}"
            ;;
        *)
            printf 'cargo clippy --locked -p %s --no-default-features --features %s -- -D warnings' \
                "${package}" "${profile}"
            ;;
    esac
}

# The lint gate is derived from each step's specifications rather than written
# beside them. A derivation that dropped a package would leave a crate the step
# tests unlinted, which is the same silent narrowing by another route.
#
# The profile is half of the pair, and the half that was missing. `pedant-graph`
# is default-off for `go` and `pedant-core` for `go-resolution`, so a gate keyed
# on the package alone lints the default build of both and compiles none of the
# Go adapter — from Step 3 through Step 12 the first clippy pass over the code a
# step introduced would have landed at Step 13.
test_every_go_step_lints_every_pair_it_compiles() {
    local step listing pairs pair expected
    for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
        run_verifier "${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        listing="$(commands_of "${ROW_OUTPUT}")"
        pairs="$(compiled_pairs "${listing}" | sort -u)"
        [ -n "${pairs}" ] \
            || fail "Go step ${step} must compile at least one package under one profile"
        while IFS= read -r pair; do
            [ -n "${pair}" ] || continue
            expected="$(clippy_command_for "${pair%% *}" "${pair#* }")"
            case "${listing}" in
                *"${expected}"*) ;;
                *) fail "Go step ${step} compiles '${pair}' without linting it: expected ${expected}" ;;
            esac
        done <<< "${pairs}"
    done
}

# The clippy gate must state the profile as well as the package. A gate that
# emitted the default build for a default-off feature would compile none of the
# adapter under test, and every row above would still pass.
test_the_lint_gate_states_the_go_feature_profiles() {
    local listing
    run_verifier "${GO_PLAN}" 12 VERIFY_STEP_LIST_ONLY=1
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"cargo clippy --locked -p pedant-graph --no-default-features --features go -- -D warnings"*) ;;
        *) fail "Go step 12 must lint the graph crate under the Go adapter feature" ;;
    esac

    run_verifier "${GO_PLAN}" 3 VERIFY_STEP_LIST_ONLY=1
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"cargo clippy --locked -p pedant-core --no-default-features --features go-resolution,resolution-test-support -- -D warnings"*) ;;
        *) fail "Go step 3 must lint the core crate under the Go resolution features" ;;
    esac
    case "${listing}" in
        *"cargo clippy --locked -p pedant-core --no-default-features -- -D warnings"*) ;;
        *) fail "Go step 3 must also lint the core crate with no feature at all" ;;
    esac
}

# The semantic carve-out the header states, kept where a reader can see it.
test_the_semantic_profile_is_linted_at_default_features() {
    local listing
    run_verifier "${GO_PLAN}" 9 VERIFY_STEP_LIST_ONLY=1
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"--features semantic -- -D warnings"*)
            fail "the semantic profile builds the ra_ap_* tree and is linted at the freeze, not here"
            ;;
    esac
    case "${listing}" in
        *"cargo clippy --locked -p pedant -- -D warnings"*) ;;
        *) fail "Go step 9 must still lint the CLI crate at default features" ;;
    esac
}

# A plan step that rewrote `Cargo.lock` while verifying would report the step
# verified against a resolution the plan never stated, and `verify_step.sh`
# already reads `Cargo.lock` as a change signal.
test_the_go_route_pins_the_lockfile() {
    local step listing line
    for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
        run_verifier "${GO_PLAN}" "${step}" VERIFY_STEP_LIST_ONLY=1
        listing="$(commands_of "${ROW_OUTPUT}")"
        while IFS= read -r line; do
            [ -n "${line}" ] || continue
            case "${line}" in
                *"cargo test --locked "* | *"cargo clippy --locked "*) ;;
                *) fail "Go step ${step} runs an unpinned build: ${line}" ;;
            esac
        done <<< "$(matching_lines "${listing}" 'cargo (test|clippy) ')"
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
    # A setup that failed silently would leave this row unrun and the file still
    # printing PASS: nothing reads a row's return value, so a refusal to set up
    # has to be recorded as a failure here.
    mkdir -p -- "$(dirname -- "${outside}")" || {
        fail "cannot open the out-of-repository fixture directory; the refusal row did not run"
        return 1
    }
    printf 'not this repository\n' > "${outside}" || {
        fail "cannot write the out-of-repository fixture; the refusal row did not run"
        return 1
    }

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
#
# This is the one row that executes a route instead of listing it, and it runs
# Step 5 for that reason. Step 1's matrix carries `check
# .github/scripts/verify_step_selftest.sh`, which the route runs — this file,
# executing itself, executing itself. Nothing but the order of Step 1's commands
# stands between that and a fork bomb: the fake below reclassifies the first
# command to 75 and leaves before the specification loop is reached, and any
# change to the fake's output, to the classifier table, or to the order of the
# matrix would remove that accident. Step 5 is two `exact` and two `root`
# specifications and no `check` at all, so the hazard is not there to remove.
test_infrastructure_failure_leaves_with_75() {
    local bin="${TEST_ROOT}/bin"
    mkdir -p -- "${bin}" || {
        fail "cannot open the fake tool directory; the 75-classification row did not run"
        return 1
    }
    cat > "${bin}/cargo" <<'FAKE'
#!/usr/bin/env bash
echo "error: No space left on device (os error 28)" >&2
exit 1
FAKE
    chmod +x "${bin}/cargo" || {
        fail "cannot install the fake cargo; the 75-classification row did not run"
        return 1
    }

    run_verifier "${GO_PLAN}" 5 "PATH=${bin}:${PATH}"
    [ "${ROW_STATUS}" -eq 75 ] \
        || fail "an unavailable machine must leave the Go route with 75, got ${ROW_STATUS}"
}

# The row above executes a route, so the step it executes must carry no `check`
# entry: a route that ran this file would run this row, which would run the
# route again. The listing is the route, so the claim is read from it.
test_the_executed_row_runs_a_step_that_re_enters_nothing() {
    run_verifier "${GO_PLAN}" 5 VERIFY_STEP_LIST_ONLY=1
    local listing
    listing="$(commands_of "${ROW_OUTPUT}")"
    [ -n "${listing}" ] || fail "Go step 5 must list the route the executed row runs"
    case "${listing}" in
        *verify_step_selftest.sh*)
            fail "Go step 5 runs this table, so the executed row would re-enter it without end"
            ;;
    esac
}

test_every_go_step_lists_a_non_empty_matrix
test_absolute_and_relative_plan_paths_give_equal_matrices
test_step_one_lists_its_own_predicates
test_step_one_covers_the_graph_crate_it_changes
test_step_one_owns_the_exact_test_harness
test_step_one_owns_the_repository_verifier_harness
test_step_seven_owns_the_go_type_fact_contract
test_step_nine_owns_the_semantic_process_budget
test_step_nine_covers_every_guard_surface_it_changes
test_every_go_step_lints_every_pair_it_compiles
test_the_lint_gate_states_the_go_feature_profiles
test_the_semantic_profile_is_linted_at_default_features
test_the_go_route_pins_the_lockfile
test_an_unrelated_valid_plan_keeps_generic_routing
test_an_unrelated_plan_at_a_high_step_still_routes
test_unknown_go_steps_fail_closed
test_a_missing_plan_path_fails_closed
test_a_plan_path_outside_the_repository_fails_closed
test_the_executed_row_runs_a_step_that_re_enters_nothing
test_infrastructure_failure_leaves_with_75

if [ "${failures}" -ne 0 ]; then
    printf 'verify_step_selftest: %s row(s) failed\n' "${failures}" >&2
    exit 1
fi

printf 'verify_step_selftest: PASS\n'
