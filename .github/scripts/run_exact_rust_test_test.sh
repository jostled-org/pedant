#!/usr/bin/env bash
#
# run_exact_rust_test_test.sh — the selection and classification table for
# `run_exact_rust_test.sh`.
#
# The helper is the step-proof authority: every plan step selects its predicate
# through it, so a helper that selected two tests, selected none, dropped a
# feature profile, or reported an unavailable machine as a code failure would
# make every later receipt meaningless. Each row below drives the helper against
# a fake `cargo` whose list output, run output, and exit status the row states,
# and reads the argv the helper actually asked for.
#
# No row reaches a registry, a network, or a real compiler: the fake tool tree
# is the only `cargo` on `PATH` for the duration of a row, and the whole tree is
# removed by one trap.

set -uo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi

HELPER="${script_dir}/run_exact_rust_test.sh"

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/run-exact-rust-test.XXXXXX")" || exit 75
cleanup() { rm -rf -- "${TEST_ROOT}"; }
interrupted() { exit 130; }
trap cleanup EXIT
trap interrupted HUP INT TERM

failures=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# The fake tool tree one row runs the helper against.
#
# `cargo` is the only tool faked: the helper's own reader is ripgrep, and a row
# that faked that too would prove nothing about the classifier it feeds.
install_fake_cargo() {
    local bin="${TEST_ROOT}/bin"
    mkdir -p "${bin}" || return 1
    cat > "${bin}/cargo" <<'FAKE'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*" >> "${FAKE_CARGO_ARGV_LOG}"
for argument in "$@"; do
    if [ "${argument}" = "--list" ]; then
        printf '%s' "${FAKE_CARGO_LIST}"
        exit "${FAKE_CARGO_LIST_STATUS}"
    fi
done
printf '%s' "${FAKE_CARGO_RUN_OUTPUT}"
exit "${FAKE_CARGO_RUN_STATUS}"
FAKE
    chmod +x "${bin}/cargo" || return 1
    printf '%s\n' "${bin}"
}

FAKE_BIN="$(install_fake_cargo)" || {
    echo "error: cannot install the fake cargo" >&2
    exit 75
}

# Run the helper for one row and leave its status, output, and argv behind.
#
# The argv log is truncated per row, so a row reads only the invocations it
# caused. `PATH` is prefixed rather than replaced, because the helper's own
# ripgrep reader must stay resolvable.
ROW_STATUS=0
ROW_OUTPUT=""
ROW_ARGV=""
run_row() {
    local list="$1" list_status="$2" run_output="$3" run_status="$4"
    shift 4
    local log="${TEST_ROOT}/argv.log"
    : > "${log}"
    ROW_STATUS=0
    ROW_OUTPUT="$(
        PATH="${FAKE_BIN}:${PATH}" \
            FAKE_CARGO_ARGV_LOG="${log}" \
            FAKE_CARGO_LIST="${list}" \
            FAKE_CARGO_LIST_STATUS="${list_status}" \
            FAKE_CARGO_RUN_OUTPUT="${run_output}" \
            FAKE_CARGO_RUN_STATUS="${run_status}" \
            "${HELPER}" "$@" 2>&1
    )" || ROW_STATUS=$?
    ROW_ARGV="$(cat -- "${log}")"
}

# A libtest listing holding the named identities, in `--format terse` shape.
listing() {
    local identity
    for identity in "$@"; do
        printf '%s: test\n' "${identity}"
    done
    printf '%s tests, 0 benchmarks\n' "$#"
}

PASSING_RUN='running 1 test
test go_resolution_vocabulary_has_exact_wire_spellings ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 41 filtered out
'

VACUOUS_RUN='running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out
'

FAILING_RUN='running 1 test
test go_resolution_vocabulary_has_exact_wire_spellings ... FAILED

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 41 filtered out
'

INFRASTRUCTURE_RUN='error: failed to write to the target directory
Caused by:
  No space left on device (os error 28)
'

SUITE="$(listing \
    enum_spelling_cases::go_resolution_vocabulary_has_exact_wire_spellings \
    resolution_asserts::legacy_rust_resolution_wire_bytes_stay_exact \
    resolution_report_bounded_decode_ignores_hostile_sequence_size_hints)"

AMBIGUOUS="$(listing \
    enum_spelling_cases::go_resolution_vocabulary_has_exact_wire_spellings \
    resolution_cases::go_resolution_vocabulary_has_exact_wire_spellings)"

test_zero_selection_is_refused() {
    run_row "${SUITE}" 0 "${PASSING_RUN}" 0 \
        pedant-types serialization default no_such_predicate
    [ "${ROW_STATUS}" -eq 1 ] \
        || fail "a predicate no listed test carries must be refused, got ${ROW_STATUS}"
    case "${ROW_OUTPUT}" in
        *no_such_predicate*) ;;
        *) fail "the zero-selection refusal must name the predicate" ;;
    esac
    case "${ROW_ARGV}" in
        *--exact*) fail "a refused selection must run no exact test" ;;
    esac
}

test_duplicate_selection_is_refused() {
    run_row "${AMBIGUOUS}" 0 "${PASSING_RUN}" 0 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 1 ] \
        || fail "two listed tests with one bare name must be refused, got ${ROW_STATUS}"
    case "${ROW_OUTPUT}" in
        *enum_spelling_cases*resolution_cases* | *resolution_cases*enum_spelling_cases*) ;;
        *) fail "the duplicate refusal must name every candidate identity" ;;
    esac
    case "${ROW_ARGV}" in
        *--exact*) fail "an ambiguous selection must run no exact test" ;;
    esac
}

test_default_profile_selects_normal_features() {
    run_row "${SUITE}" 0 "${PASSING_RUN}" 0 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 0 ] || fail "the default profile row must pass, got ${ROW_STATUS}"
    case "${ROW_ARGV}" in
        *--no-default-features*) fail "the default profile must select normal features" ;;
        *--features*) fail "the default profile must name no feature list" ;;
    esac
    case "${ROW_ARGV}" in
        *"-p pedant-types --test serialization"*) ;;
        *) fail "the helper must select the stated package and integration target" ;;
    esac
}

test_none_profile_disables_default_features() {
    run_row "${SUITE}" 0 "${PASSING_RUN}" 0 \
        pedant-types serialization none go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 0 ] || fail "the none profile row must pass, got ${ROW_STATUS}"
    case "${ROW_ARGV}" in
        *--no-default-features*) ;;
        *) fail "the none profile must disable default features" ;;
    esac
    case "${ROW_ARGV}" in
        *--features*) fail "the none profile must name no feature list" ;;
    esac
}

test_named_profile_enables_exactly_its_features() {
    run_row "${SUITE}" 0 "${PASSING_RUN}" 0 \
        pedant-core substrate go-resolution,resolution-test-support \
        go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 0 ] || fail "the feature profile row must pass, got ${ROW_STATUS}"
    case "${ROW_ARGV}" in
        *"--no-default-features --features go-resolution,resolution-test-support"*) ;;
        *) fail "a named profile must disable defaults and enable exactly its list" ;;
    esac
}

test_success_runs_one_full_identity_exactly() {
    run_row "${SUITE}" 0 "${PASSING_RUN}" 0 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 0 ] || fail "a selected passing test must pass, got ${ROW_STATUS}"
    case "${ROW_ARGV}" in
        *"--exact enum_spelling_cases::go_resolution_vocabulary_has_exact_wire_spellings"*) ;;
        *) fail "the helper must run the one resolved full identity with --exact" ;;
    esac
}

test_vacuous_selection_is_refused() {
    run_row "${SUITE}" 0 "${VACUOUS_RUN}" 0 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 1 ] \
        || fail "a run that executed no test must not pass, got ${ROW_STATUS}"
    case "${ROW_OUTPUT}" in
        *"no test executed"*) ;;
        *) fail "the vacuous refusal must say no test executed" ;;
    esac
}

test_code_failure_keeps_its_status() {
    run_row "${SUITE}" 0 "${FAILING_RUN}" 101 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 101 ] \
        || fail "a failing test must keep cargo's own status, got ${ROW_STATUS}"
}

test_infrastructure_failure_reclassifies_to_75() {
    run_row "${SUITE}" 0 "${INFRASTRUCTURE_RUN}" 101 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 75 ] \
        || fail "an unavailable machine must leave with 75, got ${ROW_STATUS}"
}

test_infrastructure_failure_while_listing_reclassifies_to_75() {
    run_row "${INFRASTRUCTURE_RUN}" 101 "${PASSING_RUN}" 0 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 75 ] \
        || fail "an unavailable machine while listing must leave with 75, got ${ROW_STATUS}"
    case "${ROW_ARGV}" in
        *--exact*) fail "a listing that never completed must run no exact test" ;;
    esac
}

test_listing_failure_keeps_its_status() {
    run_row "compile error" 101 "${PASSING_RUN}" 0 \
        pedant-types serialization default go_resolution_vocabulary_has_exact_wire_spellings
    [ "${ROW_STATUS}" -eq 101 ] \
        || fail "a listing that failed to build must keep its status, got ${ROW_STATUS}"
}

test_wrong_argument_count_is_a_usage_error() {
    run_row "${SUITE}" 0 "${PASSING_RUN}" 0 pedant-types serialization default
    [ "${ROW_STATUS}" -eq 64 ] \
        || fail "a missing argument must be a usage error, got ${ROW_STATUS}"
}

test_zero_selection_is_refused
test_duplicate_selection_is_refused
test_default_profile_selects_normal_features
test_none_profile_disables_default_features
test_named_profile_enables_exactly_its_features
test_success_runs_one_full_identity_exactly
test_vacuous_selection_is_refused
test_code_failure_keeps_its_status
test_infrastructure_failure_reclassifies_to_75
test_infrastructure_failure_while_listing_reclassifies_to_75
test_listing_failure_keeps_its_status
test_wrong_argument_count_is_a_usage_error

if [ "${failures}" -ne 0 ]; then
    printf 'run_exact_rust_test_test: %s row(s) failed\n' "${failures}" >&2
    exit 1
fi

printf 'run_exact_rust_test_test: PASS\n'
