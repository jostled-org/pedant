#!/usr/bin/env bash
#
# verify_step_selftest.sh — clean-clone tests for the generic step verifier.
#
# The verifier is repository tooling, so this test uses only tracked files and
# synthetic temporary inputs. Completed or active plan files are lifecycle
# state and are never test fixtures here.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || SCRIPT_DIR=""
if [ -z "${SCRIPT_DIR}" ] || [ ! -x "${SCRIPT_DIR}/verify_step.sh" ]; then
    echo "error: cannot resolve the executable verifier beside ${BASH_SOURCE[0]}" >&2
    exit 75
fi

ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)" || ROOT=""
if [ -z "${ROOT}" ]; then
    echo "error: cannot resolve the repository root above ${SCRIPT_DIR}" >&2
    exit 75
fi

VERIFIER="${SCRIPT_DIR}/verify_step.sh"
SYNTHETIC_PLAN="synthetic-plan"

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

ROW_STATUS=0
ROW_OUTPUT=""
ROW_SCOPE=""
ROW_CHANGED_FILES=""
run_verifier() {
    local plan="$1" step="$2"
    shift 2
    ROW_STATUS=0
    ROW_OUTPUT="$(
        cd -- "${ROOT}" || exit 75
        env "$@" \
            PLAN_PATH="${plan}" \
            PLAN_STEP="${step}" \
            PLAN_TEST_SCOPE="${ROW_SCOPE}" \
            CHANGED_FILES_PATH="${ROW_CHANGED_FILES}" \
            PROOF_OUTPUT_DIR="" \
            "${VERIFIER}" 2>&1
    )" || ROW_STATUS=$?
    ROW_SCOPE=""
    ROW_CHANGED_FILES=""
}

matching_lines() {
    local capture="$1" pattern="$2" found status=0
    found="$(rg -e "${pattern}" <<< "${capture}")" || status=$?
    case "${status}" in
        0) printf '%s\n' "${found}" ;;
        1) ;;
        *)
            echo "error: rg exited ${status}; the selftest could not inspect verifier output" >&2
            exit 1
            ;;
    esac
}

commands_of() {
    matching_lines "$1" '^\[verify_step\] command: '
}

test_generic_route_is_nonempty_and_locked() {
    local listing line
    run_verifier "${SYNTHETIC_PLAN}" 1 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 0 ] || fail "generic listing must pass, got ${ROW_STATUS}"
    case "${ROW_OUTPUT}" in
        *"route: generic (workspace, no scope)"*) ;;
        *) fail "generic listing must select the workspace route" ;;
    esac
    listing="$(commands_of "${ROW_OUTPUT}")"
    [ -n "${listing}" ] || fail "generic route must list commands"
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        case "${line}" in
            *"cargo test --locked"* | *"cargo clippy --locked"*) ;;
            *) fail "generic route runs an unpinned build: ${line}" ;;
        esac
    done <<< "$(matching_lines "${listing}" 'cargo (test|clippy) ')"
}

test_changed_file_routing_is_not_vacuous() {
    local changed="${TEST_ROOT}/changed-files"
    printf 'README.md\n' > "${changed}" || {
        fail "cannot create documentation change fixture"
        return
    }
    ROW_CHANGED_FILES="${changed}"
    run_verifier "${SYNTHETIC_PLAN}" 2 VERIFY_STEP_LIST_ONLY=1
    case "${ROW_OUTPUT}" in
        *"route: generic (nothing to verify)"*) ;;
        *) fail "documentation-only change must select nothing-to-verify" ;;
    esac

    printf 'pedant/src/main.rs\n' > "${changed}" || {
        fail "cannot create Rust change fixture"
        return
    }
    ROW_CHANGED_FILES="${changed}"
    run_verifier "${SYNTHETIC_PLAN}" 2 VERIFY_STEP_LIST_ONLY=1
    case "${ROW_OUTPUT}" in
        *"route: generic (workspace, no scope)"*) ;;
        *) fail "Rust change must select workspace verification" ;;
    esac
    [ -n "$(commands_of "${ROW_OUTPUT}")" ] || fail "Rust change must list verification commands"
}

test_scoped_route_is_locked() {
    local listing
    ROW_SCOPE="pedant-snippet"
    run_verifier "${SYNTHETIC_PLAN}" 2 VERIFY_STEP_LIST_ONLY=1
    [ "${ROW_STATUS}" -eq 0 ] || fail "scoped listing must pass, got ${ROW_STATUS}"
    listing="$(commands_of "${ROW_OUTPUT}")"
    case "${listing}" in
        *"cargo clippy --locked -p pedant-snippet -- -D warnings"*) ;;
        *) fail "scoped route must pin Clippy" ;;
    esac
    case "${listing}" in
        *"cargo test --locked -p pedant-snippet"*) ;;
        *) fail "scoped route must pin tests" ;;
    esac
}

install_unavailable_cargo() {
    local bin="${TEST_ROOT}/bin"
    mkdir -p -- "${bin}" || return 1
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'echo "error: No space left on device (os error 28)" >&2' \
        'exit 1' > "${bin}/cargo" || return 1
    chmod +x "${bin}/cargo" || return 1
}

test_cargo_failures_are_classified() {
    local bin="${TEST_ROOT}/bin"
    install_unavailable_cargo || {
        fail "cannot install fake Cargo"
        return
    }

    run_verifier "${SYNTHETIC_PLAN}" 1 "PATH=${bin}:${PATH}"
    [ "${ROW_STATUS}" -eq 75 ] || fail "workspace verification must classify infrastructure as 75, got ${ROW_STATUS}"

    ROW_SCOPE="pedant-snippet"
    run_verifier "${SYNTHETIC_PLAN}" 2 "PATH=${bin}:${PATH}"
    [ "${ROW_STATUS}" -eq 75 ] || fail "scope validation must classify infrastructure as 75, got ${ROW_STATUS}"
}

test_generic_route_is_nonempty_and_locked
test_changed_file_routing_is_not_vacuous
test_scoped_route_is_locked
test_cargo_failures_are_classified

if [ "${failures}" -ne 0 ]; then
    printf 'verify_step_selftest: %s row(s) failed\n' "${failures}" >&2
    exit 1
fi

printf 'verify_step_selftest: PASS\n'
