#!/usr/bin/env bash
#
# Helpers used only by local proof orchestration. Repository checks source
# repository_check_lib.sh directly and do not depend on this file.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

# Registration machinery, shared by the two proof runners
# ---------------------------------------------------------------------------
#
# A runner sets `PROOF_WORK_DIR` to a directory it owns before calling any of
# these. `cargo_capture` writes one numbered log per invocation there, and every
# later assertion reads that file rather than a value the runner carried in its
# head.

# Where captures are written. A runner overwrites this before its first call.
PROOF_WORK_DIR="${PROOF_WORK_DIR:-}"

# How many captures have been taken, so each log gets its own name.
proof_capture_index=0

# The path of the most recent capture.
CAPTURE_PATH=""

# The path of the most recent document capture, empty for a plain one.
DOCUMENT_PATH=""

# The `--list` capture the most recent registration proof read. A runner that
# needs the registered population of a filter reads this file rather than a
# number it carried in its head; `run_resolution_proof.sh` does. The unused
# warning below is about this file's scope rather than the variable's.
# shellcheck disable=SC2034
REGISTRATION_LIST_PATH=""

# Report a model violation and fold it into the aggregate exit.
fail() {
    echo "error: $*" >&2
    cargo_record 1
    return 1
}

# Run one cargo invocation, keeping its output where the caller can read it.
#
# The capture is the runner's evidence as well as the operator's transcript, so
# it is replayed and kept rather than discarded. Classification is not this
# function's to make; cargo_infrastructure.sh owns the pattern set and the 75.
cargo_capture() {
    local label="$1"
    shift
    proof_run_cargo capture "${label}" "$@"
}

# Run one cargo invocation whose standard output is a document the caller parses.
#
# `cargo_capture` folds stderr into the capture, which is what an operator's
# transcript wants and what a JSON document cannot survive: one `Blocking
# waiting for file lock` line makes it unparseable. So the document goes to
# `DOCUMENT_PATH` and cargo's own messages go to `CAPTURE_PATH`, which is the
# stream the classifier reads for an infrastructure cause anyway.
cargo_capture_document() {
    local label="$1"
    shift
    proof_run_cargo document "${label}" "$@"
}

# The body both capture forms share. `mode` is `document` or `capture`.
proof_run_cargo() {
    local mode="$1" label="$2"
    shift 2
    if [ -z "${PROOF_WORK_DIR}" ] || [ ! -d "${PROOF_WORK_DIR}" ]; then
        fail "PROOF_WORK_DIR must name a directory the runner owns" || return 1
    fi
    proof_capture_index=$((proof_capture_index + 1))
    CAPTURE_PATH="${PROOF_WORK_DIR}/${proof_capture_index}-${label}.log"
    DOCUMENT_PATH=""

    local code=0
    if [ "${mode}" = document ]; then
        DOCUMENT_PATH="${PROOF_WORK_DIR}/${proof_capture_index}-${label}.json"
        "$@" > "${DOCUMENT_PATH}" 2> "${CAPTURE_PATH}" || code=$?
    else
        "$@" > "${CAPTURE_PATH}" 2>&1 || code=$?
    fi
    cat "${CAPTURE_PATH}"

    local classified
    classified=$(cargo_classify "${code}" "${CAPTURE_PATH}")
    if [ "${classified}" != "${code}" ]; then
        echo "[proof] ${label}: INFRASTRUCTURE (exit ${code} reclassified as ${classified})"
    fi
    cargo_record "${classified}"
    return "${classified}"
}

# How many lines of a capture ripgrep matches.
#
# ripgrep answers "no match" with status 1 and a broken matcher with 2 or more,
# and a `|| true` would collapse both into an empty count. A forbid check that
# reads a matcher failure as "clean" is exactly the vacuous result these runners
# exist to prevent, so a real failure prints `matcher-failed`, which no caller
# can mistake for a number.
#
# The capture comes first so every remaining argument reaches ripgrep verbatim,
# and a caller chooses between a regular expression and a fixed line itself.
counted_matches() {
    local capture="$1" count status
    shift
    count="$(rg --count "$@" -- "${capture}")"
    status=$?
    case "${status}" in
        0) printf '%s' "${count}" ;;
        1) printf '0' ;;
        *) printf 'matcher-failed' ;;
    esac
}

# How many lines of a capture match one regular expression.
match_count() {
    counted_matches "$2" --regexp "$1"
}

# How many lines of a capture are exactly this text.
#
# A predicate name carries `::` and a cargo configuration carries `-`, so the
# fixed-string form is what keeps a model entry from being read as a pattern.
exact_line_count() {
    counted_matches "$2" --line-regexp --fixed-strings "$1"
}

# How many predicates a `--list` capture registered under an exact name.
registered_count() {
    exact_line_count "$2: test" "$1"
}

# Require every modelled predicate exactly once, against a non-zero total.
verify_registration() {
    local label="$1" config="$2"
    shift 2
    local -a config_args
    read -r -a config_args <<< "${config}"

    cargo_capture "list-${label}" cargo test "${config_args[@]}" -- --list || return 1
    # shellcheck disable=SC2034
    REGISTRATION_LIST_PATH="${CAPTURE_PATH}"
    local list="${CAPTURE_PATH}" total predicate count
    total=$(match_count ': test$' "${list}")
    if [ "${total}" = "matcher-failed" ] || [ "${total}" -eq 0 ]; then
        fail "${label}: cargo test ${config} registered no test at all"
        return 1
    fi
    for predicate in "$@"; do
        count=$(registered_count "${list}" "${predicate}")
        if [ "${count:-0}" != "1" ]; then
            fail "${label}: ${predicate} is registered ${count:-0} times, not once"
            return 1
        fi
    done
}

# Execute one registered predicate by its exact name.
run_exact() {
    local label="$1" config="$2" predicate="$3"
    local -a config_args
    read -r -a config_args <<< "${config}"

    cargo_capture "run-${label}" cargo test "${config_args[@]}" "${predicate}" -- --exact || return 1
    if ! rg --quiet 'test result: ok\. 1 passed' "${CAPTURE_PATH}"; then
        fail "${label}: ${predicate} selected no test"
        return 1
    fi
}

# Execute one complete registered target and prove every modelled owner reached
# `ok` exactly once.
#
# Running the target once matters for the semantic rows: each exact cargo
# invocation rebuilds the same rust-analyzer workspace, while one libtest
# process can schedule the registered owners together. Cargo success still
# cannot hide an ignored owner, because its exact `test ... ok` line is required
# here — and `--list` cannot see an ignore, so this is the only place that can.
run_registered_target() {
    local label="$1" config="$2"
    shift 2
    local -a config_args
    read -r -a config_args <<< "${config}"

    cargo_capture "run-${label}" cargo test "${config_args[@]}" || return 1
    local predicate count
    for predicate in "$@"; do
        count=$(exact_line_count "test ${predicate} ... ok" "${CAPTURE_PATH}")
        if [ "${count:-0}" != "1" ]; then
            fail "${label}: ${predicate} completed successfully ${count:-0} times, not once"
            return 1
        fi
    done
}

# List one configuration's modelled predicates, then run its complete target.
registration_row() {
    local label="$1" config="$2"
    shift 2
    verify_registration "${label}" "${config}" "$@" || return 1
    run_registered_target "${label}" "${config}" "$@"
}
