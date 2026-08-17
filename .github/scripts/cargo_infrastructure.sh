#!/usr/bin/env bash
# cargo_infrastructure.sh — the one owner of Cargo-output infrastructure status.
#
# Sourced, never executed. A cargo failure means either "this code is wrong" or
# "this machine could not do the work", and only cargo's own output tells them
# apart. Every repository check and every lifecycle runner that invokes cargo
# needs the same answer, so the signature table, the reclassification to 75, and
# the aggregate priority live here rather than in each caller. A second copy
# would drift, and a drifting copy fails a change for a full disk.
#
# The API:
#   cargo_classify <status> <capture-path>       print the status for a file
#   cargo_classify_output <status> <output>      print the status for a string
#   cargo_receipt <label> <capture-path>         leave one named receipt
#   cargo_record <status> [output]               fold one result into the total
#   cargo_run <label> <command> [args ...]       run, capture, replay, classify
#   cargo_worst                                  the aggregate status so far
#
# Priority, most severe first: infrastructure (75), then the first other
# non-zero status, then success. An infrastructure failure invalidates every
# other result on the run, so it leaves immediately rather than waiting for an
# aggregate a later ordinary failure could confuse. The caller retries, and the
# next attempt carries the definitive signal.
#
# Classification reads output with `rg`, so every caller must prove ripgrep is
# on PATH before it runs a command through here. A reader that cannot answer is
# treated as an unavailable machine rather than as a clean transcript: guessing
# "the code is wrong" for a full disk is the one mistake this file exists to
# prevent.
#
# Bash 3.2 compatible, because macOS ships nothing newer.

# Cargo failures that mean the environment is unavailable rather than that the
# code is wrong. Matched case-sensitively against the combined stdout and
# stderr of a failed cargo invocation, so `read-only API contract failed` stays
# an ordinary failure while `Read-only file system` does not.
CARGO_INFRASTRUCTURE_PATTERNS='spurious network error|failed to fetch|Could not resolve host|error: could not download|No space left on device|Read-only file system|failed to acquire package cache lock|toolchain .* is not installed|rustup could not choose a version'

CARGO_INFRASTRUCTURE_STATUS=75

cargo_infrastructure_worst=0

# Print the status one exit code and its captured output deserve.
#
# A successful run stays successful even when its output names a signature:
# cargo retried the fetch and got what it needed.
cargo_classify_output() {
    local code="$1"
    if [ "${code}" -eq 0 ]; then
        printf '%s\n' "${code}"
        return 0
    fi
    local named=0
    printf '%s\n' "$2" | rg -e "${CARGO_INFRASTRUCTURE_PATTERNS}" > /dev/null || named=$?
    # 1 is ripgrep's "no match". Anything else means the reader itself failed,
    # which is an unavailable machine and not a clean transcript.
    if [ "${named}" -eq 1 ]; then
        printf '%s\n' "${code}"
        return 0
    fi
    printf '%s\n' "${CARGO_INFRASTRUCTURE_STATUS}"
}

# The same decision for a run whose output is already on disk.
#
# The capture is a cargo transcript its caller replays whole, so holding it
# costs the order of memory that caller already spends. A capture that cannot be
# read at all is the unavailable machine again.
cargo_classify() {
    local output
    output=$(cat -- "$2") || {
        printf '%s\n' "${CARGO_INFRASTRUCTURE_STATUS}"
        return 0
    }
    cargo_classify_output "$1" "${output}"
}

# Leave one capture in the caller's output directory, named for its label.
#
# A caller that owns an output directory gets one log per label; a caller that
# owns none gets nothing. Best effort either way: a receipt that could not be
# written is not a reason to fail the run that produced it. Which capture is the
# receipt is the caller's to say — the combined transcript for a run this file
# replays, the diagnostic stream for one whose output its caller reads.
cargo_receipt() {
    if [ -n "${PROOF_OUTPUT_DIR:-}" ] && [ -d "${PROOF_OUTPUT_DIR}" ]; then
        cp -- "$2" "${PROOF_OUTPUT_DIR}/$1.log" 2> /dev/null || true
    fi
}

# Fold one result into the aggregate, classifying the output when given.
cargo_record() {
    local classified="$1"
    if [ "$#" -gt 1 ]; then
        classified=$(cargo_classify_output "$1" "$2")
    fi
    if [ "${classified}" -eq "${CARGO_INFRASTRUCTURE_STATUS}" ]; then
        cargo_infrastructure_worst="${CARGO_INFRASTRUCTURE_STATUS}"
        exit "${CARGO_INFRASTRUCTURE_STATUS}"
    fi
    if [ "${classified}" -ne 0 ] && [ "${cargo_infrastructure_worst}" -eq 0 ]; then
        cargo_infrastructure_worst="${classified}"
    fi
    return 0
}

# The aggregate status for everything recorded so far.
cargo_worst() {
    printf '%s\n' "${cargo_infrastructure_worst}"
}

# Run one command, replay its combined output once, and classify the result.
#
# The capture is the operator's transcript as well as the classifier's
# evidence, so it is replayed and — when the caller owns an output directory —
# copied there as a receipt. It is removed before any status leaves this
# function, including the infrastructure exit, because a capture nobody owns
# outlives the run that made it.
cargo_run() {
    local label="$1"
    shift
    local capture
    capture=$(mktemp "${TMPDIR:-/tmp}/cargo_infrastructure.XXXXXX") || exit "${CARGO_INFRASTRUCTURE_STATUS}"

    local code=0
    "$@" > "${capture}" 2>&1 || code=$?
    cat -- "${capture}"

    cargo_receipt "${label}" "${capture}"

    local classified
    classified=$(cargo_classify "${code}" "${capture}")
    rm -f -- "${capture}"
    if [ "${classified}" != "${code}" ]; then
        printf '[cargo_infrastructure] %s: INFRASTRUCTURE (exit %s reclassified as %s)\n' \
            "${label}" "${code}" "${classified}"
    fi
    cargo_record "${classified}"
}
