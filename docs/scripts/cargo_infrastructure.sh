#!/usr/bin/env bash
# cargo_infrastructure.sh — the one owner of Cargo-output infrastructure status.
#
# Sourced, never executed. A cargo failure means either "this code is wrong" or
# "this machine could not do the work", and only cargo's own output tells them
# apart. Every plan-loop runner that invokes cargo needs the same answer, so the
# pattern set, the reclassification to 75, and the aggregate-exit priority live
# here rather than in each runner. A second copy would drift, and a drifting
# copy fails a plan for a full disk.
#
# Contract for a sourcing script:
#   cargo_run <label> <command> [args ...]   run, capture, replay, classify
#   cargo_record <exit-code>                 fold a foreign exit into the total
#   cargo_worst                              the aggregate exit code so far
#
# Aggregate-exit priority (most severe wins):
#   infrastructure (75) > first other non-zero > success (0).
# An infrastructure failure invalidates every other result on the run: the loop
# retries 75, and the next attempt carries the definitive signal.
#
# `cargo_classify` reads captures with `rg`, so every sourcing script must prove
# ripgrep is on PATH before it runs a command through here. A missing rg exits
# 127 from inside the `if`, which reads as "no infrastructure pattern matched",
# and the classifier answers "the code is wrong" for a full disk.

# Cargo failures that mean the environment is unavailable, not that the code is
# wrong. Matched against combined stdout+stderr of a failed cargo invocation.
CARGO_INFRASTRUCTURE_PATTERNS='No space left on device|Read-only file system|failed to acquire package cache lock|spurious network error|failed to fetch|Could not resolve host|error: could not download|toolchain .* is not installed|rustup could not choose a version'

CARGO_INFRASTRUCTURE_STATUS=75

cargo_infrastructure_worst=0

# Fold one exit code into the aggregate.
cargo_record() {
    local code=$1
    [ "$code" -eq 0 ] && return 0
    if [ "$code" -eq "${CARGO_INFRASTRUCTURE_STATUS}" ]; then
        cargo_infrastructure_worst=${CARGO_INFRASTRUCTURE_STATUS}
        return 0
    fi
    [ "$cargo_infrastructure_worst" -eq 0 ] && cargo_infrastructure_worst=$code
    return 0
}

# The aggregate exit code for everything recorded so far.
cargo_worst() {
    echo "${cargo_infrastructure_worst}"
}

# Reclassify a failed run whose output names an environment cause.
cargo_classify() {
    local code=$1
    local capture=$2
    [ "$code" -eq 0 ] && {
        echo "$code"
        return 0
    }
    if rg -q "${CARGO_INFRASTRUCTURE_PATTERNS}" "$capture"; then
        echo "${CARGO_INFRASTRUCTURE_STATUS}"
        return 0
    fi
    echo "$code"
}

# Run one verification command, streaming its output to the phase log and
# copying it into PROOF_OUTPUT_DIR as a receipt when the loop supplied one.
cargo_run() {
    local label="$1"
    shift
    local capture
    capture=$(mktemp "${TMPDIR:-/tmp}/plan_verify.XXXXXX") || {
        cargo_record "${CARGO_INFRASTRUCTURE_STATUS}"
        return 0
    }

    "$@" > "$capture" 2>&1
    local code=$?
    cat "$capture"

    if [ -n "${PROOF_OUTPUT_DIR:-}" ] && [ -d "${PROOF_OUTPUT_DIR}" ]; then
        cp "$capture" "${PROOF_OUTPUT_DIR}/${label}.log" 2>/dev/null || true
    fi

    local classified
    classified=$(cargo_classify "$code" "$capture")
    if [ "$classified" != "$code" ]; then
        echo "[cargo_infrastructure] ${label}: INFRASTRUCTURE (exit ${code} reclassified as ${classified})"
    fi

    rm -f "$capture"
    cargo_record "$classified"
    return 0
}
