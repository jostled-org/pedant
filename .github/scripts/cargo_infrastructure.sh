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
#   cargo_capture <label> <command> [args ...]   run, keep the output, return
#   cargo_classify <status> <capture-path>       print the status for a file
#   cargo_classify_output <status> <output>      print the status for a string
#   cargo_feature_flags <profile>                the flags one profile adds
#   cargo_profile_of <command line>              the profile a command selects
#   cargo_profile_suffix <profile>               the label suffix it earns
#   cargo_receipt <label> <capture-path>         leave one named receipt
#   cargo_record <status> [output]               fold one result into the total
#   cargo_report_reclassification <label> <code> <classified>
#                                                say a status was reclassified
#   cargo_run <label> <command> [args ...]       run, capture, replay, classify
#   cargo_worst                                  the aggregate status so far
#   require_tools <tool ...>                     leave with 75 unless each resolves
#   rg_status <rg args ...>                      search, capture, classify 0/1/2
#   rg_status_over <document> <rg args ...>      the same over a held document
#
# The feature-profile vocabulary is stated here too, because a runner, a router,
# and a routing table all have to spell one profile the same way:
#
#   default   normal features
#   none      --no-default-features
#   all       --all-features
#   <list>    --no-default-features --features <list>
#
# It lived in six places across three files — three of them inside one function
# — and one of them had no `all` at all, so a matrix row stated eight feature
# names beside two siblings that said `--all-features` and nothing checked the
# three agreed.
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

# ---------------------------------------------------------------------------
# The machine every caller of this file needs before it runs anything
# ---------------------------------------------------------------------------

# Leave with 75 unless every named tool resolves on PATH.
#
# 75 is infrastructure and never drift: a machine with no `jq` cannot read a
# profile either way, so the caller reruns rather than reading a missing tool as
# the boundary violation the check is named for. It lives here because this is
# the one file every check, runner, and row table already sources, and because
# five of them had written the loop out by hand in two wordings — long enough
# for two owners to disagree about whether an absent tool is the repository's
# fault.
require_tools() {
    local tool
    for tool in "$@"; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            echo "error: ${tool} is unavailable; the check cannot be read" >&2
            exit "${CARGO_INFRASTRUCTURE_STATUS}"
        fi
    done
}

# ---------------------------------------------------------------------------
# Classified ripgrep searches whose answer the caller reads
# ---------------------------------------------------------------------------

# What the last classified search printed, and the status ripgrep itself left.
#
# Both are read by the callers that source this file rather than inside it, so
# the analyser sees no reader here. `RG_EXIT` is what a caller's diagnostic
# names when the third case fires: "rg exited 2" is the sentence an operator
# needs, and the classified 2 alone would not distinguish it from a ripgrep that
# was never installed.
RG_OUTPUT=""
RG_EXIT=0

# Classify one ripgrep status: 0 matched, 1 no match, 2 the matcher failed.
#
# The third case is the one this file exists for. A search that never ran comes
# back with a status a caller reading `if rg -q …` folds into "no match", and an
# unreadable subject then reads as a clean one — a check passing by failing to
# look. Nine callers had derived this three-way split by hand and resolved the
# broken case three different ways, so the split is stated once here and each
# caller states only its own resolution.
rg_classify() {
    # Read by the callers that source this file.
    # shellcheck disable=SC2034
    RG_EXIT="$1"
    case "$1" in
        0 | 1) return "$1" ;;
    esac
    return 2
}

# Search whatever paths and flags the caller names, keeping the output.
rg_status() {
    local status=0
    RG_OUTPUT="$(rg "$@")" || status=$?
    rg_classify "${status}"
}

# The same search over one document the caller already holds.
#
# The document reaches ripgrep on a here-string rather than through a pipe:
# under `pipefail` a pipeline reports the first failing stage, so a `printf`
# that died would be read as ripgrep's own status by the one function whose
# purpose is telling a broken matcher apart from a document that says nothing.
rg_status_over() {
    local subject="$1"
    shift
    local status=0
    # Read by the callers that source this file.
    # shellcheck disable=SC2034
    RG_OUTPUT="$(rg "$@" <<< "${subject}")" || status=$?
    rg_classify "${status}"
}

# ---------------------------------------------------------------------------
# The one feature-profile vocabulary every cargo caller reads
# ---------------------------------------------------------------------------

# The flags the last named profile adds, as an array and as command-line text.
#
# Two shapes of one answer, set together by one `case`, because the callers need
# both: an argv builder splices the array into a command, and a table that
# states the command a package must be linted by compares the text. Derived
# apart, the two disagreed the moment a fourth profile arrived.
CARGO_FEATURE_FLAGS=()
CARGO_FEATURE_TEXT=""

# The flags one feature profile adds to a cargo command.
#
# Bash 3.2 is what macOS ships, and there an empty array expands to an unbound
# variable under `set -u`. Every caller therefore expands the array through the
# `+` form, which expands to nothing at all when the default profile adds no
# flag rather than aborting the run.
cargo_feature_flags() {
    case "$1" in
        default) CARGO_FEATURE_FLAGS=() ;;
        none) CARGO_FEATURE_FLAGS=(--no-default-features) ;;
        all) CARGO_FEATURE_FLAGS=(--all-features) ;;
        *) CARGO_FEATURE_FLAGS=(--no-default-features --features "$1") ;;
    esac
    local flag
    CARGO_FEATURE_TEXT=""
    for flag in ${CARGO_FEATURE_FLAGS[@]+"${CARGO_FEATURE_FLAGS[@]}"}; do
        CARGO_FEATURE_TEXT="${CARGO_FEATURE_TEXT} ${flag}"
    done
}

# The feature profile one cargo command line selects, in the same vocabulary.
#
# The inverse of `cargo_feature_flags`, and its neighbour for that reason: a
# reader written beside the branch that needed it is how the profile went
# missing from a lint gate the first time. `--all-features` is asked first,
# because it is the one spelling that names no feature list.
cargo_profile_of() {
    local features
    case "$1" in
        *" --all-features"*) printf 'all\n' ;;
        *" --no-default-features --features "*)
            features="${1##* --features }"
            printf '%s\n' "${features%% *}"
            ;;
        *" --no-default-features"*) printf 'none\n' ;;
        *) printf 'default\n' ;;
    esac
}

# What one profile adds to a receipt label, so two profiles of one package do
# not write one another's transcript.
#
# The default profile earns nothing, because it is the label a package carried
# before any profile was named and a receipt directory holds both spellings.
cargo_profile_suffix() {
    case "$1" in
        default) ;;
        *) printf '_%s' "$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# Cargo output classification
# ---------------------------------------------------------------------------

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
    rg_status_over "$2" -e "${CARGO_INFRASTRUCTURE_PATTERNS}" || named=$?
    # 1 is the classified "no match". 2 means the reader itself failed, which is
    # an unavailable machine and not a clean transcript.
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

# Say that one command's status was read as an unavailable machine.
#
# Silent when the classification agreed with the status, so a caller states the
# call and not the condition. The three runners had written the same four lines
# out by hand, and two of them were in files that own neither the tag nor the
# wording: `cargo_infrastructure` names this file, so this file prints it.
cargo_report_reclassification() {
    if [ "$3" != "$2" ]; then
        printf '[cargo_infrastructure] %s: INFRASTRUCTURE (exit %s reclassified as %s)\n' \
            "$1" "$2" "$3"
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

# The combined output of the last `cargo_capture` run.
#
# Read by the callers that source this file rather than inside it, so the
# analyser sees no reader here.
# shellcheck disable=SC2034
CARGO_CAPTURE_OUTPUT=""

# Run one cargo command, keep its combined output, and answer with its status.
#
# `cargo_run` replays a transcript and folds the result into the aggregate,
# which is what a runner needs. A check reads the output instead, and it must
# read it in the caller's own shell: `cargo_record` leaves the whole process
# with 75 for an unavailable machine, and a command substitution around this
# function would swallow that exit and report a registry outage as drift.
#
# The status returned is cargo's own, so an ordinary failure stays the caller's
# to report. An unavailable machine never returns here at all.
#
# It lives beside `cargo_run` rather than in `repository_check_lib.sh`, where it
# was written: it names no repository concept, it touches only this file's own
# symbols, and the two owners had left two globals one letter apart for one
# thing.
cargo_capture() {
    local label="$1"
    shift
    local code=0
    CARGO_CAPTURE_OUTPUT="$("$@" 2>&1)" || code=$?
    local classified
    classified="$(cargo_classify_output "${code}" "${CARGO_CAPTURE_OUTPUT}")"
    cargo_report_reclassification "${label}" "${code}" "${classified}"
    cargo_record "${classified}"
    return "${code}"
}

# The combined output of the last `cargo_run`.
#
# Published because a runner that has to read what it replayed had otherwise to
# write its own copy of this function, and the copy that existed differed from
# it by an assignment and a trap.
# shellcheck disable=SC2034
CARGO_RUN_OUTPUT=""

# Run one command, replay its combined output once, and classify the result.
#
# The capture is the operator's transcript as well as the classifier's
# evidence, so it is replayed and — when the caller owns an output directory —
# copied there as a receipt. It is removed before any status leaves this
# function, including the infrastructure exit, because a capture nobody owns
# outlives the run that made it.
#
# The removal is also armed as an EXIT handler, because a signal during the
# command below leaves this function without reaching the `rm` in line. The
# caller's own handler is captured first and restored afterwards rather than
# cleared: this file is sourced by a proof that owns a staging tree through one,
# and a bare `trap - EXIT` here would leave that tree behind on every path.
cargo_run() {
    local label="$1"
    shift
    local capture previous_exit_trap
    capture=$(mktemp "${TMPDIR:-/tmp}/cargo_infrastructure.XXXXXX") || exit "${CARGO_INFRASTRUCTURE_STATUS}"
    previous_exit_trap="$(trap -p EXIT)"
    # The path is expanded as the trap is set, not as it fires: `capture` is a
    # local, and a handler that read it after this function returned would reach
    # an unset name under `set -u` and remove nothing while reporting an error.
    # shellcheck disable=SC2064
    trap "rm -f -- \"${capture}\"" EXIT

    local code=0
    "$@" > "${capture}" 2>&1 || code=$?

    # Read once. The replay, the receipt, and the classification are three
    # readers of one transcript, and reading the file three times is three
    # chances to disagree about what the command said.
    CARGO_RUN_OUTPUT="$(cat -- "${capture}")" || {
        rm -f -- "${capture}"
        # shellcheck disable=SC2294
        eval "${previous_exit_trap:-trap - EXIT}"
        exit "${CARGO_INFRASTRUCTURE_STATUS}"
    }
    printf '%s\n' "${CARGO_RUN_OUTPUT}"

    cargo_receipt "${label}" "${capture}"
    rm -f -- "${capture}"
    # shellcheck disable=SC2294
    eval "${previous_exit_trap:-trap - EXIT}"

    local classified
    classified=$(cargo_classify_output "${code}" "${CARGO_RUN_OUTPUT}")
    cargo_report_reclassification "${label}" "${code}" "${classified}"
    cargo_record "${classified}"
}
