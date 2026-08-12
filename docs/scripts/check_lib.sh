#!/usr/bin/env bash
#
# Shared helpers for the four repository boundary checks in this directory and
# for the two proof runners that reuse them.
#
# All four checks prove a claim about the workspace's shape, and all four prove
# it the same way: confirm the tools resolve, capture cargo's output into a
# shell variable, then read that capture with one `jq` predicate. Stated once, a
# fix to the tool message or the failure report reaches every check instead of
# one.
#
# The capability block is the same argument for two callers that are not both
# proof runners: `check_syntax_capabilities.sh` and `run_graph_proof.sh` each
# run pedant's own detection over a first-party tree, and each has to prove the
# detectors are live before it trusts a clean profile. One source listing, one
# spelling of the pedant command, one sentinel mirror, and one reach predicate
# keep that guard from weakening in one caller and not the other. The listing
# and its count are here because the callers derived the count two different
# ways, and one of those ways read a broken matcher as an empty tree.
#
# The registration and closure blocks at the end are the same argument for the
# proof runners: `run_resolution_proof.sh` and `run_graph_proof.sh` both have to
# prove a predicate is registered before they run it, because cargo reports
# success for a filter that selected nothing, and both read a `cargo tree`
# capture for a rendered root and then for forbidden edges. Two copies of either
# would be two places for it to weaken. Those functions need `cargo_record`, so
# a caller that uses them must source `cargo_infrastructure.sh` too; the
# boundary checks use only the blocks above and source this file alone.
#
# This file is sourced, never executed. It defines functions and runs nothing,
# so the caller keeps its own shell options and its own exit contract: the four
# `check_*.sh` run under `set -euo pipefail`, the proof runners under
# `set -uo pipefail`. Nothing here depends on which. The failure paths in the
# first block call `exit` themselves rather than return a status, so a caller
# without `-e` still stops; the registration block returns 1 instead, because a
# proof runner folds every result into one aggregate exit.

# Fail unless every named tool resolves on PATH.
require_tools() {
    local tool
    for tool in "$@"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "error: ${tool} is required on PATH" >&2
            exit 1
        fi
    done
}

# Anchor the working directory at the repository root.
#
# Inside a function, `${BASH_SOURCE[0]}` names the file that defined the
# function — this one — not the caller. So the anchor is this file's own
# location, and a check launched from any directory reads the same workspace.
# Without it, `cargo metadata` and `cargo tree` resolve whatever workspace the
# caller stood in, and a closure check run from a sibling Rust repo reports
# "'pedant-syntax' is not a workspace member": a true statement about the wrong
# workspace. The `-d` guards in the capability check have the same problem, and
# read "the trees are gone" only once the working directory is known.
cd_repo_root() {
    local lib_dir
    # Guarded on its own: an empty `lib_dir` would make the target below `/../..`,
    # which resolves to `/` and enters it, and the check would then describe the
    # filesystem root as this workspace.
    lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || lib_dir=""
    if [ -z "${lib_dir}" ]; then
        echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
        exit 1
    fi
    if ! cd -- "${lib_dir}/../.."; then
        echo "error: cannot enter the repository root above ${lib_dir}" >&2
        exit 1
    fi
}

# Print the workspace's own package list as `cargo metadata` JSON.
#
# `--no-deps` is load-bearing, not a speed-up: it is what makes `.packages[]`
# mean "workspace member" instead of "every crate in the dependency graph".
# Every caller reads the list with that meaning — the closure check derives its
# forbid set from it, and without the flag it forbids all of crates.io. Stated
# once here, so a caller cannot read the list under the wrong meaning.
workspace_metadata() {
    cargo metadata --format-version 1 --no-deps
}

# Print every workspace member except the ones named, one per line.
#
# A closure proof forbids what a package may not reach, and a hand-written
# forbid list is the wrong shape for that: it goes stale the day a member joins,
# and the new member's edge then reads as clean. Both callers therefore state
# what may be reached and derive the rest. Stated here beside
# `workspace_metadata` so one document has one reader.
#
# The document is captured before jq reads it, so a `cargo metadata` that failed
# propagates with cargo's own message rather than emptying the forbid set
# silently, and it reaches jq on a here-string for the reason `assert_jq` gives.
# A caller must still assert the result is non-empty: a member list that loaded
# and named only the excluded packages forbids nothing.
workspace_members_excluding() {
    local metadata
    metadata="$(workspace_metadata)" || return 1
    jq -r --args \
        '.packages[].name | select(IN($ARGS.positional[]) | not)' "$@" \
        <<<"${metadata}"
}

# Whether a captured JSON document satisfies a jq predicate.
#
# Arguments after the predicate go to jq verbatim up to a literal `--`. Each
# argument after that `--` is one line of the failure report. The pass-through
# is what lets a caller bind a shell value with `--argjson` instead of splicing
# it into the program text: a predicate built by interpolation is one the caller
# cannot quote, and the separator keeps a jq flag from reading as a report line.
#
# The document is captured before this runs, so a cargo failure has already
# propagated with cargo's own message. What remains is jq's own failure, and a
# broken matcher must not read as a satisfied check: `jq -e` answers a false or
# null result with 1 and an empty result with 4, and every other status means
# jq never evaluated the predicate. Only the first two are violations.
#
# The document reaches jq on a here-string rather than through a pipe. Under
# `pipefail` a pipeline reports the first failing stage, so a `printf` that died
# would land in `status` and be reported below as jq's own exit — the wrong
# diagnostic from the one function whose purpose is telling "predicate false"
# apart from "matcher broken". A here-string leaves `status` jq's alone.
#
# A false predicate returns 1 rather than exiting. A proof runner folds every
# result it can reach into one aggregate exit, and a helper that exits itself
# gives that runner a second failure protocol whose result nothing records.
# `assert_jq` below is the `set -e` form the boundary checks use. A jq that
# never evaluated the predicate exits from either, because "the check did not
# run" is not a result any caller can fold.
check_jq() {
    local document="$1" predicate="$2" status=0 line
    shift 2
    local jq_argv=(-e)
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --)
                shift
                break
                ;;
            *)
                jq_argv+=("$1")
                shift
                ;;
        esac
    done
    jq_argv+=("${predicate}")
    jq "${jq_argv[@]}" <<<"${document}" >/dev/null || status=$?
    case "${status}" in
        0)
            return 0
            ;;
        1 | 4) ;;
        *)
            echo "error: jq exited ${status} without evaluating the predicate." >&2
            echo "The check did not run; this is a tool failure, not drift." >&2
            exit 1
            ;;
    esac
    for line in "$@"; do
        echo "${line}" >&2
    done
    return 1
}

# Fail unless a captured JSON document satisfies a jq predicate.
assert_jq() {
    check_jq "$@" || exit 1
}

# ---------------------------------------------------------------------------
# Capability scanning, shared by the syntax check and the graph proof runner
# ---------------------------------------------------------------------------

# Build pedant from this workspace and read a tree's capability profile.
#
# Both callers run it twice — once over a sentinel mirror and once over the real
# tree — and one decision with four call sites is four places for it to drift to
# a `PATH` binary that is not this tree's. The array is the command; the
# function is the direct form for a caller that keeps no capture directory. A
# runner that owns one passes the array to `cargo_capture_document` instead, so
# an unavailable registry reaches the classifier as infrastructure.
#
# Both forms are used from the callers rather than here.
# shellcheck disable=SC2034
PEDANT_CAPABILITIES_COMMAND=(cargo run --quiet -p pedant -- capabilities)

pedant_capabilities() {
    cargo run --quiet -p pedant -- capabilities "$@"
}

# The capabilities every sentinel names, and therefore the capabilities a caller
# may forbid.
#
# A forbid list is an `all` over what is normally an empty finding set, so a
# regressed detector would report nothing and the real scan would read as clean.
# The mirror is what makes the forbid half mean anything, and it can only mean
# anything for the capabilities it names. This repository is pedant, so those
# detectors are the source under change.
SENTINEL_CAPABILITIES='["file_read", "file_write", "process_exec", "network"]'

# The listing `read_rust_sources` left, one repository-relative path per line.
RUST_SOURCE_LISTING=""

# How many paths that listing holds.
RUST_SOURCE_COUNT=0

# List one tree's Rust sources and count them, leaving both above.
#
# Both callers need the same pair — the listing the sentinel mirror reproduces,
# and the count the mirror's own equality and the reach predicate are held to —
# and they derived the count two different ways. That divergence is not
# cosmetic: one of them read a ripgrep matcher failure as a count of zero and
# then printed "this tree holds no Rust source", a false statement about the
# repository from the guard whose whole purpose is refusing a vacuous result.
#
# The listing is captured before anything reads it. Feeding a reader from a
# process substitution puts `find` in a subshell whose exit status nothing
# observes, so a `find` that died after emitting one path would leave one path
# and a count of one, and `mirror_sentinels` would compare that against itself
# and pass.
#
# The count is then taken from the listing by the shell. `rg --count` reports a
# broken matcher through a status a caller can read as "no match", and `wc -l`
# has the other half of the problem: a listing of no paths is still one empty
# line, so it counts one. A loop over non-empty lines has neither hazard.
#
# An empty tree is a count of zero and the caller's own refusal, not a failure
# here: the two callers say different things about it. Returning 1 means the
# listing could not be taken at all.
read_rust_sources() {
    local tree="$1" path
    RUST_SOURCE_LISTING=""
    RUST_SOURCE_COUNT=0
    RUST_SOURCE_LISTING="$(find "${tree}" -type f -name '*.rs')" || return 1
    while IFS= read -r path; do
        [ -n "${path}" ] || continue
        RUST_SOURCE_COUNT=$((RUST_SOURCE_COUNT + 1))
    done <<<"${RUST_SOURCE_LISTING}"
}

# Give every mirrored source one file that names each sentinel capability.
#
# The mirror is per file, not per directory: one sentinel per directory proves
# descent and says nothing about which files the scan then selects, and a
# discovery rule that skipped a file by name, extension case, or size would lose
# real source with no count to say so. The count is compared with the caller's
# own, so a mirror that covered fewer files than the profile ranges over fails
# here instead of narrowing the guard.
#
# The network sentinel connects to a hostname rather than an address literal.
# The literal-endpoint heuristic fires a second `network` finding on an
# IPv4-with-port string, and the reach counts are per distinct file for exactly
# that reason: a detector that fires twice on one line still counts once.
#
# The failures report and return rather than call `fail`: one caller folds a
# result into an aggregate exit and the other runs under `set -e`, so the
# decision belongs to each of them.
mirror_sentinels() {
    local mirror="$1" sources="$2" expected="$3" source written=0
    while IFS= read -r source; do
        [ -n "${source}" ] || continue
        mkdir -p "$(dirname -- "${mirror}/${source}")" || {
            echo "error: cannot mirror ${source}" >&2
            return 1
        }
        printf '%s\n' \
            'pub fn read(path: &str) -> std::io::Result<String> {' \
            '    std::fs::read_to_string(path)' \
            '}' \
            'pub fn write(path: &str) -> std::io::Result<()> {' \
            '    std::fs::write(path, "sentinel")' \
            '}' \
            'pub fn spawn() -> std::io::Result<std::process::Child> {' \
            '    std::process::Command::new("ls").spawn()' \
            '}' \
            'pub fn connect() -> std::io::Result<std::net::TcpStream> {' \
            '    std::net::TcpStream::connect("sentinel.invalid:80")' \
            '}' \
            >"${mirror}/${source}" || {
            echo "error: cannot write the sentinel for ${source}" >&2
            return 1
        }
        written=$((written + 1))
    done <<<"${sources}"
    if [ "${written}" -ne "${expected}" ]; then
        echo "error: mirrored ${written} sentinels for ${expected} sources, so the reach guard would not range over the real source set" >&2
        return 1
    fi
}

# Whether pedant reported every sentinel capability of every mirrored file.
#
# `$findings` is bound at the top because `all` rebinds `.` to the capability
# under test, which puts the document itself out of reach inside the body.
# `$expected` and `$capabilities` are jq variables the bindings below supply, so
# the single quotes keep the shell out of the program.
#
# Two forms for the reason `check_jq` and `assert_jq` are two forms: the proof
# runner folds a false result into its aggregate exit and the boundary check
# stops on it.
# shellcheck disable=SC2016
check_sentinel_reach() {
    local reach="$1" expected="$2" subject="$3"
    check_jq "${reach}" '
.findings as $findings
| $capabilities
| all(. as $capability
      | ([$findings[]
          | select(.capability == $capability)
          | .location.file]
         | unique
         | length) == $expected)
' \
        --argjson expected "${expected}" \
        --argjson capabilities "${SENTINEL_CAPABILITIES}" \
        -- \
        "error: pedant did not report every sentinel capability of every mirrored source." \
        "Expected ${expected} distinct files for each of ${SENTINEL_CAPABILITIES} —" \
        "one per source of ${subject}. The clean profile below would be vacuous," \
        "so it is not trusted."
}

# Fail unless pedant reported every sentinel capability of every mirrored file.
assert_sentinel_reach() {
    check_sentinel_reach "$@" || exit 1
}

# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Dependency-closure assertions, shared by the two proof runners
# ---------------------------------------------------------------------------
#
# Both runners forbid edges in a `cargo tree` capture, and a forbid check is
# only as strong as its matcher. `rg` answers "no match" with 1 and a broken
# matcher with 2 or more, so a check that reads the output and never the status
# reports "clean" for a capture it could not read at all — the vacuous result
# these runners exist to prevent. Every count below comes from
# `counted_matches`, which spells that failure `matcher-failed`.

# Whether a `cargo tree` capture rendered this root.
#
# A capture holds cargo's stderr too, so `Updating` and `Blocking` progress
# lines alone make it non-empty. Emptiness therefore proves nothing: the forbid
# checks that follow would range over a graph nobody printed and report the
# absence as a result. `--prefix none` prints each root as
# `<name> v<version> (<path>)`, so the root's own line is what tells a rendered
# graph from a capture of cargo's progress. Both runners make that test, and one
# owner of it is one place for it to stay strict.
#
# Returns 1 for a capture that named the root nowhere and for a matcher that
# never ran. A caller must not tell those apart in its own favour, because
# neither inspected anything; the distinction is reported here, and the caller
# writes one refusal naming the claim it was proving.
tree_names_root() {
    local capture="$1" root="$2" count
    count=$(match_count "^${root} v" "${capture}")
    if [ "${count}" = "matcher-failed" ]; then
        echo "error: the ${root} matcher failed against ${capture}, so the capture was never read" >&2
        return 1
    fi
    [ "${count}" -ne 0 ]
}

# Fail unless a closure capture names none of these packages.
assert_no_forbidden_packages() {
    local label="$1" capture="$2" package count
    shift 2
    for package in "$@"; do
        count=$(match_count "^${package} v" "${capture}")
        case "${count}" in
            matcher-failed)
                fail "${label}: the forbidden-package matcher failed, so the closure is unproven"
                return 1
                ;;
            0) ;;
            *)
                fail "${label}: the closure reaches the forbidden package ${package}"
                return 1
                ;;
        esac
    done
}

# Fail unless a closure capture enables none of these features, under any package.
assert_no_forbidden_features() {
    local label="$1" capture="$2" feature count
    shift 2
    for feature in "$@"; do
        count=$(match_count " feature \"${feature}\"" "${capture}")
        case "${count}" in
            matcher-failed)
                fail "${label}: the forbidden-feature matcher failed, so the closure is unproven"
                return 1
                ;;
            0) ;;
            *)
                fail "${label}: the closure enables the forbidden feature ${feature}"
                return 1
                ;;
        esac
    done
}

# Fail unless a closure capture names no rust-analyzer package.
#
# rust-analyzer is a family under one prefix rather than a name, so it is
# detected by prefix and only then named in the report. The listing is a second
# matcher run and its status is read too: a violation is reported whether or not
# the names could be collected, because the count above already decided it.
#
# The character class admits `-`, because `ra_ap_load-cargo` is a real member of
# the family and `pedant-core` declares it. A class of letters, digits, and `_`
# alone matched every other `ra_ap_*` package and missed that one, so a closure
# that pulled in the loader and nothing else passed both runners clean.
assert_no_rust_analyzer_edges() {
    local label="$1" capture="$2" count found
    count=$(match_count '^ra_ap_[a-z0-9_-]+ v' "${capture}")
    case "${count}" in
        matcher-failed)
            fail "${label}: the rust-analyzer matcher failed, so the closure is unproven"
            return 1
            ;;
        0)
            return 0
            ;;
    esac
    found="$(rg --only-matching '^ra_ap_[a-z0-9_-]+' -- "${capture}" | sort -u)" || found=""
    if [ -z "${found}" ]; then
        found="${count} matching lines that could not be listed"
    fi
    fail "${label}: the closure names rust-analyzer crates: ${found//$'\n'/ }"
    return 1
}
