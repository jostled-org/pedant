#!/usr/bin/env bash
#
# Shared helpers for repository boundary checks.
#
# All four checks prove a claim about the workspace's shape, and all four prove
# it the same way: confirm the tools resolve, capture cargo's output into a
# shell variable, then read that capture with one `jq` predicate. Stated once, a
# fix to the tool message or the failure report reaches every check instead of
# one.
#
# The capability checks run pedant's own detection over first-party trees and
# prove the detectors are live before trusting a clean profile. One source
# listing, one spelling of the pedant command, one sentinel mirror, and one
# reach predicate keep that guard consistent across callers.
#
# This file is sourced, never executed. It defines functions and runs nothing,
# so the caller keeps its own shell options and exit contract.

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
# A false predicate returns 1 rather than exiting. `assert_jq` below is the
# `set -e` form used by checks that stop at the first failed predicate. A jq
# that never evaluated the predicate exits from either form, because "the
# check did not run" is not a result a caller may accept.
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
# Capability scanning shared by repository checks
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
# Both forms are used from callers rather than here.
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
