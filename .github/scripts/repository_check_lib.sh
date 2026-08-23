#!/usr/bin/env bash
#
# Shared helpers for repository boundary checks.
#
# Every one of these checks proves a claim about the workspace's shape, and
# every one proves it the same way: confirm the tools resolve, capture cargo's
# output into a shell variable, then read that capture with one predicate.
# Stated once, a fix to the tool message or the failure report reaches every
# check instead of one.
#
# The capability checks run pedant's own detection over first-party trees and
# prove the detectors are live before trusting a clean profile. One source
# listing, one spelling of the pedant command, one sentinel mirror, and one
# reach predicate keep that guard consistent across callers.
#
# The dependency-closure checks prove the same claim about four different
# subjects: this configuration reaches these packages with these features and
# nothing else. `check_tree_closure` is that claim stated once, so a capture
# format, a forbid-set derivation, or a non-vacuity refusal is fixed in one
# place rather than in four copies that were already drifting apart.
#
# Every cargo command reached from here runs through `cargo_capture`, so a
# registry outage or a full disk leaves with 75 and the caller retries, instead
# of being reported as the drift the check is named for. That is why this file
# sources `cargo_infrastructure.sh`: it is the one owner of that decision, and a
# check that read a cargo failure as drift would blame a change for the machine.
#
# This file is sourced, never executed. It defines functions and runs nothing,
# so the caller keeps its own shell options and exit contract.

# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/cargo_infrastructure.sh"

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

# ---------------------------------------------------------------------------
# Violations shared by repository checks
# ---------------------------------------------------------------------------

# How many violations the running check has reported.
#
# A boundary check reports every drift it found rather than the first, because
# an operator fixing one row wants the other rows named in the same run. The
# counter is the aggregate that decision needs, and it lives here because three
# checks had already written the same two-line `violation` for it.
CHECK_VIOLATIONS=0

# Report one violation and remember it.
violation() {
    echo "error: $*" >&2
    CHECK_VIOLATIONS=$((CHECK_VIOLATIONS + 1))
}

# Fail with one summary line unless every row of this check was clean.
assert_no_violations() {
    if [ "${CHECK_VIOLATIONS}" -ne 0 ]; then
        echo "error: $1" >&2
        exit 1
    fi
}

# Whether a captured listing holds a line equal to a needle.
#
# The comparison is whole-line, so `pedant` cannot answer a claim about
# `pedant-core`. Three checks had written this byte for byte.
contains_line() {
    local haystack="$1" needle="$2" line
    while IFS= read -r line; do
        if [ "${line}" = "${needle}" ]; then
            return 0
        fi
    done <<<"${haystack}"
    return 1
}

# ---------------------------------------------------------------------------
# Classified cargo invocations whose output the caller reads
# ---------------------------------------------------------------------------

# The combined output of the last `cargo_capture` run.
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
cargo_capture() {
    local label="$1"
    shift
    local code=0
    CARGO_CAPTURE_OUTPUT="$("$@" 2>&1)" || code=$?
    local classified
    classified="$(cargo_classify_output "${code}" "${CARGO_CAPTURE_OUTPUT}")"
    if [ "${classified}" != "${code}" ]; then
        printf '[cargo_infrastructure] %s: INFRASTRUCTURE (exit %s reclassified as %s)\n' \
            "${label}" "${code}" "${classified}"
    fi
    cargo_record "${classified}"
    return "${code}"
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
    # `CDPATH` is cleared inside the substitution: `dirname` yields a bare
    # relative path for a script sourced through a relative path, `cd` then
    # consults `CDPATH`, and a match there both enters the wrong directory and
    # prints it — leaving `lib_dir` a two-line value naming another tree.
    lib_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || lib_dir=""
    if [ -z "${lib_dir}" ]; then
        echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
        exit 1
    fi
    if ! cd -- "${lib_dir}/../.."; then
        echo "error: cannot enter the repository root above ${lib_dir}" >&2
        exit 1
    fi
}

# The workspace's own package list as `cargo metadata` JSON, once loaded.
WORKSPACE_METADATA=""

# Load the workspace's own package list, or leave with cargo's own diagnosis.
#
# `--no-deps` is load-bearing, not a speed-up: it is what makes `.packages[]`
# mean "workspace member" instead of "every crate in the dependency graph".
# Every caller reads the list with that meaning — the closure check derives its
# forbid set from it, and without the flag it forbids all of crates.io. Stated
# once here, so a caller cannot read the list under the wrong meaning.
#
# The document is loaded once and kept, because one closure check reads it for
# every row and a member list cannot change between two rows of one run.
#
# Called in the caller's own shell, so an unavailable registry reaches
# `cargo_record`'s 75 exit rather than a command substitution that swallows it.
load_workspace_metadata() {
    [ -z "${WORKSPACE_METADATA}" ] || return 0
    cargo_capture workspace_metadata cargo metadata --format-version 1 --no-deps || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        echo "error: cannot read this workspace's package list" >&2
        exit 1
    }
    WORKSPACE_METADATA="${CARGO_CAPTURE_OUTPUT}"
}

# Print the workspace's own package list as `cargo metadata` JSON.
workspace_metadata() {
    load_workspace_metadata
    printf '%s\n' "${WORKSPACE_METADATA}"
}

# Print every workspace member except the ones named, one per line.
#
# A closure proof forbids what a package may not reach, and a hand-written
# forbid list is the wrong shape for that: it goes stale the day a member joins,
# and the new member's edge then reads as clean. Every closure row therefore
# states what it may reach and derives the rest here. This is the one deriver:
# `check_tree_closure` calls it for the forbid set and, with no exclusions at
# all, for the member list a `member:` specification is validated against.
#
# The document is loaded before jq reads it, so a `cargo metadata` that failed
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
# Dependency-closure checking shared by repository checks
# ---------------------------------------------------------------------------

# The capture format every closure row is read through.
#
# `{p}` is `<name> v<version> [(source)]` and `{f}` is the comma-separated
# resolved feature list, so one line answers both halves a closure row asks:
# which packages cargo would build, and with which features. A tree rendered
# with `--edges features` cannot answer the second half for a root package,
# because a `feature "…"` node is a property of one parent edge and a root has
# no parent.
CLOSURE_CAPTURE_FORMAT='{p}|{f}'

# Print one capture's resolved packages as `<name> <features>`, one per line.
#
# Cargo prints `(*)` on an already-expanded subtree and repeats a package once
# per path that reaches it, so the listing is deduplicated here. A package that
# resolved to two feature sets keeps both lines, which is the honest rendering:
# a forbid check must see every set cargo would build.
closure_resolved_packages() {
    local line package features
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        package="${line%%|*}"
        features="${line#*|}"
        package="${package%% v*}"
        features="${features% (\*)}"
        printf '%s %s\n' "${package}" "${features}"
    done <<<"$1" | sort -u
}

# Whether one capture holds a package at all.
#
# The name is matched up to the separating space, so `pedant` cannot answer a
# claim about `pedant-core`.
capture_has_package() {
    local capture="$1" package="$2" line
    while IFS= read -r line; do
        case "${line}" in
            "${package} "*) return 0 ;;
        esac
    done <<<"${capture}"
    return 1
}

# Whether one capture holds a package whose name starts with a prefix.
capture_has_prefix() {
    local capture="$1" prefix="$2" line
    while IFS= read -r line; do
        case "${line}" in
            "${prefix}"*) return 0 ;;
        esac
    done <<<"${capture}"
    return 1
}

# Whether a capture resolved `<package>` with `<feature>` enabled.
#
# The feature list is comma-separated, so the needle is matched against a list
# padded on both ends: a bare substring test would let `ts-gopher` satisfy a
# claim about `ts-go`.
capture_has_feature() {
    local capture="$1" package="$2" feature="$3" line features
    while IFS= read -r line; do
        case "${line}" in
            "${package} "*)
                features=",${line#"${package}" },"
                case "${features}" in
                    *",${feature},"*) return 0 ;;
                esac
                ;;
        esac
    done <<<"${capture}"
    return 1
}

# One comma-separated feature list, ordered so two spellings of one set compare
# equal. An empty list orders to the empty string.
sorted_feature_list() {
    local feature ordered=""
    while IFS= read -r feature; do
        [ -n "${feature}" ] || continue
        ordered="${ordered}${feature},"
    done <<<"$(printf '%s\n' "${1//,/$'\n'}" | sort)"
    printf '%s' "${ordered}"
}

# Whether every occurrence of a package resolved exactly the named feature set.
#
# A forbid list of feature names says nothing about the name nobody thought to
# forbid. Where a row's claim is "this package carries these features and no
# other", the whole set is the claim, so the whole set is compared.
capture_features_are_exactly() {
    local capture="$1" package="$2" expected line
    expected="$(sorted_feature_list "$3")"
    while IFS= read -r line; do
        case "${line}" in
            "${package} "*)
                [ "$(sorted_feature_list "${line#"${package}" }")" = "${expected}" ] || return 1
                ;;
        esac
    done <<<"${capture}"
    return 0
}

# Run one dependency-closure configuration against its specifications.
#
# Usage: check_tree_closure <label> <cargo tree args ...> -- <specification ...>
#
# Cargo arguments come first and end at a literal `--`; the caller states the
# roots, the feature selection, and the edge kinds, and this function states the
# capture shape and `--locked`. Each remaining argument is one specification:
#
#   member:<package>            — a workspace member this row may reach
#   require:<package>           — a sentinel package the capture must hold
#   direct:<package>            — a sentinel the capture must hold AND that the
#                                 root must declare directly, read from a second
#                                 `--depth 1` capture. Transitive satisfaction
#                                 would let a manifest and the documented shape
#                                 disagree, as it did while `pedant-snippet`
#                                 claimed a `pedant-types` edge it reached only
#                                 through `pedant-syntax`.
#   feature:<package>/<name>    — a sentinel feature the capture must resolve
#   absent:<package>            — a package the capture must not hold
#   no-feature:<pkg>/<name>     — a feature the capture must not resolve
#   no-prefix:<prefix>          — no package may have a name starting with it
#   only-features:<pkg>/<list>  — that package resolves exactly this comma-
#                                 separated set, everywhere it appears. An empty
#                                 list means it resolves no feature at all.
#
# Every workspace member no `member:` specification admits is forbidden to the
# row, derived rather than restated so a crate is closed the day it joins the
# workspace. The derived set is required to be non-empty: a member list that
# failed to load would forbid nothing and the row would pass having constrained
# nothing.
#
# The sentinels run before every forbid, because a forbid is a statement about a
# capture that has to be the tree it is read as. A capture that came back short,
# or one taken under a feature selection cargo silently ignored, satisfies every
# forbid the same silent way an empty capture would, so a row that states no
# sentinel at all is refused outright.
#
# Every predicate counts the capture in bash rather than through an external
# matcher, which would report "no match" and "the matcher itself failed" through
# the same exit code. A loop cannot fail that way.
check_tree_closure() {
    local label="$1"
    shift
    local args=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        args+=("$1")
        shift
    done
    if [ "${1:-}" != "--" ]; then
        echo "error: ${label} states no '--' between its cargo arguments and its specifications" >&2
        exit 1
    fi
    shift

    local spec kind value package feature
    local admitted=() wants_direct=0 sentinels=0
    for spec in "$@"; do
        case "${spec%%:*}" in
            member) admitted+=("${spec#*:}") ;;
            direct) wants_direct=1 ;;
        esac
    done

    load_workspace_metadata
    local members forbidden forbidden_count=0 member
    members="$(workspace_members_excluding)"
    forbidden="$(workspace_members_excluding ${admitted[@]+"${admitted[@]}"})"

    printf '[closure] %s: cargo tree %s\n' "${label}" "${args[*]}"
    local capture direct_capture=""
    cargo_capture "closure_${label}" cargo tree --locked "${args[@]}" \
        --prefix none --format "${CLOSURE_CAPTURE_FORMAT}" || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        violation "${label} could not capture its dependency tree"
        return
    }
    capture="$(closure_resolved_packages "${CARGO_CAPTURE_OUTPUT}")"
    if [ "${wants_direct}" -eq 1 ]; then
        cargo_capture "closure_${label}_direct" cargo tree --locked "${args[@]}" \
            --depth 1 --prefix none --format "${CLOSURE_CAPTURE_FORMAT}" || {
            printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
            violation "${label} could not capture its direct dependencies"
            return
        }
        direct_capture="$(closure_resolved_packages "${CARGO_CAPTURE_OUTPUT}")"
    fi

    for spec in "$@"; do
        kind="${spec%%:*}"
        value="${spec#*:}"
        package="${value%%/*}"
        feature="${value#*/}"
        case "${kind}" in
            member)
                contains_line "${members}" "${value}" || {
                    echo "error: ${label} admits '${value}', which is not a workspace member" >&2
                    exit 1
                }
                ;;
            require)
                sentinels=$((sentinels + 1))
                capture_has_package "${capture}" "${value}" \
                    || violation "${label} omits sentinel package ${value}; the capture is not the tree it is read as"
                ;;
            direct)
                sentinels=$((sentinels + 1))
                capture_has_package "${capture}" "${value}" \
                    || violation "${label} omits sentinel package ${value}; the capture is not the tree it is read as"
                capture_has_package "${direct_capture}" "${value}" \
                    || violation "${label} must declare a direct dependency on ${value}"
                ;;
            feature)
                sentinels=$((sentinels + 1))
                capture_has_feature "${capture}" "${package}" "${feature}" \
                    || violation "${label} omits sentinel feature ${package}/${feature}; the selection did not take"
                ;;
            absent | no-feature | no-prefix | only-features) ;;
            *)
                echo "error: ${label} states an unknown specification '${spec}'" >&2
                exit 1
                ;;
        esac
    done

    if [ "${sentinels}" -eq 0 ]; then
        echo "error: ${label} states no sentinel, so its forbid checks read an unproven capture" >&2
        exit 1
    fi

    for spec in "$@"; do
        kind="${spec%%:*}"
        value="${spec#*:}"
        package="${value%%/*}"
        feature="${value#*/}"
        case "${kind}" in
            absent)
                ! capture_has_package "${capture}" "${value}" \
                    || violation "${label} reaches forbidden package ${value}"
                ;;
            no-feature)
                ! capture_has_feature "${capture}" "${package}" "${feature}" \
                    || violation "${label} enables forbidden feature ${package}/${feature}"
                ;;
            no-prefix)
                ! capture_has_prefix "${capture}" "${value}" \
                    || violation "${label} reaches a package named ${value}*"
                ;;
            only-features)
                capture_features_are_exactly "${capture}" "${package}" "${feature}" \
                    || violation "${label} resolves ${package} with features other than '${feature}'"
                ;;
        esac
    done

    while IFS= read -r member; do
        [ -n "${member}" ] || continue
        forbidden_count=$((forbidden_count + 1))
        if capture_has_package "${capture}" "${member}"; then
            violation "${label} reaches workspace member ${member}"
        fi
    done <<<"${forbidden}"
    if [ "${forbidden_count}" -eq 0 ]; then
        violation "${label} forbids no workspace member; the member list constrains nothing"
    fi
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

# The listing every named tree's Rust sources form, one path per line.
TREE_SOURCE_LISTING=""

# How many paths that listing holds.
TREE_SOURCE_COUNT=0

# List several trees' Rust sources and count them, leaving both above.
#
# Each tree is guarded and refused on its own, so a tree that is gone and a tree
# that is empty are named rather than folded into one total. An empty tree has
# no capability to report, so a profile read over it would pass without
# constraining anything — the vacuous result every one of these checks exists to
# refuse.
#
# The three capability checks state their trees and nothing else, because the
# loop that reads them was byte-identical in the two that read more than one.
collect_tree_sources() {
    local tree
    TREE_SOURCE_LISTING=""
    TREE_SOURCE_COUNT=0
    for tree in "$@"; do
        if [ ! -d "${tree}" ]; then
            echo "error: ${tree} is missing from the repository." >&2
            exit 1
        fi
        read_rust_sources "${tree}" || {
            echo "error: cannot list the Rust sources of ${tree}." >&2
            exit 1
        }
        if [ "${RUST_SOURCE_COUNT}" -eq 0 ]; then
            echo "error: ${tree} holds no Rust source." >&2
            echo "An empty tree has no capability to report, so the profile below would" >&2
            echo "pass without constraining anything." >&2
            exit 1
        fi
        TREE_SOURCE_COUNT=$((TREE_SOURCE_COUNT + RUST_SOURCE_COUNT))
        TREE_SOURCE_LISTING="${TREE_SOURCE_LISTING}${RUST_SOURCE_LISTING}"$'\n'
    done
}

# Fail unless pedant's detectors reach every source of every named tree.
#
# Every source is mirrored under one temporary root as a sentinel naming all
# four capabilities, and the scan must come back with every one of them for
# every mirrored file. Without that, the forbid half of a profile is an `all`
# over what is normally an empty finding set, and a regressed detector would
# satisfy it by reporting nothing at all.
#
# The mirror is removed on exit. One trap covers it, so a caller states its
# trees and nothing else.
assert_capability_detectors_live() {
    local subject="$1"
    shift
    if [ "$#" -eq 0 ]; then
        echo "error: ${subject} names no tree, so the scan would range over nothing." >&2
        exit 1
    fi
    collect_tree_sources "$@"

    local mirror tree mirrored=()
    mirror="$(mktemp -d)" || {
        echo "error: cannot open a temporary root for the sentinel mirror." >&2
        exit 1
    }
    # The path is expanded as the trap is set, not as it fires: `mirror` is a
    # local, and a trap that read it after this function returned would reach an
    # unset name and remove the working directory instead.
    # shellcheck disable=SC2064
    trap "rm -rf -- \"${mirror}\"" EXIT

    mirror_sentinels "${mirror}" "${TREE_SOURCE_LISTING}" "${TREE_SOURCE_COUNT}" || exit 1

    for tree in "$@"; do
        mirrored+=("${mirror}/${tree}")
    done
    local reach
    reach="$(pedant_capabilities "${mirrored[@]}")"
    assert_sentinel_reach "${reach}" "${TREE_SOURCE_COUNT}" "${subject}"
}

# Fail unless a profile reports file reads alone, all of them under one tree.
#
# Arguments after the subject are further lines of the failure report, so a
# caller can say what its other trees are for.
#
# The path predicate is segment-anchored, so a repository-relative finding and
# an absolute one both resolve to the same tree, and the tree reaches jq as a
# bound variable rather than spliced into the program text.
#
# The `any` conjunct is what keeps the `all` from being vacuous: a scan that
# opened nothing reports nothing, and nothing satisfies `all`.
# shellcheck disable=SC2016
assert_only_file_read_under() {
    local profile="$1" tree="$2" subject="$3"
    shift 3
    assert_jq "${profile}" '
all(.findings[];
     .capability == "file_read"
     and (.location.file | test($anchor)))
and any(.findings[];
     .capability == "file_read"
     and (.location.file | test($anchor)))
' \
        --arg anchor "(^|/)${tree}/" \
        -- \
        "error: the ${subject} capability profile drifted." \
        "Expected only file_read findings, every one under ${tree}," \
        "and at least one such finding." \
        "$@"
}

# ---------------------------------------------------------------------------
