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

# The same guarded prologue every caller of this file carries, for the same
# reason and one step further down.
#
# A caller's `. "${script_dir}/repository_check_lib.sh" || exit 75` cannot see
# through this line: sourcing returns the status of the LAST command in the
# sourced file, which here is a function definition, so an unguarded source that
# failed would still leave this file with 0 and every caller's guard satisfied.
# With `cargo_infrastructure.sh` unread, `require_tools`, `rg_status`,
# `rg_status_over`, `cargo_capture`, and `cargo_run` are all "command not
# found" — and `set -e` is off in every row table that reads this file, so
# `require_tools` becomes a 127 no-op and a machine with no `jq` or `cargo` is
# reported as a clean repository. The exit is therefore taken here, where the
# failure is visible.
#
# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a file sourced by a relative path, `cd` then consults `CDPATH`, and a
# match there both enters the wrong directory and prints it.
#
# Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds and
# stays put, so `pwd` answers with the caller's own directory and the guard sees
# a non-empty value naming a tree that holds none of these files. The
# readability probe is what proves the resolution landed beside this file.
#
# The directory is named `REPOSITORY_CHECK_LIB_DIR` rather than `script_dir`,
# which is the name every caller resolves itself into: a sourced file assigning
# that name would overwrite the caller's own answer.
REPOSITORY_CHECK_LIB_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" \
    || REPOSITORY_CHECK_LIB_DIR=""
if [ -z "${REPOSITORY_CHECK_LIB_DIR}" ] \
    || [ ! -r "${REPOSITORY_CHECK_LIB_DIR}/cargo_infrastructure.sh" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${REPOSITORY_CHECK_LIB_DIR}/cargo_infrastructure.sh" || exit 75

# `require_tools`, `rg_status`, `rg_status_over`, and `cargo_capture` are
# `cargo_infrastructure.sh`'s and reach every caller of this file through the
# source above. They live there rather than here because the packaged-workspace
# proof and the two lifecycle runners source that file alone, and a probe with
# two owners is a probe two owners can disagree about.

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
#
# The status is the caller's, because only the caller knows what its own
# refusal means. A boundary check's drift is 1; the code-intelligence admission
# gate's unmet prerequisite is 64, which sends its caller to the plan rather
# than to the repository. That gate had written the counter, the reporter, and
# this refusal out line for line to change one number.
assert_no_violations() {
    if [ "${CHECK_VIOLATIONS}" -ne 0 ]; then
        echo "error: $1" >&2
        exit "${2:-1}"
    fi
}

# How many non-empty lines one newline-separated document holds.
#
# Every row table, every source listing, and every derived member list asks this
# question, and three copies of it had answered differently: one read a ripgrep
# matcher failure as a count of zero, and `wc -l` has the other half of the
# problem, because a listing of no rows is still one empty line. A loop over
# non-empty lines has neither hazard.
count_nonempty_lines() {
    local line count=0
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        count=$((count + 1))
    done <<<"$1"
    printf '%s' "${count}"
}

# How many separator-delimited fields one row states.
#
# A reader that splits on the first separator truncates a row that holds one
# too many to its prefix, which makes a required claim weaker rather than
# louder — and a row table's needles are exactly where a separator is the
# natural thing to write. Counted so a malformed row is refused where it is
# read.
count_fields() {
    local rest="$1" separator="$2" fields=1
    while [ "${rest}" != "${rest#*"${separator}"}" ]; do
        rest="${rest#*"${separator}"}"
        fields=$((fields + 1))
    done
    printf '%s' "${fields}"
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

# Whether a captured text holds one fixed substring anywhere.
#
# `contains_line` above answers the whole-line question; this answers the
# substring one, which is what a claim about a sentence inside a paragraph needs.
# Written as a `case` rather than through an external matcher for the reason the
# rest of this file gives: a matcher that failed to run and a document that does
# not state the claim leave through statuses a caller can confuse.
holds_text() {
    case "$1" in
        *"$2"*) return 0 ;;
    esac
    return 1
}

# One document with every run of whitespace reduced to a single space.
#
# A claim read out of prose is a claim about a sentence, and a sentence is the
# same claim whether its author's editor wrapped it at seventy-eight columns or
# left it on one line. A comparison over raw bytes would go red the day somebody
# reflowed a paragraph, and — worse — would push the next author toward claims
# short enough to survive wrapping, which is how a documentation contract stops
# asking anything.
#
# Stated here because the documentation check and its row table both need it, and
# two copies of a reduction are two ways to disagree about what a document says.
#
# Word splitting is the reduction: `set -f` keeps a `*` in the text from being
# read as a glob, and `"$*"` rejoins the fields with the first character of
# `IFS`. Bash's own `${var%%…}` and `${var#…}` are quadratic in the subject, so a
# reduction written with them costs eighteen seconds on a three-hundred-kilobyte
# document; this costs a twentieth of a second.
#
# The caller's own globbing is restored rather than turned on. Every call today
# sits inside a command substitution, so an unconditional `set +f` reaches no
# caller — but this is a shared library, and the first caller that reduces a
# document with `noglob` set would have it silently taken away.
collapse_whitespace() {
    local IFS=$' \t\n' joined had_noglob=""
    case $- in
        *f*) had_noglob=1 ;;
    esac
    set -f
    # Word splitting is the point.
    # shellcheck disable=SC2086
    set -- $1
    joined="$*"
    [ -n "${had_noglob}" ] || set +f
    printf '%s' "${joined}"
}

# ---------------------------------------------------------------------------
# Classified cargo invocations whose output the caller reads
# ---------------------------------------------------------------------------

# Run one lint or documentation command that no other job reaches.
#
# Usage: check_command <prefix> <label> <command> [args ...]
#
# The prefix is the tag its caller's matrix prints, and it is the only thing the
# two configuration checks did not share: the rest of this function was
# byte-identical in both, down to the order of the two printfs. A failure is
# folded into the aggregate rather than left to `set -e`, so one run names every
# command that failed instead of the first.
check_command() {
    local prefix="$1" label="$2"
    shift 2
    local failed=""
    printf '%s %s: %s\n' "${prefix}" "${label}" "$*"
    cargo_capture "${label}" "$@" || failed=1
    printf '%s\n' "${CARGO_CAPTURE_OUTPUT}"
    [ -z "${failed}" ] || violation "${label} failed"
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
    #
    # Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds
    # and stays put, so `pwd` would answer with the caller's own directory and
    # `lib_dir` would be non-empty and wrong. This file's own presence beside
    # `lib_dir` is what says the resolution landed where this function was
    # defined.
    lib_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || lib_dir=""
    if [ -z "${lib_dir}" ] || [ ! -r "${lib_dir}/repository_check_lib.sh" ]; then
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

# The edges every closure row reads.
#
# Cargo's own default kinds, named so the choice is visible: dev edges stay out,
# and build and proc-macro edges stay in. A `[build-dependencies]` on a grammar
# links it just as surely as a normal one, and `-e normal` alone dropped a fifth
# of the graph. Three closure checks had stated the constant and a paraphrase of
# that reasoning each, beside the capture format they already read from here.
#
# Not `readonly`: this file is sourced by checks that may declare their own
# copy while they are being brought over, and a sealed name would abort the
# source rather than the row.
#
# Read by the closure checks that source this file.
# shellcheck disable=SC2034
CLOSURE_EDGE_KINDS='normal,build'

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
#
# A capture holding the package nowhere matches nothing, and a loop that matched
# nothing used to return 0 — so the row passed having compared no feature set at
# all. The occurrences are counted and none is a refusal.
capture_features_are_exactly() {
    local capture="$1" package="$2" expected line matched=0
    expected="$(sorted_feature_list "$3")"
    while IFS= read -r line; do
        case "${line}" in
            "${package} "*)
                matched=$((matched + 1))
                [ "$(sorted_feature_list "${line#"${package}" }")" = "${expected}" ] || return 1
                ;;
        esac
    done <<<"${capture}"
    [ "${matched}" -ne 0 ]
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
    # The list a `member:` claim is validated against, guarded the way the
    # forbid set below is. Unguarded, a jq that failed left it empty and every
    # `member:` specification was then refused with "which is not a workspace
    # member" — a false statement about this repository, from the reader rather
    # than from the row, and the operator sent to a manifest that is correct.
    if [ "$(count_nonempty_lines "${members}")" -eq 0 ]; then
        echo "error: ${label} read no workspace member at all; the member list could not be taken" >&2
        exit 1
    fi
    forbidden="$(workspace_members_excluding ${admitted[@]+"${admitted[@]}"})"

    printf '[closure] %s: cargo tree %s\n' "${label}" "${args[*]}"
    local capture direct_capture=""
    cargo_capture "closure_${label}" cargo tree --locked --color never "${args[@]}" \
        --prefix none --format "${CLOSURE_CAPTURE_FORMAT}" || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        violation "${label} could not capture its dependency tree"
        return
    }
    capture="$(closure_resolved_packages "${CARGO_CAPTURE_OUTPUT}")"
    if [ "${wants_direct}" -eq 1 ]; then
        cargo_capture "closure_${label}_direct" cargo tree --locked --color never "${args[@]}" \
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
                # The absence is named on its own, because "resolves other
                # features" is the wrong sentence for a capture that holds no
                # such package at all.
                if ! capture_has_package "${capture}" "${package}"; then
                    violation "${label} states only-features for ${package}, which the capture does not hold"
                elif ! capture_features_are_exactly "${capture}" "${package}" "${feature}"; then
                    violation "${label} resolves ${package} with features other than '${feature}'"
                fi
                ;;
        esac
    done

    forbidden_count="$(count_nonempty_lines "${forbidden}")"
    if [ "${forbidden_count}" -eq 0 ]; then
        violation "${label} forbids no workspace member; the member list constrains nothing"
    fi
    while IFS= read -r member; do
        [ -n "${member}" ] || continue
        if capture_has_package "${capture}" "${member}"; then
            violation "${label} reaches workspace member ${member}"
        fi
    done <<<"${forbidden}"
}

# ---------------------------------------------------------------------------
# Capability scanning shared by repository checks
# ---------------------------------------------------------------------------

# Build pedant from this workspace and read a tree's capability profile into
# `CARGO_CAPTURE_OUTPUT`.
#
# Every capability check runs it twice — once over a sentinel mirror and once
# over the real tree — and one decision with several call sites is several places
# for it to drift to a `PATH` binary that is not this tree's.
#
# Routed through `cargo_capture` for the reason this file's header gives. A bare
# `cargo run` here left a registry outage or a full disk with 1 under the
# caller's `set -e`, and every one of these checks reports a 1 as the capability
# drift it is named for — the machine blamed on the source.
#
# The profile lands in the shared capture variable rather than on standard
# output, because `cargo_record` leaves the whole shell with 75 for an
# unavailable machine and a command substitution around this function would
# leave from a subshell instead.
read_pedant_capabilities() {
    cargo_capture pedant_capabilities cargo run --quiet -p pedant -- capabilities "$@"
}

# The same scan for a caller that reads the profile through a command
# substitution.
#
# Two forms for the reason `check_jq` and `assert_jq` are two forms. This one is
# taken in a subshell, so the 75 above reaches the caller as the substitution's
# own status; every caller of this form runs under `set -e`, which is what turns
# that status back into the exit the classifier intended. A failed scan replays
# cargo's message on the diagnostic stream, which the capture would otherwise
# hold and nobody would read.
pedant_capabilities() {
    local status=0
    read_pedant_capabilities "$@" || status=$?
    if [ "${status}" -ne 0 ]; then
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        return "${status}"
    fi
    printf '%s\n' "${CARGO_CAPTURE_OUTPUT}"
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
# The count is then taken from the listing by `count_nonempty_lines`, which is
# the one counter in this repository for the reason its own comment gives.
#
# An empty tree is a count of zero and the caller's own refusal, not a failure
# here: the two callers say different things about it. Returning 1 means the
# listing could not be taken at all.
read_rust_sources() {
    local tree="$1"
    RUST_SOURCE_LISTING=""
    RUST_SOURCE_COUNT=0
    RUST_SOURCE_LISTING="$(find -- "${tree}" -type f -name '*.rs')" || return 1
    RUST_SOURCE_COUNT="$(count_nonempty_lines "${RUST_SOURCE_LISTING}")"
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
    # Read in this shell rather than through a command substitution, so a
    # registry outage or a full disk during the sentinel scan leaves with the
    # classifier's 75 instead of being reported as a detector that went quiet.
    local reach
    read_pedant_capabilities "${mirrored[@]}" || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        echo "error: pedant could not scan the sentinel mirror of ${subject}." >&2
        exit 1
    }
    reach="${CARGO_CAPTURE_OUTPUT}"
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

# Fail unless a profile reports file reads, hashing, one exit status, and one
# elapsed span alone, all under one tree.
#
# The same claim as `assert_only_file_read_under` for a tree whose product is a
# command-line application watching a directory. A revision is a hash of what
# was admitted, so the tree that mints one imports a hasher, and a predicate
# forbidding `crypto` here would forbid the capability the closure was audited
# to hold. A command states its outcome as an exit status, and the only stable
# way to state one is `std::process::ExitCode` — which the Rust detector
# resolves by module prefix,
# so it arrives as `process_exec` beside the spawns that prefix normally means.
# A watcher coalescing a burst of reports has to bound the wait it opens, and the
# only clock that cannot run backwards under it is `std::time::Instant` — which
# the detector reports as `system_time` beside the wall clocks that name
# normally means.
#
# Both admissions are spelled out as evidence rather than waived as
# capabilities: a `process_exec` finding whose evidence is not the exit-status
# type fails, so `std::process::Command` in this tree is refused exactly as
# before, and a `system_time` finding whose evidence is not the monotonic clock
# fails, so a wall-clock reading — which would put the host's time-of-day into a
# revision — is refused too. The four `any` conjuncts are load-bearing for the
# reason the one above is — a regressed detector reports nothing, and nothing
# satisfies `all`.
# shellcheck disable=SC2016
assert_only_read_digest_exit_status_and_elapsed_under() {
    local profile="$1" tree="$2" subject="$3"
    shift 3
    assert_jq "${profile}" '
def admitted:
    .capability == "file_read"
    or .capability == "crypto"
    or (.capability == "process_exec" and (.evidence | startswith($exit_status)))
    or (.capability == "system_time" and (.evidence | startswith($monotonic)));
all(.findings[]; admitted and (.location.file | test($anchor)))
and any(.findings[]; .capability == "file_read" and (.location.file | test($anchor)))
and any(.findings[]; .capability == "crypto" and (.location.file | test($anchor)))
and any(.findings[]; .capability == "process_exec" and (.location.file | test($anchor)))
and any(.findings[]; .capability == "system_time" and (.location.file | test($anchor)))
' \
        --arg anchor "(^|/)${tree}/" \
        --arg exit_status "std::process::ExitCode" \
        --arg monotonic "std::time::Instant" \
        -- \
        "error: the ${subject} capability profile drifted." \
        "Expected only file_read, crypto, std::process::ExitCode, and" \
        "std::time::Instant findings, every one under ${tree}, and at least one" \
        "of each." \
        "$@"
}

# Fail unless a profile reports nothing at all.
#
# The claim a pure tree makes: it takes source text and returns a span, so it
# opens no path, writes nothing, spawns nothing, reaches no network, and asks no
# clock. There is no `any` conjunct to keep this honest, because the claim is
# that there is nothing to find — so the whole non-vacuity argument is
# `assert_capability_detectors_live`, which says the four detectors that would
# have reported are live over exactly these files.
#
# Arguments after the subject are further lines of the failure report.
assert_no_capability_under() {
    local profile="$1" subject="$2"
    shift 2
    assert_jq "${profile}" '(.findings | length) == 0' \
        -- \
        "error: the ${subject} capability profile drifted." \
        "Expected no finding at all." \
        "$@"
}
