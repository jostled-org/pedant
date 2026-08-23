#!/usr/bin/env bash
#
# Prove the Go feature graph is closed in both directions.
#
# Two claims, and neither one implies the other:
#
#   * A build that selects no Go feature links no Go grammar. `pedant-core`'s
#     `go-resolution` and `pedant-graph`'s `go` are default-off, and a
#     `default-features = true` slip on one manifest edge would put
#     `tree-sitter-go` into every consumer of the analysis engine with nothing
#     else turning red.
#   * A build that selects one links the Go grammar and nothing else. The Go
#     surface is a parser and a resolver; it must not drag in the judgment
#     surface, the semantic tier, rust-analyzer, the CLI, the MCP server, or
#     the process guard.
#
# Each configuration is captured once with `--format '{p}|{f}'`, which prints
# the resolved feature list beside every package cargo would build. That is the
# claim under test stated directly: a `feature "…"` node in the rendered tree
# is a property of one parent edge, and the root package's own selections are
# not rendered as nodes at all, so a tree read line by line cannot answer "is
# `go-resolution` on for `pedant-core` here".
#
# The forbid set is derived from `cargo metadata` rather than written down: a
# hand-written list goes stale the day a member joins the workspace, and the new
# member's edge then reads as clean. Each row names the members it may reach;
# everything else in the workspace is forbidden to it.
#
# Every row states sentinels — packages and features that must be present — and
# they run before the forbid half. A capture that came back short, or one taken
# under a feature selection cargo silently ignored, would satisfy every forbid
# check the same silent way an empty capture would.
#
# Reads the workspace and writes no file. Exit 0 clean, exit 1 on violation.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root
require_tools cargo jq

# Cargo's default edge kinds, named so the choice is visible: dev edges stay
# out, and build and proc-macro edges stay in. A `[build-dependencies]` on the
# Go grammar links it just as surely as a normal one.
readonly EDGE_KINDS="normal,build"

# The capture format. `{p}` is `<name> v<version> [(source)]` and `{f}` is the
# comma-separated resolved feature list, so one line answers both halves.
readonly CAPTURE_FORMAT='{p}|{f}'

# The workspace's members, and the aggregate exit every row folds into.
members=""
status=0

# Report one violation and remember it.
violation() {
    echo "error: $*" >&2
    status=1
}

contains_line() {
    local haystack="$1" needle="$2" line
    while IFS= read -r line; do
        if [ "${line}" = "${needle}" ]; then
            return 0
        fi
    done <<<"${haystack}"
    return 1
}

# Print one configuration's resolved packages as `<name> <features>`.
#
# Cargo prints `(*)` on an already-expanded subtree and repeats a package once
# per path that reaches it, so the listing is deduplicated here. A package that
# resolved to two feature sets would keep both lines, which is the honest
# rendering: a forbid check must see every set cargo would build.
resolved_packages() {
    local line package features
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        package="${line%%|*}"
        features="${line#*|}"
        package="${package%% v*}"
        features="${features% (\*)}"
        printf '%s %s\n' "${package}" "${features}"
    done | sort -u
}

# Whether one capture holds a package at all.
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

# Every workspace member this row does not admit must be absent from it.
#
# Derived, and required to be non-empty: a member list that failed to load would
# forbid nothing and the row would pass having constrained nothing.
assert_derived_members_are_absent() {
    local label="$1" capture="$2" admitted="$3" member forbidden=0
    while IFS= read -r member; do
        [ -n "${member}" ] || continue
        if contains_line "${admitted}" "${member}"; then
            continue
        fi
        forbidden=$((forbidden + 1))
        if capture_has_package "${capture}" "${member}"; then
            violation "${label} reaches workspace member ${member}"
        fi
    done <<<"${members}"
    if [ "${forbidden}" -eq 0 ]; then
        violation "${label} forbids no workspace member; the member list constrains nothing"
    fi
}

# Run one configuration against its specifications.
#
# Cargo arguments come first and end at a literal `--`. Each remaining argument
# is one specification:
#
#   member:<package>          — a workspace member this row may reach
#   require:<package>         — a sentinel package the capture must hold
#   absent:<package>          — a package the capture must not hold
#   feature:<package>/<name>  — a sentinel feature the capture must resolve
#   no-feature:<pkg>/<name>   — a feature the capture must not resolve
#   no-prefix:<prefix>        — no package may have a name starting with it
#
# The sentinels run first and are counted, because every forbid below is a
# statement about a capture that has to be the tree it is read as.
check_configuration() {
    local label="$1" capture spec kind value package feature admitted="" sentinels=0
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

    printf '[go-closure] configuration %s: cargo tree %s\n' "${label}" "${args[*]}"
    capture="$(cargo tree --locked "${args[@]}" -e "${EDGE_KINDS}" \
        --prefix none --format "${CAPTURE_FORMAT}" | resolved_packages)"

    for spec in "$@"; do
        kind="${spec%%:*}"
        value="${spec#*:}"
        package="${value%%/*}"
        feature="${value#*/}"
        case "${kind}" in
            member)
                admitted="${admitted}${value}"$'\n'
                ;;
            require)
                sentinels=$((sentinels + 1))
                capture_has_package "${capture}" "${value}" ||
                    violation "${label} omits sentinel package ${value}; the capture is not the tree it is read as"
                ;;
            feature)
                sentinels=$((sentinels + 1))
                capture_has_feature "${capture}" "${package}" "${feature}" ||
                    violation "${label} omits sentinel feature ${package}/${feature}; the selection did not take"
                ;;
            absent)
                capture_has_package "${capture}" "${value}" &&
                    violation "${label} reaches forbidden package ${value}"
                ;;
            no-feature)
                capture_has_feature "${capture}" "${package}" "${feature}" &&
                    violation "${label} enables forbidden feature ${package}/${feature}"
                ;;
            no-prefix)
                capture_has_prefix "${capture}" "${value}" &&
                    violation "${label} reaches a package named ${value}*"
                ;;
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
    assert_derived_members_are_absent "${label}" "${capture}" "${admitted}"
}

members="$(workspace_metadata | jq -r '.packages[].name')"
for required in pedant-core pedant-graph pedant-syntax pedant-types; do
    if ! contains_line "${members}" "${required}"; then
        echo "error: workspace metadata omits required member ${required}" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Default-off: no Go grammar reaches a build that asked for none.
# ---------------------------------------------------------------------------

check_configuration core-default \
    -p pedant-core -- \
    member:pedant-core member:pedant-types \
    require:pedant-core require:pedant-types require:syn \
    feature:pedant-core/checks \
    no-feature:pedant-core/go-resolution \
    absent:pedant-syntax absent:tree-sitter absent:tree-sitter-go \
    no-prefix:ra_ap_

check_configuration core-no-default \
    -p pedant-core --no-default-features -- \
    member:pedant-core member:pedant-types \
    require:pedant-core require:pedant-types \
    feature:syn/visit \
    no-feature:pedant-core/checks no-feature:pedant-core/go-resolution \
    no-feature:pedant-core/semantic \
    absent:pedant-syntax absent:tree-sitter absent:tree-sitter-go \
    no-prefix:ra_ap_

check_configuration graph-default \
    -p pedant-graph -- \
    member:pedant-graph member:pedant-core member:pedant-types \
    require:pedant-graph require:pedant-core require:pedant-types \
    feature:serde/rc \
    no-feature:pedant-graph/go no-feature:pedant-core/go-resolution \
    no-feature:pedant-core/checks \
    absent:pedant-syntax absent:tree-sitter absent:tree-sitter-go \
    no-prefix:ra_ap_

# ---------------------------------------------------------------------------
# Go-only: the Go grammar and nothing beside it.
# ---------------------------------------------------------------------------

# The five grammars a Go-enabled build must leave behind. `pedant-syntax`
# selects one backend per feature, and `go-resolution` asks for `ts-go` alone.
readonly OTHER_GRAMMARS=(
    absent:tree-sitter-python
    absent:tree-sitter-javascript
    absent:tree-sitter-typescript
    absent:tree-sitter-bash
    no-feature:pedant-syntax/rust
    no-feature:pedant-syntax/ts-python
    no-feature:pedant-syntax/ts-javascript
    no-feature:pedant-syntax/ts-typescript
    no-feature:pedant-syntax/ts-bash
)

check_configuration core-go-only \
    -p pedant-core --no-default-features --features go-resolution -- \
    member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-core require:pedant-syntax require:tree-sitter require:tree-sitter-go \
    feature:pedant-core/go-resolution feature:pedant-syntax/ts-go \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    absent:line-index \
    "${OTHER_GRAMMARS[@]}" \
    no-prefix:ra_ap_

check_configuration graph-go-only \
    -p pedant-graph --no-default-features --features go -- \
    member:pedant-graph member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-graph require:pedant-core require:pedant-syntax require:tree-sitter-go \
    feature:pedant-graph/go feature:pedant-core/go-resolution feature:pedant-syntax/ts-go \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    no-feature:pedant-core/resolution-test-support \
    absent:line-index \
    "${OTHER_GRAMMARS[@]}" \
    no-prefix:ra_ap_

# ---------------------------------------------------------------------------
# Unified: both Go features resolved together in one graph.
#
# Cargo unifies features across a build, so the two rows above passing
# separately says nothing about the graph a consumer of both crates gets. This
# is the configuration that ships.
# ---------------------------------------------------------------------------

check_configuration unified-core-and-graph-go \
    -p pedant-core -p pedant-graph --no-default-features \
    --features pedant-core/go-resolution,pedant-graph/go -- \
    member:pedant-graph member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-graph require:pedant-core require:pedant-syntax require:tree-sitter-go \
    feature:pedant-graph/go feature:pedant-core/go-resolution feature:pedant-syntax/ts-go \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    absent:line-index \
    "${OTHER_GRAMMARS[@]}" \
    no-prefix:ra_ap_

if [ "${status}" -ne 0 ]; then
    echo "error: the Go feature closure drifted." >&2
    exit 1
fi

echo "go dependency closure check: clean"
