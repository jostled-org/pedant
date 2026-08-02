#!/usr/bin/env bash
#
# Prove the syntax substrate's dependency direction.
#
# `pedant-syntax` owns classification, parser selection, and extraction over
# `pedant-types` alone. `pedant-snippet` owns file reading and both transports
# over `pedant-syntax`. Neither may reach the Rust analysis engine, the
# capability analyzers, or the MCP index: `pedant-lang` already depends on
# `pedant-syntax`, so a reverse edge is a cycle, and a `pedant-core` or
# `pedant-mcp` edge would drag the whole engine into a snippet build.
#
# `pedant-core` and `pedant-lang` are sibling libraries over `pedant-types`
# alone, and both directions of that are checked. Proving only that
# `pedant-lang` misses `pedant-core` leaves a `pedant-core` -> `pedant-syntax`
# edge free to land, and that edge breaks the same shape from the other side.
#
# Each package states only what it may reach. Everything else in the workspace
# is forbidden, derived from `cargo metadata` rather than restated here, so a
# new crate is closed to both packages the day it joins the workspace. A
# hand-written forbid list is the wrong shape: it was already missing
# `pedant-syntax` -> `pedant-mcp`, which is both a cycle and the exact failure
# this file names.
#
# Two spellings say what may be reached:
#   * `require:<package>` — a DIRECT edge this package must declare. Transitive
#     satisfaction would let the manifest and the documented shape disagree, as
#     it did while `pedant-snippet` claimed a `pedant-types` edge it reached
#     only through `pedant-syntax`.
#   * `allow:<package>` — an edge admitted anywhere in the closure, required
#     nowhere. `pedant-snippet` sees `pedant-types` through `pedant-syntax`, and
#     that is the substrate working as designed.
#
# Each package's `cargo tree` is captured once and every predicate counts the
# whole capture in bash. An external matcher would report "no match" and "the
# matcher itself failed" through the same exit code, so a broken tool would
# satisfy every forbid check silently. A loop cannot fail that way. `jq` reads
# the member list only, and an empty or truncated list would empty the derived
# forbid set the same silent way — so the list must name every package under
# check, every package their specs name, and enough members to forbid. The
# closure capture carries the same requirement from the other side: every
# `require:` and `allow:` dependency must appear in it, because a capture that
# came back short is one the forbid checks would read as clean.
#
# The edge set is `normal,build`, which is cargo's default and therefore also
# includes proc-macro edges. `-e normal` alone dropped a fifth of the graph: a
# `[build-dependencies] pedant-core` on `pedant-syntax` is still a cycle and
# still drags the engine into a snippet build.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=check_lib.sh
. "${script_dir}/check_lib.sh"

cd_repo_root

require_tools cargo jq

# The edges every capture reads. Cargo's default kinds, named so the choice is
# visible: dev edges stay out, and build and proc-macro edges stay in.
readonly EDGE_KINDS="normal,build"

# `cargo tree --prefix none` prints one `<name> v<version>` per line, so a
# `<name> v` prefix match counts every occurrence — including the `(*)` repeats
# cargo prints for an already-expanded subtree.
count_dependency() {
    local tree="$1" package="$2" line matches=0
    while IFS= read -r line; do
        case "${line}" in
            "${package} v"*) matches=$((matches + 1)) ;;
        esac
    done <<<"${tree}"
    printf '%s' "${matches}"
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

metadata="$(workspace_metadata)"
members="$(printf '%s\n' "${metadata}" | jq -r '.packages[].name')"

status=0

# Each remaining argument is `require:<package>` or `allow:<package>`.
check_closure() {
    local package="$1" closure direct spec mode dependency reachable member forbidden=0
    shift

    if ! contains_line "${members}" "${package}"; then
        echo "error: '${package}' is not a workspace member; the member list did not load" >&2
        status=1
        return
    fi

    closure="$(cargo tree -p "${package}" --all-features -e "${EDGE_KINDS}" --prefix none)"
    direct="$(cargo tree -p "${package}" --all-features -e "${EDGE_KINDS}" --prefix none --depth 1)"

    reachable="${package}"
    for spec in "$@"; do
        mode="${spec%%:*}"
        dependency="${spec#*:}"
        case "${mode}" in
            require | allow) ;;
            *)
                echo "error: unknown closure mode '${mode}' in '${spec}'" >&2
                exit 1
                ;;
        esac
        if ! contains_line "${members}" "${dependency}"; then
            echo "error: '${dependency}' in '${spec}' is not a workspace member" >&2
            status=1
        fi
        if [ "${mode}" = require ] && [ "$(count_dependency "${direct}" "${dependency}")" = "0" ]; then
            echo "error: ${package} must declare a direct dependency on ${dependency}" >&2
            status=1
        fi
        # The closure capture is what every forbid check below reads, and an
        # empty one empties the derived forbid set the same silent way a
        # truncated member list would. `set -e` covers a cargo tree that fails;
        # it says nothing about one that succeeds and returns less than it
        # should. Each spec is the guarantee in hand: a `require:` or `allow:`
        # dependency is in the closure by definition, so its absence means the
        # capture is not the tree it is read as.
        if [ "$(count_dependency "${closure}" "${dependency}")" = "0" ]; then
            echo "error: ${dependency} is absent from ${package}'s closure capture;" >&2
            echo "the forbid checks below would read an empty tree and pass." >&2
            status=1
        fi
        reachable="${reachable}"$'\n'"${dependency}"
    done

    while IFS= read -r member; do
        if contains_line "${reachable}" "${member}"; then
            continue
        fi
        forbidden=$((forbidden + 1))
        if [ "$(count_dependency "${closure}" "${member}")" != "0" ]; then
            echo "error: ${package} must not depend on ${member}" >&2
            status=1
        fi
    done <<<"${members}"

    if [ "${forbidden}" -eq 0 ]; then
        echo "error: no package is forbidden to ${package}; the member list constrains nothing" >&2
        status=1
    fi
}

check_closure pedant-syntax \
    require:pedant-types

check_closure pedant-snippet \
    require:pedant-syntax \
    allow:pedant-types

# `pedant-lang` is the substrate's other consumer, and its closure carries the
# same claim: it reaches `pedant-syntax` and `pedant-types` and nothing else, so
# a `pedant-core` edge between the two sibling libraries fails here rather than
# landing green.
check_closure pedant-lang \
    require:pedant-syntax \
    require:pedant-types

# The other direction of the same sibling claim. `pedant-lang` not reaching
# `pedant-core` says nothing about `pedant-core` reaching `pedant-syntax`, and
# that edge would put the whole analysis engine inside the substrate it is
# supposed to sit above. Its forbid set is derived the same way every other one
# is, so `pedant-syntax`, `pedant-snippet`, and `pedant-lang` are all closed to
# it without being named here.
check_closure pedant-core \
    require:pedant-types

if [ "${status}" -ne 0 ]; then
    echo "error: syntax dependency closure drifted." >&2
    exit 1
fi

echo "syntax dependency closure check: clean"
