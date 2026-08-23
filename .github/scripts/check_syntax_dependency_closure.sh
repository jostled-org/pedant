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
# `pedant-core` and `pedant-lang` are sibling libraries, and neither may reach
# the other. `pedant-lang` reaches `pedant-syntax` for the grammars it analyzes;
# `pedant-core` reaches it for the Go module resolution surface. Both edges run
# down into the substrate, so neither is a cycle. The edge that would break the
# shape runs the other way. `pedant-syntax` states no reachable sibling, so
# every one is forbidden to it.
#
# Each package states only what it may reach. Everything else in the workspace
# is forbidden, derived from `cargo metadata` rather than restated here, so a
# new crate is closed to both packages the day it joins the workspace. A
# hand-written forbid list is the wrong shape: it was already missing
# `pedant-syntax` -> `pedant-mcp`, which is both a cycle and the exact failure
# this file names.
#
# Three specifications say what may be reached:
#   * `member:<package>` — a workspace member this row may reach at all.
#     Everything else in the workspace is forbidden to it.
#   * `direct:<package>` — a DIRECT edge this package must declare, read from a
#     second `--depth 1` capture. Transitive satisfaction would let the manifest
#     and the documented shape disagree, as it did while `pedant-snippet`
#     claimed a `pedant-types` edge it reached only through `pedant-syntax`.
#   * `require:<package>` — an edge admitted anywhere in the closure, declared
#     nowhere. `pedant-snippet` sees `pedant-types` through `pedant-syntax`, and
#     that is the substrate working as designed. It is still a sentinel: a
#     capture that came back short is one the forbid checks would read as clean.
#
# `check_tree_closure` in `repository_check_lib.sh` owns the capture, the
# vocabulary, the derived forbid set, and both non-vacuity refusals, because the
# go, graph, and resolution closure checks prove the same shape of claim about
# their own subjects. This file states the rows.
#
# The edge set is `normal,build`, which is cargo's default and therefore also
# includes proc-macro edges. `-e normal` alone dropped a fifth of the graph: a
# `[build-dependencies] pedant-core` on `pedant-syntax` is still a cycle and
# still drags the engine into a snippet build.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`, and
# a match there both enters the wrong directory and prints it — leaving
# `script_dir` a two-line value naming a tree this repository does not own.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root

require_tools cargo jq rg

# The edges every capture reads. Cargo's default kinds, named so the choice is
# visible: dev edges stay out, and build and proc-macro edges stay in.
readonly EDGE_KINDS="normal,build"

check_tree_closure "syntax pedant-syntax" \
    -p pedant-syntax --all-features -e "${EDGE_KINDS}" -- \
    member:pedant-syntax member:pedant-types \
    require:pedant-syntax direct:pedant-types

check_tree_closure "syntax pedant-snippet" \
    -p pedant-snippet --all-features -e "${EDGE_KINDS}" -- \
    member:pedant-snippet member:pedant-syntax member:pedant-types \
    require:pedant-snippet require:pedant-types direct:pedant-syntax

# `pedant-lang` is the substrate's other consumer, and its closure carries the
# same claim: it reaches `pedant-syntax` and `pedant-types` and nothing else, so
# a `pedant-core` edge between the two sibling libraries fails here rather than
# landing green.
check_tree_closure "syntax pedant-lang" \
    -p pedant-lang --all-features -e "${EDGE_KINDS}" -- \
    member:pedant-lang member:pedant-syntax member:pedant-types \
    require:pedant-lang direct:pedant-syntax direct:pedant-types

# The other direction of the same sibling claim. `pedant-core` reaches the
# substrate directly and nothing else. Its `pedant-syntax` edge is the one
# `go-resolution` selects: default-off, versioned, and carrying the Go grammar
# alone. `direct:` rather than `require:` is the point — the edge must stay
# declared in this manifest. A `pedant-core` that reached the grammar through a
# sibling would read it from beside itself, not below. Its forbid set is derived
# the same way every other one is, so `pedant-snippet` and `pedant-lang` are
# closed to it without being named here.
check_tree_closure "syntax pedant-core" \
    -p pedant-core --all-features -e "${EDGE_KINDS}" -- \
    member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-core direct:pedant-types direct:pedant-syntax

assert_no_violations "syntax dependency closure drifted."

echo "syntax dependency closure check: clean"
