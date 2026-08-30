#!/usr/bin/env bash
#
# Prove the syntax substrate's dependency direction.
#
# `pedant-syntax` owns classification, parser selection, and extraction over
# `pedant-types` alone. It may reach no sibling: `pedant-lang` and `pedant-core`
# already depend on it, so a reverse edge is a cycle, and a `pedant-mcp` edge
# would drag the whole engine into every substrate build.
#
# `pedant-snippet` is a consumer of the substrate and states no row here.
# `check_code_intelligence_dependency_closure.sh` owns its closure, across every
# feature profile it ships rather than the one profile a row here could name —
# including the two workspace members `graph-rust` and `graph-go` select. A row
# here would be a second authority for the same claim, and it was: it forbade
# `pedant-core` and `pedant-graph` to a package whose graph features had been
# built on both since they were introduced.
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
#
# Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds and
# stays put, so `script_dir` comes back non-empty and names whatever directory
# the caller stood in. The library this script is about to source is what says
# the resolution landed beside the script, and an unreadable library is an
# unavailable machine rather than the drift this check is named for.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ] || [ ! -r "${script_dir}/repository_check_lib.sh" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh" || exit 75

cd_repo_root

require_tools cargo jq rg

check_tree_closure "syntax pedant-syntax" \
    -p pedant-syntax --all-features -e "${CLOSURE_EDGE_KINDS}" -- \
    member:pedant-syntax member:pedant-types \
    require:pedant-syntax direct:pedant-types

# `pedant-lang` is the substrate's other consumer, and its closure carries the
# same claim: it reaches `pedant-syntax` and `pedant-types` and nothing else, so
# a `pedant-core` edge between the two sibling libraries fails here rather than
# landing green.
check_tree_closure "syntax pedant-lang" \
    -p pedant-lang --all-features -e "${CLOSURE_EDGE_KINDS}" -- \
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
    -p pedant-core --all-features -e "${CLOSURE_EDGE_KINDS}" -- \
    member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-core direct:pedant-types direct:pedant-syntax

assert_no_violations "syntax dependency closure drifted."

echo "syntax dependency closure check: clean"
