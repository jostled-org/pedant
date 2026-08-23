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
# `check_tree_closure` in `repository_check_lib.sh` owns the capture, the
# specification vocabulary, the derived forbid set, and the non-vacuity
# refusals, because the syntax, graph, and resolution closure checks prove the
# same shape of claim about their own subjects. This file states the rows.
#
# Reads the workspace and writes no file. Exit 0 clean, exit 1 on violation.

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

# Cargo's default edge kinds, named so the choice is visible: dev edges stay
# out, and build and proc-macro edges stay in. A `[build-dependencies]` on the
# Go grammar links it just as surely as a normal one.
readonly EDGE_KINDS="normal,build"

# ---------------------------------------------------------------------------
# Default-off: no Go grammar reaches a build that asked for none.
# ---------------------------------------------------------------------------

check_tree_closure "go core-default" \
    -p pedant-core -e "${EDGE_KINDS}" -- \
    member:pedant-core member:pedant-types \
    require:pedant-core require:pedant-types require:syn \
    feature:pedant-core/checks \
    no-feature:pedant-core/go-resolution \
    absent:pedant-syntax absent:tree-sitter absent:tree-sitter-go \
    no-prefix:ra_ap_

check_tree_closure "go core-no-default" \
    -p pedant-core --no-default-features -e "${EDGE_KINDS}" -- \
    member:pedant-core member:pedant-types \
    require:pedant-core require:pedant-types \
    feature:syn/visit \
    no-feature:pedant-core/checks no-feature:pedant-core/go-resolution \
    no-feature:pedant-core/semantic \
    absent:pedant-syntax absent:tree-sitter absent:tree-sitter-go \
    no-prefix:ra_ap_

check_tree_closure "go graph-default" \
    -p pedant-graph -e "${EDGE_KINDS}" -- \
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

# The five sibling grammars a Go-enabled build must leave behind, and the
# generic recognizer none of them is needed to turn on.
#
# `pedant-syntax` selects one backend per feature, and `go-resolution` asks for
# `ts-go` alone. `ts-go` is the one `ts-*` feature that does not enable
# `_ts_generic`, so forbidding the five siblings does not forbid `_ts_generic`:
# it can be turned on by itself, and a one-character slip would compile the
# whole generic recognizer into every Go build with nothing red. The manifest
# claims in prose that a Go-only build compiles no generic recognizer at all,
# and this is where that claim is checked.
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
    no-feature:pedant-syntax/_ts_generic
)

check_tree_closure "go core-go-only" \
    -p pedant-core --no-default-features --features go-resolution -e "${EDGE_KINDS}" -- \
    member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-core require:pedant-syntax require:tree-sitter require:tree-sitter-go \
    feature:pedant-core/go-resolution feature:pedant-syntax/ts-go \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    absent:line-index \
    "${OTHER_GRAMMARS[@]}" \
    no-prefix:ra_ap_

check_tree_closure "go graph-go-only" \
    -p pedant-graph --no-default-features --features go -e "${EDGE_KINDS}" -- \
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

check_tree_closure "go unified-core-and-graph" \
    -p pedant-core -p pedant-graph --no-default-features \
    --features pedant-core/go-resolution,pedant-graph/go -e "${EDGE_KINDS}" -- \
    member:pedant-graph member:pedant-core member:pedant-types member:pedant-syntax \
    require:pedant-graph require:pedant-core require:pedant-syntax require:tree-sitter-go \
    feature:pedant-graph/go feature:pedant-core/go-resolution feature:pedant-syntax/ts-go \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    absent:line-index \
    "${OTHER_GRAMMARS[@]}" \
    no-prefix:ra_ap_

assert_no_violations "the Go feature closure drifted."

echo "go dependency closure check: clean"
