#!/usr/bin/env bash
#
# Prove the Go surface reads source files and does nothing else.
#
# Three first-party trees implement Go analysis, and each has its own claim:
#
#   * `pedant-syntax/src/go` takes source text and returns facts. It opens
#     nothing.
#   * `pedant-core/src/resolution/go` is the one tree that opens a path — a
#     `go.mod` and a `.go` source, both inside the root the caller supplied.
#   * `pedant-graph/src/go` projects already-validated resolution facts. It
#     opens nothing.
#
# So the profile admits `file_read` under the core resolution tree and nothing
# anywhere else: no write, no spawn, no network, and no read from the parser or
# the projector.
#
# Pedant reports findings and nothing else, so a tree it never opened and a tree
# with nothing to report print the same empty list. The forbid half is an `all`
# over what is normally a short list, and a regressed detector would satisfy it
# by reporting nothing at all. Every source of all three trees is therefore
# mirrored under one temporary root as a sentinel that names all four
# capabilities, and the scan must come back with every one of them for every
# mirrored file before the real profile is read.
#
# `repository_check_lib.sh` owns the source listing, the mirror, the sentinel
# bodies, the reach predicate, and the pedant command, because the syntax and
# graph capability checks make the same argument about their own trees.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

# Every path below is repository-relative, and the mirror reproduces those
# relative paths under one temporary root. `cd_repo_root` is what makes the `-d`
# guards below mean "the trees are gone" instead of "you stood in the wrong
# directory".
cd_repo_root

require_tools cargo jq find mktemp dirname

# The one tree a Go analysis may open a path from.
readonly CORE_TREE="pedant-core/src/resolution/go"

# The two trees that take text and return values.
readonly SYNTAX_TREE="pedant-syntax/src/go"
readonly GRAPH_TREE="pedant-graph/src/go"

sentinels=0
tree_sources=""
for tree in "${CORE_TREE}" "${SYNTAX_TREE}" "${GRAPH_TREE}"; do
    if [ ! -d "${tree}" ]; then
        echo "error: ${tree} is missing from the repository." >&2
        exit 1
    fi
    read_rust_sources "${tree}"
    if [ "${RUST_SOURCE_COUNT}" -eq 0 ]; then
        echo "error: ${tree} holds no Rust source." >&2
        echo "An empty tree has no capability to report, so the profile below would" >&2
        echo "pass without constraining anything." >&2
        exit 1
    fi
    sentinels=$((sentinels + RUST_SOURCE_COUNT))
    tree_sources="${tree_sources}${RUST_SOURCE_LISTING}"$'\n'
done

mirror="$(mktemp -d)"
trap 'rm -rf "${mirror}"' EXIT

# Each sentinel takes the mirrored path of one real source, so the file set the
# reach guard ranges over is the file set the profile ranges over. A count that
# disagrees with the one above returns 1, and `set -e` stops here.
mirror_sentinels "${mirror}" "${tree_sources}" "${sentinels}"

reach="$(pedant_capabilities \
    "${mirror}/${CORE_TREE}" "${mirror}/${SYNTAX_TREE}" "${mirror}/${GRAPH_TREE}")"
assert_sentinel_reach "${reach}" "${sentinels}" \
    "${CORE_TREE}, ${SYNTAX_TREE}, and ${GRAPH_TREE}"

# The path predicate is segment-anchored, so a repository-relative finding and
# an absolute one both resolve to the same tree.
predicate='
all(.findings[];
     .capability == "file_read"
     and (.location.file | test("(^|/)pedant-core/src/resolution/go/")))
and any(.findings[];
     .capability == "file_read"
     and (.location.file | test("(^|/)pedant-core/src/resolution/go/")))
'

profile="$(pedant_capabilities "${CORE_TREE}" "${SYNTAX_TREE}" "${GRAPH_TREE}")"

assert_jq "${profile}" "${predicate}" -- \
    "error: the Go capability profile drifted." \
    "Expected only file_read findings, every one under ${CORE_TREE}," \
    "and at least one such finding. ${SYNTAX_TREE} and ${GRAPH_TREE} take" \
    "text and facts, so neither may state a capability at all."

echo "go capability profile check: clean"
