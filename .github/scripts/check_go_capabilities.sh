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
# `repository_check_lib.sh` owns the tree listing, the mirror, the sentinel
# bodies, the reach proof, the pedant command, and the read-only profile
# predicate, because the syntax and graph capability checks make the same
# argument about their own trees. This check states its trees and nothing else.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`,
# and a match there both enters the wrong directory and prints it — leaving
# `script_dir` a two-line value naming a tree this repository does not own.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
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

# Each sentinel takes the mirrored path of one real source, so the file set the
# reach guard ranges over is the file set the profile ranges over.
assert_capability_detectors_live "the Go surface" \
    "${CORE_TREE}" "${SYNTAX_TREE}" "${GRAPH_TREE}"

profile="$(pedant_capabilities "${CORE_TREE}" "${SYNTAX_TREE}" "${GRAPH_TREE}")"

assert_only_file_read_under "${profile}" "${CORE_TREE}" "Go" \
    "${SYNTAX_TREE} and ${GRAPH_TREE} take text and facts, so neither may" \
    "state a capability at all."

echo "go capability profile check: clean"
