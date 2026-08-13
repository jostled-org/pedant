#!/usr/bin/env bash
#
# Prove the two new first-party source trees stay read-only, and that only the
# snippet tool touches the filesystem at all.
#
# `pedant-syntax` extraction is pure: it takes source text and returns a span.
# `pedant-snippet` is the one crate that opens a path. Pedant's own capability
# detection is the check, so a new write, spawn, or network call in either tree
# fails here rather than arriving as a documented exception.
#
# The path predicate is segment-anchored, so a repository-relative finding and
# an absolute one both resolve to the same crate. The profile is captured into a
# shell variable before `jq` reads it, so a cargo failure propagates with cargo's
# own message instead of masquerading as drift; no profile file is written, and
# pedant is built from this workspace rather than taken from `PATH` or
# `PEDANT_BIN`.
#
# Pedant reports findings and nothing else, so a tree it never opened and a tree
# with nothing to report print the same empty list. The profile's `any` conjunct
# catches a snippet tree that went entirely unread, but not a file of it that
# did: `all` says nothing about a finding that was never produced, so a write in
# a file the scan skipped reads as clean. Both trees carry the `all`, so both
# need the reach proved first, independently of the profile:
#   * each tree must hold Rust source at all, counted here in bash;
#   * every `.rs` file of both trees, mirrored under one temporary root, must
#     come back as a finding. Three directories hold all 22 sources, so the
#     mirror is per file rather than per directory.
#   * each sentinel names all four capabilities the profile rules on, and each
#     one is counted on its own. The profile admits `file_read` and forbids
#     write, spawn, and network, and that forbid half is an `all` over what is
#     in practice a one-element list. A sentinel that only reads a file proves
#     only that the `file_read` detector is live.
#
# `repository_check_lib.sh` owns the source listing and its count, the mirror,
# the sentinel bodies, the reach predicate, and the pedant command because the
# graph capability check makes the same argument about a third tree.
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
# directory". Repository checks share it because each reads a workspace and
# none may read the caller's.
cd_repo_root

require_tools cargo jq find mktemp dirname

# The trees this check constrains. `.github/workflows/ci.yml` scans the same
# two among all eight; here they are the whole subject.
readonly SYNTAX_TREE="pedant-syntax/src"
readonly SNIPPET_TREE="pedant-snippet/src"

# The listing the mirror reproduces, and the count it is held to, taken per tree
# so an empty tree is named on its own. `repository_check_lib.sh` owns both
# because the graph check mirrors a third tree from the same listing.
#
# The listing is captured before the mirror reads it. Feeding the loop from a
# process substitution puts `find` in a subshell whose exit status neither
# `set -e` nor `pipefail` observes, so a `find` that died after emitting one
# path would leave one sentinel and a count of one, and the equality inside
# `mirror_sentinels` would compare that against itself and pass.
sentinels=0
tree_sources=""
for tree in "${SYNTAX_TREE}" "${SNIPPET_TREE}"; do
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

reach="$(pedant_capabilities "${mirror}/${SYNTAX_TREE}" "${mirror}/${SNIPPET_TREE}")"
assert_sentinel_reach "${reach}" "${sentinels}" "${SYNTAX_TREE} and ${SNIPPET_TREE}"

predicate='
all(.findings[];
     .capability == "file_read"
     and (.location.file | test("(^|/)pedant-snippet/src/")))
and any(.findings[];
     .capability == "file_read"
     and (.location.file | test("(^|/)pedant-snippet/src/")))
'

profile="$(pedant_capabilities "${SYNTAX_TREE}" "${SNIPPET_TREE}")"

assert_jq "${profile}" "${predicate}" -- \
    "error: first-party syntax capability profile drifted." \
    "Expected only file_read findings, every one under ${SNIPPET_TREE}," \
    "and at least one such finding."

echo "syntax capability profile check: clean"
