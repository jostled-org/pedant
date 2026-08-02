#!/usr/bin/env bash
#
# Prove that `pedant-lang` keeps its published feature surface and forwards
# every backend to `pedant-syntax`.
#
# Every tree-sitter crate moved to `pedant-syntax`, so `pedant-lang` must:
#   * expose exactly `default` plus the five `ts-*` features it always had,
#   * keep the same five-entry `default` array,
#   * map each `ts-X` to `pedant-syntax/ts-X` and nothing else, and
#   * name no tree-sitter package at all — not a grammar, and not the
#     `tree-sitter` crate itself. Its analyzer signatures reach `Node` through
#     the `pedant-syntax` re-export, so one pin governs both crates and a
#     parser bump cannot link two incompatible node types.
#
# Two more assertions guard the same claim from the two ends of one edge.
#
# `pedant-syntax`'s own `default` array is empty. "Every feature is off by
# default" is a contract, not a coincidence. The moment `pedant-syntax` gains a
# default feature, both consumers inherit a grammar, and `cargo test -p
# pedant-lang --no-default-features` — the only configuration that reaches the
# regex fallback — stops meaning what it says.
#
# `pedant-lang`'s edge to `pedant-syntax` turns nothing on either: no feature
# list, and default features off. An empty `default` on the far side says
# nothing about what the near side asks for. `features = ["ts-python"]` on this
# one edge links the Python grammar into every `--no-default-features` build
# while every assertion above still passes, and the regex fallback goes
# untested under the command named to test it.
#
# Array equality rejects a missing, wrong, or extra backend edge; the dependency
# predicate rejects parser-ownership residue. Both `default` arrays are sorted
# before comparison, matching the order-insensitive `keys` comparison above
# them: alphabetizing a manifest array changes nothing and must not turn CI red.
# The metadata is captured before `jq` reads it, so a cargo failure propagates
# with cargo's own message instead of masquerading as drift. Writes no file.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=check_lib.sh
. "${script_dir}/check_lib.sh"

cd_repo_root

require_tools cargo jq

# `$found` and `$syntax` are jq bindings, and jq spells its variables the way
# the shell does. Single quotes are what keep this a jq program; the shell must
# not expand any of it.
# shellcheck disable=SC2016
predicate='
[.packages[] | select(.name == "pedant-lang")] as $found
| [.packages[] | select(.name == "pedant-syntax")] as $syntax
| ($found | length) == 1
  and ($syntax | length) == 1
  and (($found[0].features | keys)
       == ["default", "ts-bash", "ts-go", "ts-javascript", "ts-python", "ts-typescript"])
  and (($found[0].features.default | sort)
       == (["ts-python", "ts-javascript", "ts-typescript", "ts-go", "ts-bash"] | sort))
  and (["python", "javascript", "typescript", "go", "bash"]
       | all($found[0].features["ts-\(.)"] == ["pedant-syntax/ts-\(.)"]))
  and ([$found[0].dependencies[].name
        | select(. == "tree-sitter" or startswith("tree-sitter-"))]
       | length) == 0
  and ($syntax[0].features.default == [])
  and ([$found[0].dependencies[] | select(.name == "pedant-syntax")] | length) == 1
  and ($found[0].dependencies[] | select(.name == "pedant-syntax")
       | .features == [] and .uses_default_features == false)
'

metadata="$(workspace_metadata)"

assert_jq "${metadata}" "${predicate}" -- \
    "error: pedant-lang feature forwarding drifted." \
    "Expected features default + ts-{python,javascript,typescript,go,bash}," \
    "each ts-X == [pedant-syntax/ts-X], no direct tree-sitter dependency," \
    "an empty pedant-syntax default array, and a pedant-syntax edge that" \
    "enables no feature and no default features."

echo "pedant-lang feature forwarding check: clean"
