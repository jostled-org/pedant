#!/usr/bin/env bash
#
# Keep pedant-graph's production and test dependency surfaces closed.
#
# `pedant-graph` projects resolution facts. Production reaches `pedant-core` and
# `pedant-types` with no `pedant-core` feature at all; the test surface adds
# exactly one, `resolution-test-support`. Neither surface may reach the judgment
# tier, the semantic tier, rust-analyzer, or the process guard.
#
# The feature claims are whole-set rather than a forbid list, because a forbid
# list says nothing about the feature nobody thought to forbid.
#
# `check_tree_closure` in `repository_check_lib.sh` owns the capture, the
# vocabulary, the derived forbid set, and both non-vacuity refusals, because the
# go, syntax, and resolution closure checks prove the same shape of claim about
# their own subjects. This file states the rows.
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

# The two packages outside this workspace that neither surface may reach.
# `line-index` arrives with the semantic tier; `pedant-process-guard` is a
# workspace-excluded test helper, so the derived member forbid set cannot name
# either of them.
readonly OUTSIDE_MEMBERS=(
    absent:line-index
    absent:pedant-process-guard
)

check_tree_closure "graph production" \
    -p pedant-graph --no-default-features -e normal,build -- \
    member:pedant-graph member:pedant-core member:pedant-types \
    require:pedant-graph require:pedant-core \
    only-features:pedant-core/ \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    "${OUTSIDE_MEMBERS[@]}" \
    no-prefix:ra_ap_

check_tree_closure "graph test" \
    -p pedant-graph --no-default-features -e normal,build,dev -- \
    member:pedant-graph member:pedant-core member:pedant-types \
    require:pedant-graph require:pedant-core \
    feature:pedant-core/resolution-test-support \
    only-features:pedant-core/resolution-test-support \
    no-feature:pedant-core/checks no-feature:pedant-core/semantic \
    "${OUTSIDE_MEMBERS[@]}" \
    no-prefix:ra_ap_

assert_no_violations "graph dependency closure drifted."

echo "graph dependency closure check: clean"
