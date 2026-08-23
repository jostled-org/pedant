#!/usr/bin/env bash
#
# Keep the parse-only resolution substrate independent of rust-analyzer.
#
# `pedant-core` with `resolution-test-support` and no default feature is the
# profile the resolution proofs run under. It parses; it does not analyze. So it
# reaches `pedant-types` and nothing else in this workspace, and neither
# `line-index` nor any `ra_ap_*` crate outside it.
#
# `check_tree_closure` in `repository_check_lib.sh` owns the capture, the
# vocabulary, the derived forbid set, and both non-vacuity refusals, because the
# go, syntax, and graph closure checks prove the same shape of claim about their
# own subjects. This file states the row.
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

check_tree_closure "resolution parse-only" \
    -p pedant-core --no-default-features --features resolution-test-support \
    -e normal -- \
    member:pedant-core member:pedant-types \
    require:pedant-core require:pedant-types \
    feature:pedant-core/resolution-test-support \
    absent:line-index \
    no-prefix:ra_ap_

assert_no_violations "the parse-only resolution closure drifted."

echo "resolution dependency closure check: clean"
