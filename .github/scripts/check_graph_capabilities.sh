#!/usr/bin/env bash
#
# Prove that graph projection reads no files, writes no files, starts no
# processes, and opens no network connections.

set -euo pipefail

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`,
# and a match there both enters the wrong directory and prints it — leaving
# `script_dir` a two-line value naming a tree this repository does not own.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root
require_tools cargo jq find mktemp dirname

readonly GRAPH_SOURCE_TREE="pedant-graph/src"

assert_capability_detectors_live "graph projection" "${GRAPH_SOURCE_TREE}"

profile="$(pedant_capabilities "${GRAPH_SOURCE_TREE}")"
# shellcheck disable=SC2016
assert_jq "${profile}" '
.findings as $findings
| $capabilities
| all(. as $capability
      | ([$findings[] | select(.capability == $capability)] | length) == 0)
' \
    --argjson capabilities "${SENTINEL_CAPABILITIES}" \
    -- \
    "error: ${GRAPH_SOURCE_TREE} reports a direct file-read, file-write," \
    "process-execution, or network site."

echo "graph capability profile check: clean"
