#!/usr/bin/env bash
#
# Prove that graph projection reads no files, writes no files, starts no
# processes, and opens no network connections.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root
require_tools cargo jq find mktemp dirname

readonly GRAPH_SOURCE_TREE="pedant-graph/src"

if [ ! -d "${GRAPH_SOURCE_TREE}" ]; then
    echo "error: ${GRAPH_SOURCE_TREE} is missing from the repository" >&2
    exit 1
fi

read_rust_sources "${GRAPH_SOURCE_TREE}"
sources="${RUST_SOURCE_LISTING}"
sentinels="${RUST_SOURCE_COUNT}"
if [ "${sentinels}" -eq 0 ]; then
    echo "error: ${GRAPH_SOURCE_TREE} holds no Rust source" >&2
    exit 1
fi

mirror="$(mktemp -d)"
trap 'rm -rf "${mirror}"' EXIT
mirror_sentinels "${mirror}" "${sources}" "${sentinels}"

reach="$(pedant_capabilities "${mirror}/${GRAPH_SOURCE_TREE}")"
assert_sentinel_reach "${reach}" "${sentinels}" "${GRAPH_SOURCE_TREE}"

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
