#!/usr/bin/env bash
#
# Keep the parse-only resolution substrate independent of rust-analyzer.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root
require_tools cargo

tree="$(cargo tree -p pedant-core --no-default-features \
    --features resolution-test-support --edges normal --prefix none)"

root_found=0
status=0
while IFS= read -r line; do
    case "${line}" in
        "pedant-core v"*) root_found=1 ;;
        "line-index v"* | "ra_ap_"*" v"*)
            echo "error: the parse-only resolution closure reaches ${line%% v*}" >&2
            status=1
            ;;
    esac
done <<<"${tree}"

if [ "${root_found}" -ne 1 ]; then
    echo "error: the dependency capture names no pedant-core root" >&2
    status=1
fi

if [ "${status}" -ne 0 ]; then
    exit 1
fi

echo "resolution dependency closure check: clean"
