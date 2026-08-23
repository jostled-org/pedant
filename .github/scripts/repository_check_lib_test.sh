#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

# Keep this test independent of the live workspace inventory. The closure row
# needs one forbidden member so its derived forbid set remains non-vacuous.
load_workspace_metadata() {
    :
}

workspace_members_excluding() {
    case "$#" in
        0)
            printf '%s\n' pedant-core pedant-graph forbidden-member
            ;;
        *)
            printf '%s\n' forbidden-member
            ;;
    esac
}

# Model Cargo under CI's forced-color environment. Cargo colors the duplicate
# marker unless the machine-readable invocation explicitly disables color.
cargo() {
    local argument color=always
    for argument in "$@"; do
        case "${argument}" in
            --color=never) color=never ;;
            --color) ;;
            never) color=never ;;
        esac
    done

    printf '%s\n' 'pedant-graph v0.3.0|'
    printf '%s\n' 'pedant-core v0.22.0|resolution-test-support'
    case "${color}" in
        never)
            printf '%s\n' 'pedant-core v0.22.0|resolution-test-support (*)'
            ;;
        always)
            printf 'pedant-core v0.22.0|resolution-test-support \033[33m\033[2m(*)\033[39m\033[22m\n'
            ;;
    esac
}

check_tree_closure "forced-color capture" \
    -p pedant-graph --no-default-features -e normal,build,dev -- \
    member:pedant-graph member:pedant-core \
    require:pedant-graph require:pedant-core \
    feature:pedant-core/resolution-test-support \
    only-features:pedant-core/resolution-test-support

assert_no_violations "machine-readable cargo tree output is not color-safe"
