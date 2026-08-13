#!/usr/bin/env bash
#
# Keep pedant-graph's production and test dependency surfaces closed.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root
require_tools cargo jq

readonly ALLOWED_TEST_CORE_FEATURE='pedant-core feature "resolution-test-support"'

contains_line() {
    local haystack="$1" needle="$2" line
    while IFS= read -r line; do
        if [ "${line}" = "${needle}" ]; then
            return 0
        fi
    done <<<"${haystack}"
    return 1
}

tree_contains_package() {
    local tree="$1" package="$2" line
    while IFS= read -r line; do
        case "${line}" in
            "${package} v"*) return 0 ;;
        esac
    done <<<"${tree}"
    return 1
}

assert_rendered_graph() {
    local label="$1" tree="$2" root
    for root in pedant-graph pedant-core; do
        if ! tree_contains_package "${tree}" "${root}"; then
            echo "error: ${label} dependency capture names no ${root} root" >&2
            return 1
        fi
    done
}

assert_closed_packages() {
    local label="$1" tree="$2" package
    shift 2
    for package in "$@"; do
        if tree_contains_package "${tree}" "${package}"; then
            echo "error: ${label} closure reaches forbidden package ${package}" >&2
            return 1
        fi
    done
}

assert_closed_features() {
    local label="$1" tree="$2" line
    while IFS= read -r line; do
        case "${line}" in
            *' feature "checks"'* | *' feature "semantic"'*)
                echo "error: ${label} closure enables forbidden edge ${line}" >&2
                return 1
                ;;
            "ra_ap_"*" v"*)
                echo "error: ${label} closure reaches rust-analyzer package ${line%% v*}" >&2
                return 1
                ;;
        esac
    done <<<"${tree}"
}

assert_production_core_features() {
    local tree="$1" line
    while IFS= read -r line; do
        case "${line}" in
            'pedant-core feature "'*)
                echo "error: production closure enables ${line}" >&2
                return 1
                ;;
        esac
    done <<<"${tree}"
}

assert_test_core_features() {
    local tree="$1" line allowed=0
    while IFS= read -r line; do
        case "${line}" in
            "${ALLOWED_TEST_CORE_FEATURE}" | "${ALLOWED_TEST_CORE_FEATURE} (*)")
                allowed=$((allowed + 1))
                ;;
            'pedant-core feature "'*)
                echo "error: test closure enables unmodelled edge ${line}" >&2
                return 1
                ;;
        esac
    done <<<"${tree}"
    if [ "${allowed}" -eq 0 ]; then
        echo "error: test closure does not enable ${ALLOWED_TEST_CORE_FEATURE}" >&2
        return 1
    fi
}

members="$(workspace_metadata | jq -r '.packages[].name')"
for required in pedant-graph pedant-core pedant-types; do
    if ! contains_line "${members}" "${required}"; then
        echo "error: workspace metadata omits required graph member ${required}" >&2
        exit 1
    fi
done

forbidden=(line-index pedant-process-guard)
while IFS= read -r member; do
    case "${member}" in
        pedant-graph | pedant-core | pedant-types) ;;
        "") ;;
        *) forbidden+=("${member}") ;;
    esac
done <<<"${members}"
if [ "${#forbidden[@]}" -le 2 ]; then
    echo "error: workspace metadata produced no forbidden workspace members" >&2
    exit 1
fi

production="$(cargo tree -p pedant-graph --no-default-features \
    --edges normal,build,features --prefix none)"
test_closure="$(cargo tree -p pedant-graph --no-default-features \
    --edges normal,build,dev,features --prefix none)"

assert_rendered_graph production "${production}"
assert_rendered_graph test "${test_closure}"
assert_closed_packages production "${production}" "${forbidden[@]}"
assert_closed_packages test "${test_closure}" "${forbidden[@]}"
assert_closed_features production "${production}"
assert_closed_features test "${test_closure}"
assert_production_core_features "${production}"
assert_test_core_features "${test_closure}"

echo "graph dependency closure check: clean"
