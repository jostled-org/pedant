#!/usr/bin/env bash

set -euo pipefail

SHELLCHECK_VERSION="0.11.0"
readonly SHELLCHECK_VERSION

actual_version="$(shellcheck --version | awk '$1 == "version:" { print $2 }')"
case "${actual_version}" in
    "${SHELLCHECK_VERSION}") ;;
    *)
        echo "error: shellcheck ${SHELLCHECK_VERSION} is required; found ${actual_version:-unknown}." >&2
        exit 1
        ;;
esac

exec shellcheck -x \
    .github/scripts/repository_check_lib.sh \
    .github/scripts/cargo_infrastructure.sh \
    .github/scripts/check_go_capabilities.sh \
    .github/scripts/check_go_configurations.sh \
    .github/scripts/check_go_dependency_closure.sh \
    .github/scripts/check_graph_capabilities.sh \
    .github/scripts/check_graph_dependency_closure.sh \
    .github/scripts/check_lang_feature_forwarding.sh \
    .github/scripts/check_packaged_workspace.sh \
    .github/scripts/check_published_manifests.sh \
    .github/scripts/check_release_readiness.sh \
    .github/scripts/check_resolution_dependency_closure.sh \
    .github/scripts/check_syntax_capabilities.sh \
    .github/scripts/check_syntax_dependency_closure.sh \
    .github/scripts/run_exact_rust_test.sh \
    .github/scripts/run_exact_rust_test_test.sh \
    .github/scripts/verify_step.sh \
    .github/scripts/verify_step_selftest.sh \
    .github/scripts/run_shellcheck.sh \
    pedant/tests/supply_chain_support/packaged_workspace_support/cargo-semver-checks.sh \
    pedant/tests/supply_chain_support/packaged_workspace_support/cargo.sh \
    pedant/tests/supply_chain_support/packaged_workspace_support/date.sh \
    pedant/tests/supply_chain_support/packaged_workspace_support/du.sh \
    pedant/tests/supply_chain_support/packaged_workspace_support/release-plz.sh
