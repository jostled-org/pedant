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
    docs/scripts/check_*.sh \
    docs/scripts/cargo_infrastructure.sh \
    docs/scripts/verify_step.sh \
    docs/scripts/verify_affected.sh \
    docs/scripts/run_resolution_proof.sh \
    docs/scripts/run_graph_proof.sh \
    docs/scripts/run_shellcheck.sh
