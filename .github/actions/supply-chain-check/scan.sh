#!/usr/bin/env bash

set -euo pipefail

BASELINE_PATH="${BASELINE_PATH:-.pedant/baselines}"
FAIL_ON="${FAIL_ON:-hash-mismatch}"
UPDATE_BASELINES="${UPDATE_BASELINES:-false}"

if [ "$UPDATE_BASELINES" = "true" ]; then
  exec pedant supply-chain update --baseline-path "$BASELINE_PATH"
fi

exec pedant supply-chain verify --baseline-path "$BASELINE_PATH" --fail-on "$FAIL_ON"
