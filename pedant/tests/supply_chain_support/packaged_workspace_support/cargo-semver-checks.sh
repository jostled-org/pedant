#!/bin/sh
# The stand-in cargo-semver-checks. Being the pinned version is its whole job.

set -eu

printf 'version cargo-semver-checks\n' >> "${FAKE_STATE_DIR}/operations"
printf 'cargo-semver-checks 0.48.0\n'
