#!/bin/sh
# The stand-in cargo-semver-checks. Being the pinned version is its whole job.
#
# It answers exactly one argument list, because the answer is what a warm target
# root is claimed on. A script regression that probed this binary with another
# subcommand or flag would otherwise still read "warm", and every row would
# still pass over a probe nobody answered.

set -eu

case "$*" in
    "semver-checks --version")
        printf 'version cargo-semver-checks\n' >> "${FAKE_STATE_DIR}/operations"
        printf 'cargo-semver-checks 0.48.0\n'
        ;;
    *)
        printf 'error: the fake cargo-semver-checks does not implement [%s]\n' "$*" >&2
        exit 2
        ;;
esac
