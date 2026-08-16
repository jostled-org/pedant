#!/bin/sh
# The stand-in release-plz.
#
# It records whether the pinned semver checker reached its PATH — the real tool
# consults that binary to decide whether this tree's API change requires a major
# version — and then stages the versions, requirements, and changelogs the real
# tool would have written into the isolated clone.

set -eu

state="${FAKE_STATE_DIR}"

case "${1:-}" in
    --version)
        printf 'version release-plz\n' >> "${state}/operations"
        printf 'release-plz 0.3.160\n'
        ;;
    update)
        presence=absent
        if command -v cargo-semver-checks > /dev/null 2>&1; then
            presence=present
        fi
        printf 'update release-plz semver-checks-%s\n' "${presence}" >> "${state}/operations"
        cp -R "${FAKE_STAGED_TREE}/." .
        ;;
    *)
        printf 'error: the fake release-plz does not implement %s\n' "${1:-}" >&2
        exit 2
        ;;
esac
