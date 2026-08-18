#!/bin/sh
# The stand-in du one packaged-workspace budget row installs on PATH.
#
# The proof measures the caller's target root and its own staging root with
# `du -sk` and refuses a stage that grew either past its budget. No row can
# fill a disk to see that refusal, so a row that wants one says how big the
# subject is. Every other measurement is the real tool's.

set -eu

subject=""
for argument in "$@"; do
    subject="${argument}"
done

report() {
    printf '%s\t%s\n' "$1" "${subject}"
    exit 0
}

if [ "${subject}" = "${CARGO_TARGET_DIR:-}" ]; then
    if [ -n "${FAKE_DU_TARGET_KIB:-}" ]; then
        counter="${FAKE_STATE_DIR}/du-target-reads"
        reads=0
        if [ -f "${counter}" ]; then
            reads=$(cat "${counter}")
        fi
        reads=$((reads + 1))
        printf '%s\n' "${reads}" > "${counter}"
        # The starting size reads as nothing and every later one as the size
        # this row asked for, so the growth the refusal reports is exactly that
        # size rather than that size less whatever the target already held.
        if [ "${reads}" -gt 1 ]; then
            report "${FAKE_DU_TARGET_KIB}"
        fi
        report 0
    fi
elif [ -n "${FAKE_DU_STAGING_KIB:-}" ]; then
    report "${FAKE_DU_STAGING_KIB}"
fi

command -p du "$@"
exit 0
