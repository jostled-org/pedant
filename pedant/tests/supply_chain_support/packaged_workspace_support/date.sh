#!/bin/sh
# The stand-in date one packaged-workspace budget row installs on PATH.
#
# The proof reads the wall clock through `date +%s` and refuses a stage that
# outran its runtime budget. Those budgets are minutes long and a row is not,
# so a row that wants that refusal supplies the jump rather than waiting for
# it. Every other call is the real tool's.

set -eu

if [ "${1:-}" != "+%s" ] || [ -z "${FAKE_DATE_JUMP_SECONDS:-}" ]; then
    command -p date "$@"
    exit 0
fi

# The first reading starts the stage's clock and is kept, so every later one is
# exactly that far ahead. The elapsed seconds the refusal reports are then the
# jump this row asked for rather than the jump plus however long the row took.
started="${FAKE_STATE_DIR}/date-started"
if [ -f "${started}" ]; then
    printf '%s\n' "$(($(cat "${started}") + FAKE_DATE_JUMP_SECONDS))"
    exit 0
fi

now=$(command -p date +%s)
printf '%s\n' "${now}" > "${started}"
printf '%s\n' "${now}"
