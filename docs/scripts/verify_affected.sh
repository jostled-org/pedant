#!/usr/bin/env bash
# verify_affected.sh — the affected-workspace verification job for pedant.
#
# Invoked by plan_loop.sh's `affected` phase, under the outer build lease the
# manifest command supplies. One job: run the workspace test suite the way the
# acceptance freeze's first `test_configurations` entry runs it.
#
# The root Cargo.toml is a virtual manifest, so bare `cargo test` already covers
# every workspace member; neither `--workspace` nor `--all-targets` is added
# here. Features stay at their defaults: `semantic` pulls the ra_ap_* tree, a
# roughly ten-minute build, and belongs to the freeze matrix.
#
# The plan loop hands this phase an isolated per-run CARGO_TARGET_DIR, which
# cargo honors straight from the environment, so nothing here sets it.
#
# Exit code: 0 = pass, 75 = infrastructure unavailable, other non-zero =
# verification failure. The classification is not this script's to make; see
# cargo_infrastructure.sh.

set -uo pipefail

# `set -e` is deliberately off, so a failed `cd` here would leave `script_dir`
# empty, turn the `.` line into a silent no-op, and reduce `cargo_run` and its
# siblings to "command not found" — a run that verified nothing.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ]; then
    echo "ERROR: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh"

# `cd ""` succeeds and stays put, so an empty ROOT cannot be caught by the `cd`
# alone: the suite would run against whatever workspace the caller stood in and
# report that as this plan's result. Prove the path before entering it.
ROOT="$(cd -- "${script_dir}/../.." && pwd)" || ROOT=""
if [ -z "${ROOT}" ] || ! cd -- "${ROOT}"; then
    echo "ERROR: cannot enter the repository root above ${script_dir}" >&2
    exit 75
fi

# `cargo_classify` reads its captures with ripgrep. Without rg it returns 127,
# the classifier's `if` reads false, and a full disk is reported as a code
# failure — the plan blamed for the machine.
for tool in cargo rg; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "ERROR: ${tool} is not on PATH — cannot verify a Rust workspace" >&2
        exit 75
    }
done

echo "[verify_affected] workspace: cargo test"
cargo_run test cargo test

exit "$(cargo_worst)"
