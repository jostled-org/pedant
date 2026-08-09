#!/usr/bin/env bash
# verify_step.sh — per-step verification for pedant (Rust workspace).
#
# Invoked by plan_loop.sh's `run_plan_loop_phase step` with these env vars:
#   PLAN_PATH                 — path to the plan file
#   PLAN_STEP                 — 1-indexed step number
#   PLAN_BASE_SHA             — commit SHA at plan start
#   PLAN_HEAD_SHA             — current commit SHA
#   CHANGED_FILES_PATH        — file listing paths changed since PLAN_BASE_SHA
#   PROOF_OUTPUT_DIR          — per-invocation directory for phase artifacts
#   PLAN_TEST_SCOPE           — verbatim `test_scope:` frontmatter entries joined
#                               with single spaces (empty when absent). Every
#                               entry names a Rust crate in the workspace; an
#                               unknown crate is a plan authoring bug (exit 64).
#   PLAN_ATTESTATION_BASELINE — pedant baseline attestation path
#   PLAN_ATTESTATION_CURRENT  — path the phase may write its current attestation to
#
# Routing precedence:
#   1. `PLAN_TEST_SCOPE` non-empty → fmt + clippy + test scoped to those crates.
#   2. `PLAN_TEST_SCOPE` empty but `CHANGED_FILES_PATH` shows Rust-relevant
#      changes → full workspace run.
#   3. Both empty (first step, or no diff yet) → full workspace run, so the plan
#      cannot slip a regression through by opening with a rename.
#   4. Scope empty and only non-Rust files changed (docs, plans) → nothing to
#      verify; exit 0.
#
# Commands mirror the [ci] identities in .manifest.toml, which in turn mirror
# .github/workflows/ci.yml. The root Cargo.toml is a virtual manifest, so bare
# `cargo clippy`/`cargo test` already cover every workspace member; neither
# `--workspace` nor `--all-targets` is added here. A step gate stricter than
# the freeze spends fix iterations on warnings CI would never enforce.
#
# Features: default only. The `semantic` feature pulls the ra_ap_* tree, a
# ~10-minute build, so it runs solely in the [ci] matrix at the acceptance
# freeze. The accepted consequence: a step can pass here and the freeze's
# clippy_semantic / doc_semantic / test_configuration_2 identities can still
# reject it. Semantic-only breakage therefore surfaces at closeout, not at the
# step that introduced it.
#
# The lease is the manifest command's, not this script's: the outer wrapper
# serializes heavy builds and guards the volume reserve, and plan_loop hands
# each run an isolated per-RUN_ID CARGO_TARGET_DIR that cargo honors straight
# from the environment. Adding an inner lease here would deadlock against it.
#
# Cargo-output classification, the 75 status, and the aggregate-exit priority
# belong to cargo_infrastructure.sh, which the affected-workspace runner and the
# final-proof runner source too.
#
# Exit code: 0 = pass, 64 = plan/config error, 75 = infrastructure unavailable,
# other non-zero = verification failure.

set -uo pipefail

# `set -e` is deliberately off, so a failed `cd` here would leave `script_dir`
# empty, turn the `.` line into a silent no-op, and reduce `cargo_run` and its
# siblings to "command not found" — a step that verified nothing.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ]; then
    echo "ERROR: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh"

# `cd ""` succeeds and stays put, so an empty ROOT cannot be caught by the `cd`
# alone: the step would verify whatever workspace the caller stood in and report
# that as this plan's result. Prove the path before entering it.
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

# Rust-relevant path prefixes for the scope-empty fallback: every workspace
# member, the manifests that change resolution for all of them, and the config
# file whose precedence rules are themselves under test.
RUST_PATHS=(
    pedant/
    pedant-core/
    pedant-lang/
    pedant-mcp/
    pedant-snippet/
    pedant-syntax/
    pedant-types/
    Cargo.toml
    Cargo.lock
    .pedant.toml
)

# ---------- parse and validate PLAN_TEST_SCOPE ----------
scope_rust=()
if [ -n "${PLAN_TEST_SCOPE:-}" ]; then
    # Verbatim test_scope: entries joined by single spaces
    # (plan_loop_test_scope_raw in plan_loop_verification.sh). Word-split on
    # IFS whitespace.
    for entry in ${PLAN_TEST_SCOPE}; do
        scope_rust+=("$entry")
    done
fi
if [ ${#scope_rust[@]} -gt 0 ]; then
    missing=()
    for pkg in "${scope_rust[@]}"; do
        cargo pkgid -p "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: PLAN_TEST_SCOPE names unknown Rust crate(s): ${missing[*]}" >&2
        echo "       Fix the test_scope frontmatter in ${PLAN_PATH:-the plan file}." >&2
        exit 64
    fi
fi

# ---------- changed-files signal (scope-empty fallback) ----------
changed_rust=false
if [ -n "${CHANGED_FILES_PATH:-}" ] && [ -f "${CHANGED_FILES_PATH}" ]; then
    # `|| [ -n "$path" ]` keeps a final line that carries no trailing newline.
    # This loop is the only writer of `changed_rust`, so dropping that line
    # would route a one-entry unterminated list to "nothing to verify" and the
    # step would pass having compiled nothing.
    while IFS= read -r path || [ -n "$path" ]; do
        for prefix in "${RUST_PATHS[@]}"; do
            case "$path" in
                "$prefix"*) changed_rust=true ;;
            esac
        done
    done < "${CHANGED_FILES_PATH}"
fi

# ---------- routing ----------
if [ ${#scope_rust[@]} -eq 0 ]; then
    if [ "${PLAN_STEP:-1}" = "1" ] || [ ! -f "${CHANGED_FILES_PATH:-/nonexistent}" ] || [ "$changed_rust" = true ]; then
        echo "[verify_step] workspace: cargo fmt/clippy/test (no scope)"
        cargo_run fmt cargo fmt --check
        cargo_run clippy cargo clippy -- -D warnings
        cargo_run test cargo test
    else
        echo "[verify_step] no Rust-relevant changes and no scope — nothing to verify"
    fi
    exit "$(cargo_worst)"
fi

# ---------- scoped run ----------
echo "[verify_step] scoped: ${scope_rust[*]}"
# fmt --check does not build, so the workspace check is cheap and matches what
# the freeze runs; cargo fmt has no useful per-package scoping here.
cargo_run fmt cargo fmt --check
for pkg in "${scope_rust[@]}"; do
    cargo_run "clippy_${pkg}" cargo clippy -p "$pkg" -- -D warnings
    cargo_run "test_${pkg}" cargo test -p "$pkg"
done

exit "$(cargo_worst)"
