#!/usr/bin/env bash
#
# run_exact_rust_test.sh — run exactly one registered integration test.
#
# Usage: run_exact_rust_test.sh <package> <integration-target> <profile> <predicate>
#
# A plan step's receipt is only worth what its filter selected. `cargo test …
# <bare name>` is a substring filter over every registered identity, so it
# silently runs two tests when a name is reused, runs none when a predicate was
# renamed, and reports both as a pass. This helper closes that hole: it lists the
# target under the requested feature profile, resolves the bare predicate to
# exactly one full libtest identity, refuses zero and duplicate selection, and
# then runs that one identity with `--exact`.
#
# The profile is the feature vocabulary the plan states, and
# `cargo_infrastructure.sh` owns it: `default` is normal features, `none` is
# `--no-default-features`, `all` is `--all-features`, and anything else is a
# comma-separated feature list. This helper, the step router, and the routing
# table all read a profile through the one translator, because a profile spelled
# in three places is three chances for a receipt to name a build nobody ran.
#
# Cargo-output classification, the 75 status, and the aggregate-exit priority
# belong to cargo_infrastructure.sh, so an unavailable machine leaves with 75
# from here too and the caller reruns rather than blaming the change.
#
# The build lease is the caller's: this helper runs beneath one outer lease and
# the absolute CARGO_TARGET_DIR it inherits, and takes neither of its own.
#
# Exit code: 0 = the one selected test passed, 1 = selection or non-vacuity
# refusal, 64 = usage error, 75 = infrastructure unavailable, other non-zero =
# the selected test's own failure.

set -uo pipefail

# `set -e` is deliberately off, so a failed `cd` here would leave `script_dir`
# empty, turn the `.` line into a silent no-op, and reduce the classifier API to
# "command not found" — a step that verified nothing.
#
# `CDPATH` is cleared inside the substitution. A caller that invokes this helper
# by a relative path leaves `dirname` a bare relative directory, `cd` then
# consults `CDPATH`, and a match there both enters the wrong directory and
# prints it — leaving `script_dir` a two-line value naming another tree, which
# is where the classifier would be sourced from.
#
# Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds and
# stays put, so `script_dir` comes back non-empty and names whatever directory
# the caller stood in. The classifier's presence beside this script is what says
# the resolution landed here, and the source is guarded for the same reason —
# unread, `require_tools`, `cargo_record`, and `cargo_worst` are all 127 no-ops
# and this helper prints PASS with no infrastructure classification at all.
# Every sibling in this directory carries both halves; this one carried neither.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ] || [ ! -r "${script_dir}/cargo_infrastructure.sh" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh" || exit 75

if [ "$#" -ne 4 ]; then
    echo "usage: ${BASH_SOURCE[0]} <package> <integration-target> <profile> <predicate>" >&2
    exit 64
fi

package="$1"
target="$2"
profile="$3"
predicate="$4"

# `cd ""` succeeds and stays put, so an empty root cannot be caught by the `cd`
# alone: the helper would select a test out of whatever workspace the caller
# stood in and report that as this plan's receipt.
#
# One hop and a cleared `CDPATH`, which is the spelling every other runner and
# library in this directory resolves its root by. Neither buys anything here on
# its own — `script_dir` is absolute and a first component of `..` is the one
# case `cd` never searches `CDPATH` for — so this is the weaker claim the
# neighbouring prologues make for themselves: a resolution written two ways is a
# resolution somebody has to read twice, and this file's copy was the one that
# drifted.
repository_root="$(CDPATH='' cd -- "${script_dir}/../.." && pwd)" || repository_root=""
if [ -z "${repository_root}" ] || ! cd -- "${repository_root}"; then
    echo "error: cannot enter the repository root above ${script_dir}" >&2
    exit 75
fi

# `cargo_classify` reads its captures with ripgrep. Without rg it returns 127,
# the classifier's `if` reads false, and a full disk is reported as a code
# failure — the plan blamed for the machine. The probe is the classifier's own,
# so every runner on this machine leaves with one status and one wording.
require_tools cargo rg

# ---------- feature profile ----------
#
# The flags are the classifier's, derived from the profile by the one translator
# every cargo caller in this directory reads. Bash 3.2 is what macOS ships, and
# there an empty array expands to an unbound variable under `set -u`, so the `+`
# form below expands to nothing at all when the default profile adds no flag
# rather than aborting the run.
cargo_feature_flags "${profile}"
feature_flags=(${CARGO_FEATURE_FLAGS[@]+"${CARGO_FEATURE_FLAGS[@]}"})

# ---------- list, then resolve one identity ----------
#
# `cargo_run` is the one runner: it opens the capture, replays it, leaves the
# receipt, removes the capture however the run ends, and publishes what it read
# in `CARGO_RUN_OUTPUT`. This file used to carry a near-verbatim copy of it that
# added an assignment and a trap, and read its capture file three times to do it.
#
# `--locked` on both invocations: a step receipt is only worth what the
# lockfile it resolved against says, and a helper that quietly rewrote
# `Cargo.lock` mid-plan would still report the step verified.
cargo_run "list_${package}_${target}" \
    cargo test --locked -p "${package}" --test "${target}" \
    ${feature_flags[@]+"${feature_flags[@]}"} -- --list --format terse
listing="${CARGO_RUN_OUTPUT}"

if [ "$(cargo_worst)" -ne 0 ]; then
    echo "error: listing ${package} --test ${target} did not complete" >&2
    exit "$(cargo_worst)"
fi

# Every listed identity whose last `::` segment is the requested predicate.
#
# The suffix is bound at a `::` boundary rather than by substring, so a longer
# predicate ending in the requested one answers for neither.
selected=()
while IFS= read -r line; do
    case "${line}" in
        *": test") ;;
        *) continue ;;
    esac
    identity="${line%: test}"
    case "${identity}" in
        "${predicate}" | *"::${predicate}") selected+=("${identity}") ;;
    esac
done <<< "${listing}"

case "${#selected[@]}" in
    1) ;;
    0)
        echo "error: ${package} --test ${target} (${profile}) registers no test named ${predicate}" >&2
        exit 1
        ;;
    *)
        echo "error: ${package} --test ${target} (${profile}) registers ${#selected[@]} tests named ${predicate}:" >&2
        printf '  %s\n' "${selected[@]}" >&2
        echo "A step receipt must select one identity; rename the duplicates." >&2
        exit 1
        ;;
esac

identity="${selected[0]}"

# ---------- run that one identity ----------
printf '[run_exact_rust_test] %s --test %s (%s): %s\n' \
    "${package}" "${target}" "${profile}" "${identity}"

cargo_run "exact_${package}_${target}_${predicate}" \
    cargo test --locked -p "${package}" --test "${target}" \
    ${feature_flags[@]+"${feature_flags[@]}"} -- --exact "${identity}"

status="$(cargo_worst)"
if [ "${status}" -ne 0 ]; then
    exit "${status}"
fi

# A green status over a filter that matched nothing is the failure this helper
# exists to prevent, so the receipt is refused unless libtest reports the one
# selected test as executed.
#
# The needle carries libtest's whole summary prefix. A bare `1 passed` is a
# suffix of `11 passed` and of `21 passed`, so a run that executed eleven tests
# would satisfy a claim about the one this helper selected.
case "${CARGO_RUN_OUTPUT}" in
    *"test result: ok. 1 passed"*) ;;
    *)
        echo "error: ${identity} reported success but no test executed" >&2
        exit 1
        ;;
esac

printf '[run_exact_rust_test] %s: PASS\n' "${identity}"
