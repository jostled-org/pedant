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
# The profile is the feature vocabulary the plan states:
#   default        normal features
#   none           --no-default-features
#   <list>         --no-default-features --features <list>
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
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh"

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
repository_root="$(cd -- "${script_dir}/.." && cd .. && pwd)" || repository_root=""
if [ -z "${repository_root}" ] || ! cd -- "${repository_root}"; then
    echo "error: cannot enter the repository root above ${script_dir}" >&2
    exit 75
fi

# `cargo_classify` reads its captures with ripgrep. Without rg it returns 127,
# the classifier's `if` reads false, and a full disk is reported as a code
# failure — the plan blamed for the machine.
for tool in cargo rg; do
    command -v "${tool}" > /dev/null 2>&1 || {
        echo "error: ${tool} is not on PATH — cannot select a Rust test" >&2
        exit 75
    }
done

# ---------- feature profile ----------
#
# Bash 3.2 is what macOS ships, and there an empty array expands to an unbound
# variable under `set -u`. The `+` form below expands to nothing at all when the
# profile adds no flag, so the default profile passes normal features rather
# than aborting the run.
feature_flags=()
case "${profile}" in
    default) ;;
    none) feature_flags=(--no-default-features) ;;
    *) feature_flags=(--no-default-features --features "${profile}") ;;
esac

# ---------- one classified cargo invocation ----------

# The combined output of the last `capture_cargo` run.
CARGO_CAPTURED_OUTPUT=""

# Run one cargo command, replay it, leave a receipt, and fold its classified
# status into the aggregate.
#
# The output is left in a variable rather than printed to a caller's command
# substitution, because `cargo_record` leaves the whole process with 75 for an
# unavailable machine and a subshell would swallow that exit. Both call sites
# below read the same capture, so the replay, the receipt, and the
# classification are stated once.
#
# The capture is removed on exit as well as in line. A signal during the build
# below leaves this function without reaching its own `rm`, and a transcript
# nobody owns outlives the run that made it; the trap is what closes that. It is
# cleared again before the function returns, so the next run's trap is the only
# one armed and a status leaving here is never the trap's.
capture_cargo() {
    local label="$1"
    shift
    local capture
    capture="$(mktemp "${TMPDIR:-/tmp}/run_exact_rust_test.XXXXXX")" || exit 75
    # The path is expanded as the trap is set, not as it fires: `capture` is a
    # local, and a trap that read it after this function returned would reach an
    # unset name under `set -u` and remove nothing while reporting an error.
    # shellcheck disable=SC2064
    trap "rm -f -- \"${capture}\"" EXIT

    local code=0
    "$@" > "${capture}" 2>&1 || code=$?
    cat -- "${capture}"

    cargo_receipt "${label}" "${capture}"

    local classified
    classified="$(cargo_classify "${code}" "${capture}")"
    CARGO_CAPTURED_OUTPUT="$(cat -- "${capture}")"
    rm -f -- "${capture}"
    trap - EXIT
    if [ "${classified}" != "${code}" ]; then
        printf '[cargo_infrastructure] %s: INFRASTRUCTURE (exit %s reclassified as %s)\n' \
            "${label}" "${code}" "${classified}"
    fi
    cargo_record "${classified}"
}

# ---------- list, then resolve one identity ----------
# `--locked` on both invocations: a step receipt is only worth what the
# lockfile it resolved against says, and a helper that quietly rewrote
# `Cargo.lock` mid-plan would still report the step verified.
capture_cargo "list_${package}_${target}" \
    cargo test --locked -p "${package}" --test "${target}" \
    ${feature_flags[@]+"${feature_flags[@]}"} -- --list --format terse

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
done <<< "${CARGO_CAPTURED_OUTPUT}"

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

capture_cargo "exact_${package}_${target}_${predicate}" \
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
case "${CARGO_CAPTURED_OUTPUT}" in
    *"test result: ok. 1 passed"*) ;;
    *)
        echo "error: ${identity} reported success but no test executed" >&2
        exit 1
        ;;
esac

printf '[run_exact_rust_test] %s: PASS\n' "${identity}"
