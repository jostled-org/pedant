#!/usr/bin/env bash
#
# Shared helpers for the four repository boundary checks in this directory.
#
# All four prove a claim about the workspace's shape, and all four prove it
# the same way: confirm the tools resolve, capture cargo's output into a shell
# variable, then read that capture with one `jq` predicate. Stated once, a fix
# to the tool message or the failure report reaches every check instead of one.
#
# This file is sourced, never executed. It defines functions and runs nothing,
# so the caller keeps `set -euo pipefail` and its own exit contract.

# Fail unless every named tool resolves on PATH.
require_tools() {
    local tool
    for tool in "$@"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "error: ${tool} is required on PATH" >&2
            exit 1
        fi
    done
}

# Anchor the working directory at the repository root.
#
# Inside a function, `${BASH_SOURCE[0]}` names the file that defined the
# function — this one — not the caller. So the anchor is this file's own
# location, and a check launched from any directory reads the same workspace.
# Without it, `cargo metadata` and `cargo tree` resolve whatever workspace the
# caller stood in, and a closure check run from a sibling Rust repo reports
# "'pedant-syntax' is not a workspace member": a true statement about the wrong
# workspace. The `-d` guards in the capability check have the same problem, and
# read "the trees are gone" only once the working directory is known.
cd_repo_root() {
    local lib_dir
    lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    if ! cd -- "${lib_dir}/../.."; then
        echo "error: cannot enter the repository root above ${lib_dir}" >&2
        exit 1
    fi
}

# Print the workspace's own package list as `cargo metadata` JSON.
#
# `--no-deps` is load-bearing, not a speed-up: it is what makes `.packages[]`
# mean "workspace member" instead of "every crate in the dependency graph".
# Every caller reads the list with that meaning — the closure check derives its
# forbid set from it, and without the flag it forbids all of crates.io. Stated
# once here, so a caller cannot read the list under the wrong meaning.
workspace_metadata() {
    cargo metadata --format-version 1 --no-deps
}

# Fail unless a captured JSON document satisfies a jq predicate.
#
# Arguments after the predicate go to jq verbatim up to a literal `--`. Each
# argument after that `--` is one line of the failure report. The pass-through
# is what lets a caller bind a shell value with `--argjson` instead of splicing
# it into the program text: a predicate built by interpolation is one the caller
# cannot quote, and the separator keeps a jq flag from reading as a report line.
#
# The document is captured before this runs, so a cargo failure has already
# propagated with cargo's own message. What remains is jq's own failure, and a
# broken matcher must not read as a satisfied check: `jq -e` answers a false or
# null result with 1 and an empty result with 4, and every other status means
# jq never evaluated the predicate. Only the first two are violations.
#
# The document reaches jq on a here-string rather than through a pipe. Under
# `pipefail` a pipeline reports the first failing stage, so a `printf` that died
# would land in `status` and be reported below as jq's own exit — the wrong
# diagnostic from the one function whose purpose is telling "predicate false"
# apart from "matcher broken". A here-string leaves `status` jq's alone.
assert_jq() {
    local document="$1" predicate="$2" status=0 line
    shift 2
    local jq_argv=(-e)
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --)
                shift
                break
                ;;
            *)
                jq_argv+=("$1")
                shift
                ;;
        esac
    done
    jq_argv+=("${predicate}")
    jq "${jq_argv[@]}" <<<"${document}" >/dev/null || status=$?
    case "${status}" in
        0)
            return 0
            ;;
        1 | 4) ;;
        *)
            echo "error: jq exited ${status} without evaluating the predicate." >&2
            echo "The check did not run; this is a tool failure, not drift." >&2
            exit 1
            ;;
    esac
    for line in "$@"; do
        echo "${line}" >&2
    done
    exit 1
}
