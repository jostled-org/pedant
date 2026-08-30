#!/usr/bin/env bash
#
# Lint every shell script this repository tracks, under one pinned analyser.
#
# The subject list is derived from the two directories that hold them rather
# than written out. A hand-named list matches its directory on the day it is
# typed and answers for it ever after: the thirty-sixth script lands unlinted,
# and nothing goes red to say so. A glob cannot drift from the directory it
# expands.
#
# The version is pinned because a lint gate whose analyser changes under it is
# two gates. A newer shellcheck reports findings this tree has never seen and a
# older one stops reporting findings it was written against, and either way the
# clean run means something different from the last one.
#
# `--list` prints the derived subject list, one repository-relative path a line,
# and lints nothing. A caller that has to prove a given script is linted reads
# the same derivation this run lints, rather than searching this file for the
# path: a derived list holds no path to find, and a search for one would report
# every script as unlinted.
#
# Exit 0 clean, 1 on a finding or a wrong analyser version, 75 when the analyser
# is not installed at all or cannot state which version it is. `--list` needs no
# analyser and never leaves 1.

set -euo pipefail

# Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds and
# stays put, so `script_dir` comes back non-empty and names whatever directory
# the caller stood in — and the globs below would then expand against a tree
# this repository does not own, or against nothing.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ] || [ ! -r "${script_dir}/repository_check_lib.sh" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh" || exit 75

# The globs are repository-relative, so every finding names a path the reader
# can open from the root.
cd_repo_root

list_only=0
case "${1-}" in
    --list) list_only=1 ;;
    "") ;;
    *)
        echo "usage: $0 [--list]" >&2
        exit 64
        ;;
esac
readonly list_only

# Every tracked shell script, read out of the two directories that hold them.
SUBJECTS=(
    .github/scripts/*.sh
    pedant/tests/supply_chain_support/packaged_workspace_support/*.sh
)

# A glob that matched nothing expands to its own pattern, and a run over a
# pattern is a run over no script at all. Both directories hold scripts, so an
# unexpanded entry is a working directory that is not the repository root.
for subject in "${SUBJECTS[@]}"; do
    test -f "${subject}" || {
        echo "error: ${subject} is no file; the subject list expanded against the wrong tree" >&2
        exit 75
    }
done

if [ "${list_only}" -eq 1 ]; then
    printf '%s\n' "${SUBJECTS[@]}"
    exit 0
fi

# An absent analyser is an unavailable machine, not a tree that failed to lint.
# Without this the version substitution below dies under `set -e` and the run
# leaves with 127, which every caller reads as a finding.
#
# `awk` is named beside it because the version substitution runs `awk` too, and
# an absent one dies at exactly the same place with exactly the same 127 for
# exactly the same wrong reason.
require_tools shellcheck awk

SHELLCHECK_VERSION="0.11.0"
readonly SHELLCHECK_VERSION

# An analyser that resolves and cannot state its version is an unusable machine,
# not a wrong version and not a finding. Left to `set -e`, `pipefail` handed the
# assignment whatever shellcheck died of and this run left with that status —
# every one of which a caller reads as a tree that failed to lint, and retries
# nothing.
actual_version="$(shellcheck --version | awk '$1 == "version:" { print $2 }')" || {
    echo "error: shellcheck resolves but could not report its version." >&2
    exit 75
}
case "${actual_version}" in
    "${SHELLCHECK_VERSION}") ;;
    *)
        echo "error: shellcheck ${SHELLCHECK_VERSION} is required; found ${actual_version:-unknown}." >&2
        exit 1
        ;;
esac

exec shellcheck -x "${SUBJECTS[@]}"
