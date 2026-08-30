#!/usr/bin/env bash
#
# Prove the syntax substrate touches nothing at all.
#
# `pedant-syntax` extraction is pure: it takes source text and returns a span.
# So the claim here is the strongest one a tree can make — the profile reports
# no finding whatever. Pedant's own capability detection is the check, so a new
# read, write, spawn, or network call in that tree fails here rather than
# arriving as a documented exception.
#
# `pedant-snippet` states no row here. It is the code-intelligence product, and
# `check_code_intelligence_capabilities.sh` owns its tree across the closure it
# actually ships — reads, hashing, the exit status its command line contracts,
# and the elapsed span its watcher bounds. A row here was a second authority for
# that claim and a strictly weaker one: the same anchor, the same predicate, and
# two more `cargo run -p pedant capabilities` invocations and a second full
# sentinel mirror of the same tree in the same job.
#
# Pedant reports findings and nothing else, so a tree it never opened and a tree
# with nothing to report print the same empty list. That is the whole hazard for
# a claim of "nothing", and there is no `any` conjunct that could answer it, so
# the reach is proved first and independently of the profile:
#   * the tree must hold Rust source at all, counted here in bash;
#   * every `.rs` file of it, mirrored under one temporary root, must come back
#     as a finding. A handful of directories hold all of them, so the mirror is
#     per file rather than per directory.
#   * each sentinel names all four capabilities the profile rules on, and each
#     one is counted on its own. A sentinel that only reads a file would prove
#     only that the `file_read` detector is live, and this tree's claim forbids
#     all four.
#
# The profile is captured into a shell variable before `jq` reads it, so a cargo
# failure propagates with cargo's own message instead of masquerading as drift;
# no profile file is written, and pedant is built from this workspace rather
# than taken from `PATH` or `PEDANT_BIN`.
#
# `repository_check_lib.sh` owns the tree listing and its count, the mirror, the
# sentinel bodies, the reach proof, the pedant command, and the profile
# predicate, because the code-intelligence, graph, and Go capability checks make
# the same argument about their own trees. This check states its tree and
# nothing else.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`,
# and a match there both enters the wrong directory and prints it — leaving
# `script_dir` a two-line value naming a tree this repository does not own.
#
# Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds and
# stays put, so `script_dir` comes back non-empty and names whatever directory
# the caller stood in. The library this script is about to source is what says
# the resolution landed beside the script, and an unreadable library is an
# unavailable machine rather than the drift this check is named for.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ] || [ ! -r "${script_dir}/repository_check_lib.sh" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh" || exit 75

# Every path below is repository-relative, and the mirror reproduces those
# relative paths under one temporary root. `cd_repo_root` is what makes the `-d`
# guards below mean "the trees are gone" instead of "you stood in the wrong
# directory". Repository checks share it because each reads a workspace and
# none may read the caller's.
cd_repo_root

# `rg` is named beside the tools this file spells out itself, because every
# cargo command here reaches it: `cargo_capture` classifies its capture with
# `rg_status_over`, and an absent `rg` returns 127, which the classifier folds to
# an unavailable machine. A genuine build failure or a real capability drift
# would then be reported as a machine to retry on, and the caller would retry
# forever without ever being told which tool is missing.
require_tools cargo jq rg find mktemp dirname

# The one tree this check constrains. The code-intelligence capability check
# owns `pedant-snippet/src`; including it here would combine its admitted reads,
# digest, exit status, and elapsed time with this substrate's empty profile.
readonly SYNTAX_TREE="pedant-syntax/src"

# Each sentinel takes the mirrored path of one real source, so the file set the
# reach guard ranges over is the file set the profile ranges over.
assert_capability_detectors_live "the first-party syntax surface" "${SYNTAX_TREE}"

profile="$(pedant_capabilities "${SYNTAX_TREE}")"

assert_no_capability_under "${profile}" "first-party syntax" \
    "Extraction takes source text and returns a span, so the syntax tree opens" \
    "no path, writes nothing, spawns nothing, and reaches no network."

echo "syntax capability profile check: clean"
