#!/usr/bin/env bash
#
# Prove the code-intelligence product tree reads source files and does nothing
# else.
#
# `pedant-snippet` is the one first-party tree in this closure that opens a
# path. Its substrates already have their own profiles — `pedant-syntax` and
# `pedant-graph` take text and facts and open nothing, and `pedant-core`'s Go
# resolution tree is covered by the Go capability check — so this one owns the
# product tree those substrates are assembled in.
#
# The admitted closure beneath it is a watcher, an ignore-aware walker, and a
# digest. Together they may read source bytes, observe a directory, and hash
# what they read. The profile below is what holds the code that calls them to
# the same terms: reads, hashing, the exit status the command line contracts,
# and the elapsed span the watcher bounds its settle window with — and no write,
# no spawn, no network, and no language toolchain invocation. Those last two are
# named because the Rust detector resolves both by module prefix: it reports
# `std::process::ExitCode` as `process_exec` and `std::time::Instant` as
# `system_time`. The predicate admits those exact spellings and no others, so a
# spawn or a wall-clock reading in this tree still fails.
#
# Pedant reports findings and nothing else, so a tree it never opened and a tree
# with nothing to report print the same empty list. The forbid half is an `all`
# over what is normally a short list, and a regressed detector would satisfy it
# by reporting nothing at all. Every source of the tree is therefore mirrored
# under one temporary root as a sentinel that names all four capabilities, and
# the scan must come back with every one of them for every mirrored file before
# the real profile is read.
#
# `repository_check_lib.sh` owns the tree listing, the mirror, the sentinel
# bodies, the reach proof, the pedant command, and the read-only profile
# predicate, because the syntax, graph, and Go capability checks make the same
# argument about their own trees. This check states its tree and nothing else.
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
# relative paths under one temporary root. `cd_repo_root` is what makes the
# guards inside the listing mean "the tree is gone" instead of "you stood in the
# wrong directory".
cd_repo_root

# `rg` is named beside the tools this file spells out itself, because every
# cargo command here reaches it: `cargo_capture` classifies its capture with
# `rg_status_over`, and an absent `rg` returns 127, which the classifier folds to
# an unavailable machine. A genuine compile failure or a real capability drift
# would then be reported as a machine to retry on, and the caller would retry
# forever without ever being told which tool is missing.
require_tools cargo jq rg find mktemp dirname

# The product tree, and the only first-party tree in this closure that opens a
# path.
readonly PRODUCT_TREE="pedant-snippet/src"

# The sentinel takes the mirrored path of every real source, so the file set the
# reach guard ranges over is the file set the profile ranges over.
assert_capability_detectors_live "the code-intelligence surface" "${PRODUCT_TREE}"

profile="$(pedant_capabilities "${PRODUCT_TREE}")"

assert_only_read_digest_exit_status_and_elapsed_under \
    "${profile}" "${PRODUCT_TREE}" "code-intelligence" \
    "The admitted closure is a reader, a directory watcher, and a digest, so" \
    "this tree may open a source path, hash what it read, state the exit status" \
    "its command line contracts, and measure how long it waited for the host to" \
    "stop changing the root, and may do nothing else with any of them."

echo "code intelligence capability profile check: clean"
