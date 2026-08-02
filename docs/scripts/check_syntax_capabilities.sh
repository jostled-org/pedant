#!/usr/bin/env bash
#
# Prove the two new first-party source trees stay read-only, and that only the
# snippet tool touches the filesystem at all.
#
# `pedant-syntax` extraction is pure: it takes source text and returns a span.
# `pedant-snippet` is the one crate that opens a path. Pedant's own capability
# detection is the check, so a new write, spawn, or network call in either tree
# fails here rather than arriving as a documented exception.
#
# The path predicate is segment-anchored, so a repository-relative finding and
# an absolute one both resolve to the same crate. The profile is captured into a
# shell variable before `jq` reads it, so a cargo failure propagates with cargo's
# own message instead of masquerading as drift; no profile file is written, and
# pedant is built from this workspace rather than taken from `PATH` or
# `PEDANT_BIN`.
#
# Pedant reports findings and nothing else, so a tree it never opened and a tree
# with nothing to report print the same empty list. The profile's `any` conjunct
# catches a snippet tree that went entirely unread, but not a file of it that
# did: `all` says nothing about a finding that was never produced, so a write in
# a file the scan skipped reads as clean. Both trees carry the `all`, so both
# need the reach proved first, independently of the profile:
#   * each tree must hold Rust source at all, counted here in bash;
#   * every `.rs` file of both trees, mirrored under one temporary root, must
#     come back as a finding. The mirror is per file, not per directory: three
#     directories hold all 22 sources, so one sentinel per directory proves
#     descent and says nothing about which files the scan then selects. A
#     discovery rule that skips a file by name, extension case, or size loses
#     real source, and only a per-file count says so.
#   * each sentinel names all four capabilities the profile rules on, and each
#     one is counted on its own. The profile admits `file_read` and forbids
#     write, spawn, and network, and that forbid half is an `all` over what is
#     in practice a one-element list. A sentinel that only reads a file proves
#     only that the `file_read` detector is live; with a regressed write,
#     spawn, or network detector, a real `std::fs::write` in the syntax tree
#     would report nothing and this check would print "clean". This repository
#     is pedant, so those detectors are the source under change.
#
# The network sentinel connects to a hostname rather than an address literal.
# The literal-endpoint heuristic fires a second `network` finding on an
# IPv4-with-port string, and the counts below are per distinct file for exactly
# that reason: a detector that fires twice on one line still counts once.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=check_lib.sh
. "${script_dir}/check_lib.sh"

# Every path below is repository-relative, and the mirror reproduces those
# relative paths under one temporary root. `cd_repo_root` is what makes the `-d`
# guards below mean "the trees are gone" instead of "you stood in the wrong
# directory". All four checks call it; it lives in `check_lib.sh` because all
# four read a workspace and none of them may read the caller's.
cd_repo_root

require_tools cargo jq find mktemp dirname wc tr

# The trees this check constrains. `.github/workflows/ci.yml` scans the same
# two among all seven; here they are the whole subject.
readonly SYNTAX_TREE="pedant-syntax/src"
readonly SNIPPET_TREE="pedant-snippet/src"

# The build-from-this-workspace decision the header states, in one spelling.
# The reach guard and the profile both run pedant, and two call sites for one
# decision are two places for it to drift.
pedant_capabilities() {
    cargo run --quiet -p pedant -- capabilities "$@"
}

for tree in "${SYNTAX_TREE}" "${SNIPPET_TREE}"; do
    if [ ! -d "${tree}" ]; then
        echo "error: ${tree} is missing from the repository." >&2
        exit 1
    fi
    sources="$(find "${tree}" -type f -name '*.rs' | wc -l | tr -d '[:space:]')"
    if [ "${sources}" -eq 0 ]; then
        echo "error: ${tree} holds no Rust source." >&2
        echo "An empty tree has no capability to report, so the profile below would" >&2
        echo "pass without constraining anything." >&2
        exit 1
    fi
done

mirror="$(mktemp -d)"
trap 'rm -rf "${mirror}"' EXIT

# The listing is captured before the loop reads it. Feeding the loop from a
# process substitution puts `find` in a subshell whose exit status neither
# `set -e` nor `pipefail` observes, so a `find` that died after emitting one
# path would leave one sentinel and a count of one, and the equality below would
# compare that against itself and pass. A plain assignment propagates the
# failure with find's own message.
tree_sources="$(find "${SYNTAX_TREE}" "${SNIPPET_TREE}" -type f -name '*.rs')"

# Each sentinel takes the mirrored path of one real source, so the file set the
# reach guard ranges over is the file set the profile ranges over.
sentinels=0
while IFS= read -r source; do
    [ -n "${source}" ] || continue
    mkdir -p "$(dirname -- "${mirror}/${source}")"
    printf '%s\n' \
        'pub fn read(path: &str) -> std::io::Result<String> {' \
        '    std::fs::read_to_string(path)' \
        '}' \
        'pub fn write(path: &str) -> std::io::Result<()> {' \
        '    std::fs::write(path, "sentinel")' \
        '}' \
        'pub fn spawn() -> std::io::Result<std::process::Child> {' \
        '    std::process::Command::new("ls").spawn()' \
        '}' \
        'pub fn connect() -> std::io::Result<std::net::TcpStream> {' \
        '    std::net::TcpStream::connect("sentinel.invalid:80")' \
        '}' \
        >"${mirror}/${source}"
    sentinels=$((sentinels + 1))
done <<<"${tree_sources}"

if [ "${sentinels}" -eq 0 ]; then
    echo "error: no source was mirrored from ${SYNTAX_TREE} or ${SNIPPET_TREE}." >&2
    echo "The reach assertion below would compare zero against zero and pass," >&2
    echo "so the profile it guards would be vacuous." >&2
    exit 1
fi

reach="$(pedant_capabilities "${mirror}/${SYNTAX_TREE}" "${mirror}/${SNIPPET_TREE}")"

# The mirrored source count is bound with `--argjson`, not spliced into the
# program text. Every other predicate in these checks is a fixed string, and
# this one stays a fixed string too: a shell value reaches jq as an argument.
# `$expected` is that binding — a jq variable, which jq spells the way the shell
# does — so the single quotes are what keep the shell out of the program.
# `$findings` is bound at the top because `all` rebinds `.` to the capability
# under test, which puts the document itself out of reach inside the body.
# shellcheck disable=SC2016
reach_predicate='
.findings as $findings
| ["file_read", "file_write", "process_exec", "network"]
| all(. as $capability
      | ([$findings[]
          | select(.capability == $capability)
          | .location.file]
         | unique
         | length) == $expected)
'

assert_jq "${reach}" "${reach_predicate}" \
    --argjson expected "${sentinels}" -- \
    "error: pedant did not report every capability of every mirrored source." \
    "Expected ${sentinels} distinct files for each of file_read, file_write," \
    "process_exec, and network — one per source of ${SYNTAX_TREE} and ${SNIPPET_TREE}." \
    "The clean profile below would be vacuous, so it is not trusted."

predicate='
all(.findings[];
     .capability == "file_read"
     and (.location.file | test("(^|/)pedant-snippet/src/")))
and any(.findings[];
     .capability == "file_read"
     and (.location.file | test("(^|/)pedant-snippet/src/")))
'

profile="$(pedant_capabilities "${SYNTAX_TREE}" "${SNIPPET_TREE}")"

assert_jq "${profile}" "${predicate}" -- \
    "error: first-party syntax capability profile drifted." \
    "Expected only file_read findings, every one under ${SNIPPET_TREE}," \
    "and at least one such finding."

echo "syntax capability profile check: clean"
