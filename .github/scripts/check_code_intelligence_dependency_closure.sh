#!/usr/bin/env bash
#
# Prove the code-intelligence feature graph is closed in every direction.
#
# `pedant-snippet` is becoming one navigation application built from the syntax
# substrate, the resolution substrate, and the graph projector. Three claims
# follow from that, and none of them implies the others:
#
#   * A build that selects no feature links no grammar, no resolver, and no
#     graph. The `lang-*` and `graph-*` rows are the whole selection surface, so
#     a `default-features = true` slip on the `pedant-syntax` edge — or a
#     grammar named on the edge instead of behind a feature — would put a parser
#     into every library consumer with nothing else turning red.
#   * A build that selects one language links that grammar and no other. A
#     consumer indexing Python must not pay for five parsers it will never
#     dispatch to.
#   * No build, at any selection, reaches the judgment surface, the semantic
#     tier, rust-analyzer, a process spawner, or a network client. This is the
#     claim the whole product boundary rests on: the linter and the navigator
#     share substrates, and only the substrates.
#
# `check_tree_closure` in `repository_check_lib.sh` owns the capture, the
# specification vocabulary, the derived forbid set, and the non-vacuity
# refusals, because the syntax, graph, Go, and resolution closure checks prove
# the same shape of claim about their own subjects. This file states the rows.
#
# Reads the workspace and writes no file. Exit 0 clean, exit 1 on violation.

set -euo pipefail

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`, and
# a match there both enters the wrong directory and prints it — leaving
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
# The one table stating which features each named profile selects. Every row
# below derives its cargo arguments from it, so this file and the configuration
# matrix cannot test different profiles under one name.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=code_intelligence_profiles.sh
. "${script_dir}/code_intelligence_profiles.sh" || exit 75

cd_repo_root
# `rg` is named beside cargo and jq because every cargo command here reaches it:
# `cargo_capture` classifies its capture with `rg_status_over`, and an absent
# `rg` returns 127, which the classifier folds to an unavailable machine. A
# genuine resolve failure or a real closure drift would then be reported as a
# machine to retry on, and the caller would retry forever without ever being
# told which tool is missing.
require_tools cargo jq rg

# The edge kinds every row reads are `CLOSURE_EDGE_KINDS`, which
# `repository_check_lib.sh` owns beside the capture format for the same readers.
# A `[build-dependencies]` on a grammar links it just as surely as a normal one,
# and three closure checks had each stated that constant and a paraphrase of its
# reasoning.

# The package every row below selects a profile of.
readonly ROOT=(-p pedant-snippet -e "${CLOSURE_EDGE_KINDS}")

# The three workspace members every profile reaches, and the two it reaches only
# behind a graph feature.
readonly SYNTAX_MEMBERS=(
    member:pedant-snippet
    member:pedant-types
    member:pedant-syntax
)
readonly GRAPH_MEMBERS=(
    "${SYNTAX_MEMBERS[@]}"
    member:pedant-core
    member:pedant-graph
)

# The edges the manifest must declare directly rather than inherit.
#
# Transitive satisfaction would let the manifest and the documented shape
# disagree, as it did while `pedant-snippet` claimed a `pedant-types` edge it
# reached only through `pedant-syntax`. The runtime three are stated on every
# row because they are unconditional: a feature that made the watcher, the
# walker, or the digest optional would change the product, not just the build.
readonly BASE_EDGES=(
    direct:pedant-types
    direct:pedant-syntax
    direct:notify
    direct:ignore
    direct:sha2
)

# The completed product's two transports and the runtime they need.
#
# Stated on every row for the same reason the runtime three are: the command
# tree and the stdio server are unconditional, so a profile that stopped
# resolving one of them would be a build that ships a library where an
# application was published. They are also what the forbids below are about — a
# read-only product grows a spawner, a socket, or a writer through one of these
# edges or not at all.
readonly PRODUCT_EDGES=(
    direct:clap
    direct:rmcp
    direct:serde
    direct:serde_json
    direct:thiserror
    direct:tokio
)

# What no profile may reach, whatever it selected.
#
# The judgment surface and the semantic tier are `pedant-core` features one
# forwarding entry away. rust-analyzer is a whole toolchain behind the second of
# them, and `line-index` is the package that arrives with it, so both spellings
# are refused. The HTTP clients are named because a navigation product that
# grew one would still pass every feature claim above it.
#
# The two ECMAScript rows are forward-declared. The `typescript-graph-extraction`
# specification extends this same index with ECMAScript project slices, and this
# plan states that no profile it ships selects that resolution. Naming the
# features now means the row that would first enable one arrives red rather than
# silently widening a closure nobody re-read.
#
# The four `tokio` rows and `tempfile` are the completed product's own risk.
# The binary selects `rt` and `time` for the stdio server's shutdown path, and
# each of the four is one list entry away: `process` is a spawner, `net` is a
# socket, `fs` is a writer, and `signal` is a second way to reach the process
# table. `tempfile` is the same claim as a package — a crate whose whole job is
# creating files, admitted into no production profile. All five are universal
# because the claim is: there is no profile of a read-only navigator in which a
# process spawner is correct.
readonly UNIVERSAL_FORBIDS=(
    no-feature:tokio/process
    no-feature:tokio/net
    no-feature:tokio/fs
    no-feature:tokio/signal
    absent:tempfile
    no-feature:pedant-core/checks
    no-feature:pedant-core/semantic
    no-feature:pedant-core/resolution-test-support
    no-feature:pedant-core/ecmascript-resolution
    no-feature:pedant-graph/typescript
    no-prefix:ra_ap_
    absent:line-index
    absent:reqwest
    absent:ureq
    absent:hyper
)

# Every label a row below entered, one per line.
#
# Recorded as each row runs, and read once at the foot of this file. A list of
# the rows this file ought to state would be a second authority beside the
# shared table; what this is instead is a reading of what happened.
CHECKED_PROFILES=""

# One row's cargo arguments, in `CODE_INTELLIGENCE_ARGS`, and its label kept.
#
# The shared profile table is the one authority for which features a named
# profile selects, and for the refusal a label it does not carry earns — a row
# naming a profile that does not exist is this file misspelling itself rather
# than a closure that drifted. Four sections across two files had written that
# refusal out.
#
# The grammar forbids are reset here rather than left to each row, so a row that
# states no grammar set of its own forbids no grammar instead of inheriting the
# previous row's.
profile_args() {
    code_intelligence_require_profile_args "$1"
    CODE_INTELLIGENCE_NO_OTHER_GRAMMAR=()
    CHECKED_PROFILES="${CHECKED_PROFILES}$1
"
}

# ---------------------------------------------------------------------------
# No feature at all: the transports, the runtime, and neither a parser nor a
# resolver.
# ---------------------------------------------------------------------------

profile_args snippet-no-features
code_intelligence_no_other_grammar absent:
check_tree_closure "code-intelligence snippet-no-features" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:pedant-snippet \
    no-feature:pedant-syntax/rust \
    no-feature:pedant-syntax/_ts \
    no-feature:pedant-syntax/_ts_generic \
    no-feature:syn/visit \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

# ---------------------------------------------------------------------------
# One language at a time: that grammar, and no other.
#
# Rust is the odd row. Its backend is `syn`, not tree-sitter, so a Rust-only
# build links no grammar at all and the whole tree-sitter set is forbidden.
#
# Every row states the grammars it links and the shared complement derives the
# rest, so "and no other" is a complement rather than a list somebody has to
# keep. The list had already gone stale: the TypeScript row named Go, Python,
# and Bash and never named JavaScript. Each row still states for itself whether
# the shared generic recognizer is compiled — Go is the one grammar whose
# declarations belong to the `go` fact inventory, so a Go-only build must not
# carry `_ts_generic`.
# ---------------------------------------------------------------------------

profile_args snippet-lang-rust
code_intelligence_no_other_grammar absent:
check_tree_closure "code-intelligence snippet-lang-rust" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:syn \
    feature:pedant-syntax/rust feature:syn/visit \
    no-feature:pedant-syntax/_ts \
    no-feature:pedant-syntax/_ts_generic \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-lang-go
code_intelligence_no_other_grammar absent: tree-sitter-go
check_tree_closure "code-intelligence snippet-lang-go" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:tree-sitter require:tree-sitter-go \
    feature:pedant-syntax/ts-go feature:pedant-syntax/_ts \
    no-feature:pedant-syntax/rust \
    no-feature:pedant-syntax/_ts_generic \
    no-feature:syn/visit \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-lang-python
code_intelligence_no_other_grammar absent: tree-sitter-python
check_tree_closure "code-intelligence snippet-lang-python" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:tree-sitter require:tree-sitter-python \
    feature:pedant-syntax/ts-python feature:pedant-syntax/_ts_generic \
    no-feature:pedant-syntax/rust \
    no-feature:syn/visit \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-lang-javascript
code_intelligence_no_other_grammar absent: tree-sitter-javascript
check_tree_closure "code-intelligence snippet-lang-javascript" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:tree-sitter require:tree-sitter-javascript \
    feature:pedant-syntax/ts-javascript feature:pedant-syntax/_ts_generic \
    no-feature:pedant-syntax/rust \
    no-feature:syn/visit \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-lang-typescript
code_intelligence_no_other_grammar absent: tree-sitter-typescript
check_tree_closure "code-intelligence snippet-lang-typescript" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:tree-sitter require:tree-sitter-typescript \
    feature:pedant-syntax/ts-typescript feature:pedant-syntax/_ts_generic \
    no-feature:pedant-syntax/rust \
    no-feature:syn/visit \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-lang-bash
code_intelligence_no_other_grammar absent: tree-sitter-bash
check_tree_closure "code-intelligence snippet-lang-bash" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${SYNTAX_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    require:tree-sitter require:tree-sitter-bash \
    feature:pedant-syntax/ts-bash feature:pedant-syntax/_ts_generic \
    no-feature:pedant-syntax/rust \
    no-feature:syn/visit \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

# ---------------------------------------------------------------------------
# Resolved languages: the substrate and the projector, and nothing above them.
#
# `graph-rust` is where the judgment surface would arrive if it ever did:
# `pedant-core` with its default features on is the linter. The row states the
# resolution packages it must reach and forbids every feature above them.
# ---------------------------------------------------------------------------

profile_args snippet-graph-rust
code_intelligence_no_other_grammar absent:
check_tree_closure "code-intelligence snippet-graph-rust" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${GRAPH_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    direct:pedant-core direct:pedant-graph \
    require:syn require:toml require:semver \
    feature:pedant-syntax/rust \
    no-feature:pedant-core/go-resolution \
    no-feature:pedant-graph/go \
    no-feature:pedant-syntax/_ts \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-graph-go
code_intelligence_no_other_grammar absent: tree-sitter-go
check_tree_closure "code-intelligence snippet-graph-go" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${GRAPH_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    direct:pedant-core direct:pedant-graph \
    require:tree-sitter-go \
    feature:pedant-graph/go \
    feature:pedant-core/go-resolution \
    feature:pedant-syntax/ts-go \
    no-feature:pedant-syntax/rust \
    no-feature:pedant-syntax/_ts_generic \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

# ---------------------------------------------------------------------------
# Combined: two graph producers and one syntax-only language, resolved
# together.
#
# Cargo unifies features across a build, so the rows above passing separately
# says nothing about the graph a consumer of all three gets. This is the shape
# a mixed repository selects when it does not want the whole default.
# ---------------------------------------------------------------------------

profile_args snippet-combined
code_intelligence_no_other_grammar absent: tree-sitter-go tree-sitter-typescript
check_tree_closure "code-intelligence snippet-combined" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${GRAPH_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    direct:pedant-core direct:pedant-graph \
    require:syn require:tree-sitter-go require:tree-sitter-typescript \
    feature:pedant-syntax/rust \
    feature:pedant-syntax/ts-go \
    feature:pedant-syntax/ts-typescript \
    feature:pedant-graph/go \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

# ---------------------------------------------------------------------------
# The installed application, and everything the crate publishes at once.
#
# `--all-features` must reach no further than the default. The two rows are
# stated separately because that is the claim: a feature added without a place
# in `default` would show up here and nowhere else.
# ---------------------------------------------------------------------------

readonly INSTALLED=(
    require:syn
    require:tree-sitter
    require:tree-sitter-go
    require:tree-sitter-python
    require:tree-sitter-javascript
    require:tree-sitter-typescript
    require:tree-sitter-bash
    feature:pedant-syntax/rust
    feature:pedant-syntax/ts-go
    feature:pedant-syntax/ts-python
    feature:pedant-syntax/ts-javascript
    feature:pedant-syntax/ts-typescript
    feature:pedant-syntax/ts-bash
    feature:pedant-syntax/_ts_generic
    feature:pedant-core/go-resolution
    feature:pedant-graph/go
)

profile_args snippet-default
code_intelligence_no_other_grammar absent: "${CODE_INTELLIGENCE_GRAMMARS[@]}"
check_tree_closure "code-intelligence snippet-default" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${GRAPH_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    direct:pedant-core direct:pedant-graph \
    "${INSTALLED[@]}" \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

profile_args snippet-all-features
code_intelligence_no_other_grammar absent: "${CODE_INTELLIGENCE_GRAMMARS[@]}"
check_tree_closure "code-intelligence snippet-all-features" \
    "${ROOT[@]}" ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} -- \
    "${GRAPH_MEMBERS[@]}" \
    "${BASE_EDGES[@]}" \
    "${PRODUCT_EDGES[@]}" \
    direct:pedant-core direct:pedant-graph \
    "${INSTALLED[@]}" \
    ${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]+"${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[@]}"} \
    "${UNIVERSAL_FORBIDS[@]}"

# Every profile the shared table states was given a row above.
#
# The rows are written out one per label, which is what the row table models and
# mutates, so nothing here could see a thirteenth profile added to the table:
# it would be closed by no row and reported by nothing. This is the reading that
# closes it, and the compile, identity, and liveness matrices make the same one.
code_intelligence_assert_every_profile_ran \
    "${CHECKED_PROFILES}" "the code-intelligence closure"

assert_no_violations "the code-intelligence feature closure drifted."

echo "code intelligence dependency closure check: clean"
