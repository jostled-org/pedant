#!/usr/bin/env bash
#
# Compile every feature configuration the code-intelligence product claims to
# support, and prove each one compiled the units it was named for.
#
# The closure check reads what cargo would *resolve*. This one reads what cargo
# actually *compiled*, and the two are not the same reading: a feature that
# resolves a package and never builds a unit of it, or a `cfg` that quietly
# stopped gating on its own feature, is invisible to a resolve graph. Both
# failures read as a passing matrix, and both are the reason each row below is
# checked from the compiler's own artifact stream rather than from a manifest.
#
# So each row states three things: the packages its compile must reach, the
# workspace members it admits, and the third-party packages it must not build.
# Everything else in the workspace is derived and forbidden, so a crate is
# closed to every row the day it joins. A row that compiled nothing at all fails
# before any list is read, because a build that selected no unit and a build
# that selected the wrong ones print the same clean status.
#
# The rows are the closed feature table: no feature, each of the six languages
# on its own, each resolved language, the combined selection, the installed
# default, and everything at once. The reduced profiles are default-off, so no
# other job in this repository lints or documents them — the liveness section
# below is where that gap is closed, over the whole target set rather than the
# library alone.
#
# Every cargo command runs through `cargo_capture`, so a registry outage or a
# full disk leaves with 75 and the caller retries rather than reading the
# machine as drift.
#
# The identity section below answers the other question a feature matrix owes:
# whether the profile a build compiled is part of what its index claims. Each
# closed row indexes an empty repository through the one exact public predicate
# and hands back its enabled-language and graph-coverage vectors beside the
# revision they produced. Profiles that state the same vector must agree, and
# profiles that state different ones must not — a build that dropped either
# vector from its claim collapses rows that have to differ.
#
# The liveness section answers the third question, which the other two leave
# open. A profile that compiles and states an identity has still not been shown
# to *run* anything, and a conditional public item has still not been shown to
# be conditional: `cargo check` accepts a `cfg` that gates on the wrong feature,
# and an identity receipt is one predicate's output. Each closed row therefore
# lints its whole target set, documents its public API with missing-doc denial,
# runs the crate's one integration root and requires a non-zero passing count,
# and reads the generated documentation for the exact items its features select
# and the exact items they do not.
#
# The rustdoc section answers the fourth, which is not about this crate alone.
# The navigation contract is published from five crates, and a consumer reads one
# page set: each is documented under missing-doc denial in the profile that
# publishes the most surface, each compiles its own examples, the product's
# public pages and its eight questions are read back out of the generated
# documentation, and the product is required to state at least one example — a
# doctest job over a crate with no examples is a compiler that read nothing.
#
# Which features each of the twelve profiles selects is stated once, in
# `code_intelligence_profiles.sh`, and every section here reads it. Four
# authorities used to spell those selections — the compile arguments, the
# identity tokens, the liveness arguments, and the dependency closure's rows —
# and nothing checked they agreed, so a row whose compile line said `graph-go`
# while its liveness line said `graph-rust` passed every guard this file carries
# and the two sections tested different profiles under one name.
#
# Usage: check_code_intelligence_configurations.sh [all|compile|identity|liveness|rustdoc|list]
#
# `all` runs the four sections, which is what a caller that names nothing is
# asking for; each section name runs that one, so a claim about compiling is not
# paid for twice when the claim under test is about identity. `list` prints the
# shared profile table and runs nothing.
#
# Runs beneath the caller's build lease and inherited `CARGO_TARGET_DIR`, opens
# no temporary root beyond one receipt file the identity section removes on the
# way out however it leaves, and reaches no network beyond what the lockfile
# already pins. Exit 0 clean, exit 1 on
# violation, exit 64 on a usage error, 75 when the machine cannot answer.

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
# The one table stating which features each named profile selects. Every section
# below reads it, so the compile arguments, the identity token, and the liveness
# arguments of one row cannot name three different profiles.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=code_intelligence_profiles.sh
. "${script_dir}/code_intelligence_profiles.sh" || exit 75

cd_repo_root
# `rg` is named beside cargo because every cargo command here reaches it:
# `cargo_capture` classifies its capture with `rg_status_over`, and an absent
# `rg` returns 127, which the classifier folds to an unavailable machine. A
# genuine compile failure or a real profile drift would then be reported as a
# machine to retry on, and the caller would retry forever without ever being
# told which tool is missing.
#
# `sort` and `tail` are named for the same reason `sed` is: `compiled_packages`
# ends in `sort -u` and `passing_count` ends in `tail -n 1`, so an absent one
# leaves a row reading an empty package list or an empty passing count rather
# than an unreadable machine.
#
# `env` and `cat` are named under the same rule and were the two this list left
# out: every documentation row runs its build through `env`, and both the public
# page and the identity receipt are read with `cat`.
require_tools cargo jq rg mktemp sed sort tail env cat

# Which section to run, and how many arguments name one.
#
# `all` runs the four; each section name runs that one, so a claim about
# compiling is not paid for twice when the claim under test is about identity;
# `list` prints the shared profile table and runs nothing. A trailing argument
# is refused rather than dropped, because a caller that wrote two of them meant
# something this script cannot do and would otherwise get the first one silently.
SECTION="${1:-all}"
if [ "$#" -gt 1 ]; then
    echo "error: name at most one section; got $# arguments" >&2
    echo "usage: ${BASH_SOURCE[0]} [all|compile|identity|liveness|rustdoc|list]" >&2
    exit 64
fi
case "${SECTION}" in
    all | compile | identity | liveness | rustdoc) ;;
    list)
        code_intelligence_profiles
        exit 0
        ;;
    *)
        echo "usage: ${BASH_SOURCE[0]} [all|compile|identity|liveness|rustdoc|list]" >&2
        exit 64
        ;;
esac

# The package every row compiles a profile of.
readonly ROOT=(--locked -p pedant-snippet)

# The workspace members a profile may compile. Everything else in the workspace
# is derived and forbidden, so a crate is closed to every row the day it joins.
#
# A hand-written forbid list is the wrong shape for the same reason
# `workspace_members_excluding` gives: it goes stale the day a member joins, and
# the new member's edge then reads as clean. The two lists that used to be
# written out here — the applications and the resolution pair — are exactly what
# "not admitted" now means.
readonly SYNTAX_MEMBERS="pedant-snippet pedant-syntax pedant-types"
readonly GRAPH_MEMBERS="${SYNTAX_MEMBERS} pedant-core pedant-graph"

# Every label each section entered, one per line.
#
# Recorded as each row runs, and read at that section's own foot. The rows are
# written out one per label — which is what the row table models and mutates —
# so nothing in this file could see a thirteenth profile added to the shared
# table: it would be compiled by no row, given no identity, run by no liveness
# row, and reported by nothing. A list of the rows this file ought to state
# would be the second authority the shared table exists to remove; these are a
# reading of what happened.
COMPILE_PROFILES=""
IDENTITY_PROFILES=""
LIVENESS_PROFILES=""

# Deny a missing doc, and a link that does not resolve, on the documentation
# rows nothing else reaches.
#
# The second is a profile claim rather than a style one. An intra-doc link to a
# conditional item resolves in the build that selects it and silently does not
# in the build that does not, so a page documenting a reduced profile would ship
# describing a method that profile cannot call.
readonly DOC_FLAGS="-D missing_docs -D rustdoc::broken_intra_doc_links"

# The package names one artifact stream reports, one per line.
#
# Cargo's package ids come in two spellings: `<source>#<name>@<version>` and,
# when the name repeats the last path segment, `<source>/<name>#<version>`. Both
# are reduced here, so a row's claim is about package names rather than about
# whichever spelling cargo chose.
#
# `fromjson?` drops the lines that are not JSON at all. The capture is cargo's
# combined output, and the progress lines on stderr are part of it.
compiled_packages() {
    jq -R -r '
        fromjson?
        | select(.reason == "compiler-artifact")
        | .package_id
        | split("#") as $parts
        | ($parts[-1]) as $tail
        | if ($tail | test("@"))
          then ($tail | split("@")[0])
          else ($parts[0] | split("/")[-1])
          end
    ' <<< "$1" | sort -u
}

# Compile one profile and hold its artifact stream to its three lists.
#
# Usage: check_profile <label> <required> <admitted members> <forbidden>
#
# All three lists are space-separated names, and the cargo arguments are the
# shared table's: the label is the whole feature selection.
#
# The required list runs first: a forbid over a stream that came back short
# passes the same silent way an empty one would, so a row that requires nothing
# is refused outright.
#
# The forbid half is two sets. `forbidden` names the packages no workspace
# member list can derive — the grammars and the parser runtime. Every workspace
# member the row does not admit is derived from `cargo metadata`, so a crate
# joining the workspace is closed to every row without a line being typed.
check_profile() {
    local label="$1" required="$2" admitted_members="$3" forbidden="$4"

    if [ -z "${required}" ]; then
        echo "error: ${label} requires no package, so its forbids read an unproven stream" >&2
        exit 1
    fi

    code_intelligence_require_profile_args "${label}"
    COMPILE_PROFILES="${COMPILE_PROFILES}${label}
"

    # Loaded in this shell rather than inside the substitution below, because
    # `cargo_record` leaves the whole process with 75 for an unavailable machine
    # and a subshell would leave with it instead.
    load_workspace_metadata
    local derived
    # The admitted member list is space-separated names, and splitting it is the point.
    # shellcheck disable=SC2086
    derived="$(workspace_members_excluding ${admitted_members})"
    # A row that forbids nothing states only what it built, never what it may
    # not build, and that is the half of a profile claim nothing else in this
    # repository makes — it would still print "N packages compiled" and pass.
    # The derived set is where that refusal lives now, because it is the half
    # that is always there: the two widest rows compile every grammar and so
    # name no third-party forbid at all, while every row has a member it may not
    # compile.
    if [ "$(count_nonempty_lines "${derived}")" -eq 0 ]; then
        echo "error: ${label} admits every workspace member, so it forbids none" >&2
        exit 1
    fi

    printf '[code-intelligence-config] %s: cargo check %s\n' \
        "${label}" "${CODE_INTELLIGENCE_ARGS[*]-installed default}"
    cargo_capture "${label}" cargo check "${ROOT[@]}" \
        ${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"} \
        --message-format json || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        violation "${label} did not compile"
        return
    }

    local compiled name count
    compiled="$(compiled_packages "${CARGO_CAPTURE_OUTPUT}")"
    count="$(count_nonempty_lines "${compiled}")"
    if [ "${count}" -eq 0 ]; then
        violation "${label} compiled no unit at all; the row would pass having built nothing"
        return
    fi

    for name in ${required}; do
        contains_line "${compiled}" "${name}" \
            || violation "${label} compiled no ${name}; the profile did not take"
    done
    for name in ${forbidden}; do
        contains_line "${compiled}" "${name}" \
            && violation "${label} compiled forbidden package ${name}"
    done
    while IFS= read -r name; do
        [ -n "${name}" ] || continue
        contains_line "${compiled}" "${name}" \
            && violation "${label} compiled workspace member ${name}, which it does not admit"
    done <<< "${derived}"
    printf '[code-intelligence-config] %s: %s packages compiled\n' "${label}" "${count}"
}

# How many predicates one libtest capture reported passing, or nothing.
#
# libtest's own summary is the reading, and the last summary is the one that
# counts: a capture holding several roots ends with the total the caller asked
# for. The empty answer is left empty rather than folded to zero, because both
# callers refuse the two the same way and neither may report a run it never saw
# as a run of none.
#
# One reader, because two copies of this line are two ways to disagree about
# what "the crate ran something" means.
passing_count() {
    printf '%s' "$1" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | tail -n 1
}

# Print the package-name complement for one row's linked grammars.
grammar_complement() {
    code_intelligence_no_other_grammar "" "$@"
    printf '%s' "${CODE_INTELLIGENCE_NO_OTHER_GRAMMAR[*]}"
}

# The tag this matrix prefixes its command lines with.
#
# `check_command` is `repository_check_lib.sh`'s: it was byte-identical here and
# in the Go matrix apart from this prefix, so the prefix is what each caller
# states and the rest has one owner.
readonly COMMAND_TAG="[code-intelligence-config]"

# ---------------------------------------------------------------------------
# No feature at all: the library, the transports, and the runtime the index is
# built on — and neither a parser nor a resolver.
# ---------------------------------------------------------------------------

if [ "${SECTION}" = "all" ] || [ "${SECTION}" = "compile" ]; then

check_profile snippet-no-features \
    "pedant-snippet pedant-syntax pedant-types notify ignore sha2" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement)"

# ---------------------------------------------------------------------------
# One language at a time: that grammar compiles, and no other does.
#
# Rust is the odd row again. Its backend is `syn`, so a Rust-only build compiles
# no grammar unit at all.
# ---------------------------------------------------------------------------

check_profile snippet-lang-rust \
    "pedant-snippet pedant-syntax syn" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement)"

check_profile snippet-lang-go \
    "pedant-snippet pedant-syntax tree-sitter tree-sitter-go" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement tree-sitter-go)"

check_profile snippet-lang-python \
    "pedant-snippet pedant-syntax tree-sitter tree-sitter-python" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement tree-sitter-python)"

check_profile snippet-lang-javascript \
    "pedant-snippet pedant-syntax tree-sitter tree-sitter-javascript" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement tree-sitter-javascript)"

check_profile snippet-lang-typescript \
    "pedant-snippet pedant-syntax tree-sitter tree-sitter-typescript" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement tree-sitter-typescript)"

check_profile snippet-lang-bash \
    "pedant-snippet pedant-syntax tree-sitter tree-sitter-bash" \
    "${SYNTAX_MEMBERS}" \
    "$(grammar_complement tree-sitter-bash)"

# ---------------------------------------------------------------------------
# Resolved languages: the substrate and the projector compile, and the judgment
# surface above them never does.
# ---------------------------------------------------------------------------

check_profile snippet-graph-rust \
    "pedant-snippet pedant-syntax pedant-core pedant-graph syn" \
    "${GRAPH_MEMBERS}" \
    "$(grammar_complement)"

check_profile snippet-graph-go \
    "pedant-snippet pedant-syntax pedant-core pedant-graph tree-sitter-go" \
    "${GRAPH_MEMBERS}" \
    "$(grammar_complement tree-sitter-go)"

# ---------------------------------------------------------------------------
# Combined, installed, and everything at once.
#
# Cargo unifies features across a build, so the rows above compiling separately
# says nothing about the units a consumer of several gets.
# ---------------------------------------------------------------------------

check_profile snippet-combined \
    "pedant-snippet pedant-core pedant-graph tree-sitter-go tree-sitter-typescript syn" \
    "${GRAPH_MEMBERS}" \
    "$(grammar_complement tree-sitter-go tree-sitter-typescript)"

check_profile snippet-default \
    "pedant-snippet pedant-core pedant-graph syn tree-sitter tree-sitter-go tree-sitter-python tree-sitter-javascript tree-sitter-typescript tree-sitter-bash" \
    "${GRAPH_MEMBERS}" \
    ""

check_profile snippet-all-features \
    "pedant-snippet pedant-core pedant-graph syn tree-sitter tree-sitter-go tree-sitter-python tree-sitter-javascript tree-sitter-typescript tree-sitter-bash" \
    "${GRAPH_MEMBERS}" \
    ""

code_intelligence_assert_every_profile_ran \
    "${COMPILE_PROFILES}" "the code-intelligence compile matrix"

# The lint and documentation commands this section used to run are gone. Every
# one of them was a strict subset of a liveness row over the same profile:
# `clippy --no-default-features` is contained in the `--all-targets` form that
# row issues, and the no-features doc command was byte-identical to the one it
# issues. Two invocations of the same claim in one job is one budget spent
# twice, and the weaker of the two is the one that would have gone stale.

fi

# ---------------------------------------------------------------------------
# The identity every profile claims for one empty repository.
#
# Empty on purpose: equal admitted bytes, equal authorities, equal limits, and
# equal project keys in every row, so the only thing left to differ is the pair
# of language vectors the profile selects. The predicate itself asserts that its
# own vectors are the ones its features state; what only a caller running all
# twelve can assert is how those vectors relate, which is the table below.
# ---------------------------------------------------------------------------

# The exact public predicate every identity row runs.
readonly IDENTITY_PREDICATE="code_intelligence_revision_language_profiles_change_identity"

# The one runner that resolves a bare predicate to a single libtest identity.
#
# Repository-relative, because `cd_repo_root` already ran: a copy of this script
# somewhere else still reaches the runner this repository owns.
readonly IDENTITY_RUNNER=".github/scripts/run_exact_rust_test.sh"

# One line per row: `<label>|<key>|<revision>`.
IDENTITY_STATES=""

# The one receipt path every identity row writes through.
IDENTITY_RECEIPT=""

# Open that path and remove it however this run ends.
#
# One path with one trap rather than one `mktemp` per row. This script runs
# under `set -euo pipefail`, so a row that failed between its own `mktemp` and
# its own `rm` — a `cat` of an unreadable receipt is enough — left the file in
# `TMPDIR`, and an interrupt anywhere in the twelve-row loop left one too. The
# receipt is a fixed one-line document that the predicate rewrites in full, so
# twelve rows need one file and not twelve.
#
# This script opens one receipt rather than a fixture tree, so it owns the
# receipt and its cleanup directly.
open_identity_receipt() {
    IDENTITY_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/code-intelligence-identity.XXXXXX")" || exit 75
    trap 'rm -f -- "${IDENTITY_RECEIPT}"' EXIT
    trap 'exit 130' HUP INT TERM
}

# Run one profile's identity predicate and record what it claimed.
#
# The feature selection is the shared table's, in the exact-test runner's own
# vocabulary. Spelled here, this row was the third of four copies and the one
# that had already drifted: it hand-listed eight feature names because the
# runner had no `all` token, so a ninth crate feature would have dropped out of
# this row while the compile and liveness sections picked it up through
# `--all-features`.
identity_row() {
    local label="$1" profile
    code_intelligence_require_profile "${label}"
    profile="${CODE_INTELLIGENCE_PROFILE}"
    IDENTITY_PROFILES="${IDENTITY_PROFILES}${label}
"
    printf '[code-intelligence-identity] %s: %s\n' "${label}" "${profile}"

    # Truncated before the run, not after: the path is shared across rows, so a
    # predicate that exited 0 without writing would otherwise leave the previous
    # row's receipt to be read as this row's identity.
    : > "${IDENTITY_RECEIPT}"

    local status=0 output
    output="$(PEDANT_CODE_INTELLIGENCE_RECEIPT="${IDENTITY_RECEIPT}" \
        "${IDENTITY_RUNNER}" pedant-snippet interfaces "${profile}" "${IDENTITY_PREDICATE}" 2>&1)" \
        || status=$?
    if [ "${status}" -eq 75 ]; then
        printf '%s\n' "${output}" >&2
        exit 75
    fi
    if [ "${status}" -ne 0 ]; then
        printf '%s\n' "${output}" >&2
        violation "${label} did not state an identity"
        return
    fi

    local line languages coverage revision key
    line="$(cat -- "${IDENTITY_RECEIPT}")"

    # The receipt's shape is matched before any field is split out of it,
    # because `${line##* revision=}` is a no-op when the pattern is absent. A
    # predicate that stopped writing the revision therefore left `revision`
    # holding the whole `languages=… coverage=…` text — never empty, so the
    # emptiness guard below could not fire, and derived from the same two
    # vectors as the key, so equal keys carried equal "revisions" and different
    # keys carried different ones. `compare_identities` then passed 12 of 12 on
    # a receipt that stated no identity at all: the exact regression this
    # section exists to catch, read as clean.
    case "${line}" in
        "languages="*" coverage="*" revision="*) ;;
        *)
            violation "${label} left no readable receipt: ${line}"
            return
            ;;
    esac

    languages="${line#languages=}"
    languages="${languages%% *}"
    coverage="${line#* coverage=}"
    coverage="${coverage%% *}"
    revision="${line##* revision=}"
    # The shape says the three field names are present and in order; this says
    # each one carries a value.
    if [ -z "${languages}" ] || [ -z "${coverage}" ] || [ -z "${revision}" ]; then
        violation "${label} left no readable receipt: ${line}"
        return
    fi
    key="${languages}-${coverage}"
    IDENTITY_STATES="${IDENTITY_STATES}${label}|${key}|${revision}
"
    printf '[code-intelligence-identity] %s: revision=%s vector=%s\n' \
        "${label}" "${revision}" "${key}"
}

# Hold every recorded pair to the two rules the claim states.
#
# The floor is the shared table's own length rather than a written-down twelve.
# A thirteenth profile has to state an identity like every other one, and a
# number typed beside the rows would keep admitting the table it was written to
# close.
compare_identities() {
    local recorded=0 stated left right left_rest right_rest
    local left_label left_key left_revision right_label right_key right_revision
    stated="$(count_nonempty_lines "$(code_intelligence_profile_labels)")"

    while IFS= read -r left; do
        [ -n "${left}" ] || continue
        recorded=$((recorded + 1))
        left_label="${left%%|*}"
        left_rest="${left#*|}"
        left_key="${left_rest%%|*}"
        left_revision="${left_rest#*|}"
        while IFS= read -r right; do
            [ -n "${right}" ] || continue
            right_label="${right%%|*}"
            [ "${right_label}" != "${left_label}" ] || continue
            right_rest="${right#*|}"
            right_key="${right_rest%%|*}"
            right_revision="${right_rest#*|}"
            if [ "${left_key}" = "${right_key}" ] && [ "${left_revision}" != "${right_revision}" ]; then
                violation "${left_label} and ${right_label} state the same language vector and different identities"
            fi
            if [ "${left_key}" != "${right_key}" ] && [ "${left_revision}" = "${right_revision}" ]; then
                violation "${left_label} and ${right_label} state different language vectors and the same identity"
            fi
        done <<< "${IDENTITY_STATES}"
    done <<< "${IDENTITY_STATES}"

    [ "${recorded}" -eq "${stated}" ] \
        || violation "the identity table recorded ${recorded} of ${stated} profiles"
}

if [ "${SECTION}" = "all" ] || [ "${SECTION}" = "identity" ]; then

open_identity_receipt

identity_row snippet-no-features
identity_row snippet-lang-rust
identity_row snippet-lang-go
identity_row snippet-lang-python
identity_row snippet-lang-javascript
identity_row snippet-lang-typescript
identity_row snippet-lang-bash
identity_row snippet-graph-rust
identity_row snippet-graph-go
identity_row snippet-combined
identity_row snippet-default
identity_row snippet-all-features

code_intelligence_assert_every_profile_ran \
    "${IDENTITY_PROFILES}" "the code-intelligence identity table"
compare_identities

fi

# ---------------------------------------------------------------------------
# What every closed profile lints, documents, runs, and publishes.
#
# The compile section proves a profile builds the units it was named for. It
# cannot prove the profile runs a test, and it cannot prove a conditional item
# is conditional on the feature it claims — a `cfg` that gates on the wrong
# feature compiles cleanly in both directions.
#
# Each row below therefore does four things with the one profile it names. It
# lints every target, which for the reduced profiles no other job in this
# repository reaches. It documents the public API with missing-doc denial. It
# runs `pedant-snippet`'s one integration root and requires a passing count
# above zero, so a row cannot report as live having executed nothing. And it
# reads the generated documentation for the items the profile's features select
# and for the items they do not — the one reading in this repository that can
# tell a correct `cfg` from one that gates on a feature nobody selected.
# ---------------------------------------------------------------------------

# Where rustdoc leaves this crate's pages.
#
# Removed before every row: the directory is shared across profiles, and a page
# left by the previous row would be read as this row's public API.
readonly DOC_ROOT="${CARGO_TARGET_DIR:-target}/doc/pedant_snippet"

# The items every profile publishes, whatever it selected.
#
# Their absence is what makes the conditional rows below mean something: a row
# that read an empty directory would find no forbidden item either.
readonly ALWAYS_ITEMS=(
    struct.CodeIntelligenceIndex.html
    struct.CodeIntelligenceState.html
    enum.CodeIntelligenceError.html
)

# The items only a graph producer publishes.
readonly GRAPH_ITEMS=(
    struct.StructureInstance.html
    struct.RelationQuery.html
    struct.PathQuery.html
)

# Run one closed profile's whole liveness row.
#
# Usage: liveness_row <label>
#
# The cargo arguments and the conditional item set are both the shared table's.
# Written out here, they were the fourth copy of the feature selection and a
# second authority for which profiles publish the graph surface — and a row
# whose clippy line named one profile while its item list expected another
# passed every guard this file carries.
liveness_row() {
    local label="$1"
    code_intelligence_require_profile_args "${label}"
    LIVENESS_PROFILES="${LIVENESS_PROFILES}${label}
"
    local cargo_args=(${CODE_INTELLIGENCE_ARGS[@]+"${CODE_INTELLIGENCE_ARGS[@]}"})

    local expected_items=()
    if code_intelligence_profile_states_graph "${label}"; then
        expected_items=("${GRAPH_ITEMS[@]}")
    fi

    printf '[code-intelligence-live] %s: %s\n' "${label}" "${cargo_args[*]-installed default}"
    check_command "${COMMAND_TAG}" "clippy-${label}" \
        cargo clippy --locked -p pedant-snippet ${cargo_args[@]+"${cargo_args[@]}"} \
        --all-targets -- -D warnings

    rm -rf -- "${DOC_ROOT}"
    check_command "${COMMAND_TAG}" "doc-${label}" env RUSTDOCFLAGS="${DOC_FLAGS}" \
        cargo doc --locked --no-deps -p pedant-snippet ${cargo_args[@]+"${cargo_args[@]}"}

    liveness_tests "${label}" ${cargo_args[@]+"${cargo_args[@]}"}
    liveness_items "${label}" ${expected_items[@]+"${expected_items[@]}"}
}

# Run one profile's integration root and require it to have executed something.
#
# libtest's own summary is the reading. A filtered-out run and a passing run
# both exit 0, so "0 passed" is exactly the state a row would otherwise report
# as live.
liveness_tests() {
    local label="$1"
    shift
    local passed=""
    cargo_capture "test-${label}" \
        cargo test --locked -p pedant-snippet "$@" --test interfaces || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        violation "${label} could not run its integration root"
        return
    }
    passed="$(passing_count "${CARGO_CAPTURE_OUTPUT}")"
    case "${passed}" in
        "" | 0)
            violation "${label} executed ${passed:-no} predicates; a live row runs at least one"
            ;;
        *) printf '[code-intelligence-live] %s: %s predicates passed\n' "${label}" "${passed}" ;;
    esac
}

# Hold one profile's generated documentation to the items its features select.
#
# The expected list is the whole conditional surface for that row. Everything in
# `GRAPH_ITEMS` that the row does not expect is forbidden, so a `cfg` that
# stopped gating fails here rather than publishing a type a build cannot use.
liveness_items() {
    local label="$1"
    shift
    local expected=" $* " item
    if [ ! -d "${DOC_ROOT}" ]; then
        violation "${label} generated no documentation, so its item reading is vacuous"
        return
    fi
    for item in "${ALWAYS_ITEMS[@]}" "$@"; do
        test -f "${DOC_ROOT}/${item}" \
            || violation "${label} publishes no ${item}; the profile did not take"
    done
    for item in "${GRAPH_ITEMS[@]}"; do
        case "${expected}" in
            *" ${item} "*) continue ;;
        esac
        test ! -f "${DOC_ROOT}/${item}" \
            || violation "${label} publishes ${item} without selecting a graph producer"
    done
}

if [ "${SECTION}" = "all" ] || [ "${SECTION}" = "liveness" ]; then

liveness_row snippet-no-features
liveness_row snippet-lang-rust
liveness_row snippet-lang-go
liveness_row snippet-lang-python
liveness_row snippet-lang-javascript
liveness_row snippet-lang-typescript
liveness_row snippet-lang-bash
liveness_row snippet-graph-rust
liveness_row snippet-graph-go
liveness_row snippet-combined
liveness_row snippet-default
liveness_row snippet-all-features

code_intelligence_assert_every_profile_ran \
    "${LIVENESS_PROFILES}" "the code-intelligence liveness matrix"

fi

# ---------------------------------------------------------------------------
# What the five published crates document, and what their examples compile
# against.
#
# The liveness section above documents `pedant-snippet` alone. The navigation
# contract is spread over five crates — the wire vocabulary, the structure
# inventories, the resolution substrate, the graph, and the product — and a
# consumer reads one page set. `-D missing_docs` is what makes that page set
# complete, and it is denied here for every one of them under the profile that
# publishes the most surface, because an item behind a feature nothing selects is
# an item no doc build ever reads.
#
# The doctests are the other half. A page can document a method that no longer
# exists in the shape the page describes; an example that compiles cannot. They
# run under the same profile as the doc build, so an example naming a
# feature-gated type is compiled in the build that has it.
# ---------------------------------------------------------------------------

# One line per documented crate: `<package>|<profile arguments>`.
#
# `pedant-core` is documented without default features and with Go resolution:
# the judgment surface has its own doc job in the workspace matrix, and the
# navigation contract consumes the substrate half.
readonly DOC_PACKAGES="\
pedant-types|--all-features
pedant-core|--no-default-features --features go-resolution
pedant-graph|--features go
pedant-snippet|--all-features"

# The public navigation surface, as pages. Read on the `pedant-snippet` row,
# which is the crate that publishes all of it.
#
# Stated as a list rather than trusted to `missing_docs`: that lint fires on an
# item that is published and undocumented, and says nothing about an item that
# stopped being published at all. A type withdrawn from the public API is a
# breaking change a doc build reports as clean.
readonly PUBLIC_ITEMS=(
    struct.CodeIntelligenceIndex.html
    struct.CodeIntelligenceIndexer.html
    struct.CodeIntelligenceState.html
    struct.CodeIntelligenceLimits.html
    struct.RepositoryLimits.html
    struct.NavigationResponse.html
    struct.QueryFailure.html
    struct.PageCursor.html
    struct.StructureHandle.html
    struct.LiveCodeIntelligenceIndex.html
    struct.RootWatcher.html
    struct.RelationQuery.html
    struct.PathQuery.html
    struct.AnalysisQuery.html
    enum.CodeIntelligenceError.html
    enum.ErrorCode.html
    struct.LimitField.html
    enum.StructureCoverage.html
)

# The eight questions, as methods on the published state page.
#
# A page exists for a type whose methods were all removed, so the type list above
# is not the whole claim. These are the operations both transports call.
readonly PUBLIC_METHODS="\
list_projects
search_symbols
outline_file
read_structure
structure_at
query_relations
find_path
analyze_graph"

# Where rustdoc leaves the product's pages, and the page the methods are read
# from.
readonly PUBLIC_PAGE="${DOC_ROOT}/struct.CodeIntelligenceState.html"

# The package whose example count the floor below is about.
readonly PRODUCT_PACKAGE="pedant-snippet"

# How many examples the product compiled, once its row has read it.
#
# A scalar, because one row is the only reader. The table of one line per
# documented crate that this replaced accumulated four answers nothing asked
# for, and each of them was folded to zero on the way in — which is the reading
# `passing_count` refuses to make.
PRODUCT_EXAMPLES=""

# Document one crate under missing-doc denial and compile its examples.
#
# The product's pages are removed before every row, and the product is the last
# row, so the surface read below is the one this run generated rather than one a
# previous configuration left behind.
rustdoc_row() {
    local package="$1"
    shift
    printf '[code-intelligence-doc] %s: %s\n' "${package}" "$*"
    rm -rf -- "${DOC_ROOT}"
    check_command "${COMMAND_TAG}" "doc-${package}" env RUSTDOCFLAGS="${DOC_FLAGS}" \
        cargo doc --locked --no-deps -p "${package}" "$@"

    local passed=""
    cargo_capture "doctest-${package}" cargo test --locked --doc -p "${package}" "$@" || {
        printf '%s\n' "${CARGO_CAPTURE_OUTPUT}" >&2
        violation "${package} could not compile its examples"
        return
    }
    # `passing_count` returns nothing rather than zero on purpose: no caller may
    # report a run it never saw as a run of none. This row used to fold the two
    # together with `${passed:-0}`, so an unreadable libtest summary printed
    # "0 examples compiled" and passed for every crate but the product.
    passed="$(passing_count "${CARGO_CAPTURE_OUTPUT}")"
    if [ -z "${passed}" ]; then
        violation "${package}'s doctest run states no libtest summary; it was not read"
        return
    fi
    case "${package}" in
        "${PRODUCT_PACKAGE}") PRODUCT_EXAMPLES="${passed}" ;;
    esac
    printf '[code-intelligence-doc] %s: %s examples compiled\n' "${package}" "${passed}"
}

# The product publishes every public navigation page and every question.
assert_the_public_surface_is_published() {
    local item method
    if [ ! -d "${DOC_ROOT}" ]; then
        violation "the product generated no documentation, so its surface reading is vacuous"
        return
    fi
    for item in "${PUBLIC_ITEMS[@]}"; do
        test -f "${DOC_ROOT}/${item}" \
            || violation "the public API publishes no ${item}"
    done
    if [ ! -f "${PUBLIC_PAGE}" ]; then
        violation "the state page is absent, so no question can be read from it"
        return
    fi
    local page
    page="$(cat -- "${PUBLIC_PAGE}")"
    while IFS= read -r method; do
        [ -n "${method}" ] || continue
        case "${page}" in
            *"method.${method}"*) ;;
            *) violation "the state page documents no ${method} method" ;;
        esac
    done <<< "${PUBLIC_METHODS}"
}

# The product's own examples are compiled, and there is at least one.
#
# A crate with no example passes `cargo test --doc` in a tenth of a second, and
# the doctest row above it would then be a claim about a compiler that read
# nothing. The floor is stated for the product alone: the substrate crates
# document their own surfaces under their own jobs, and requiring an example of
# every one of them would be this check inventing a documentation policy for
# crates it is not about.
assert_the_product_states_examples() {
    case "${PRODUCT_EXAMPLES}" in
        "" | 0)
            violation "the product compiled ${PRODUCT_EXAMPLES:-no} examples; its public API states at least one"
            ;;
    esac
}

if [ "${SECTION}" = "all" ] || [ "${SECTION}" = "rustdoc" ]; then

while IFS= read -r documented; do
    [ -n "${documented}" ] || continue
    package="${documented%%|*}"
    profile="${documented#*|}"
    # Word splitting is the point: a profile is fixed, space-separated cargo
    # arguments, and none of them may contain a space.
    # shellcheck disable=SC2086
    rustdoc_row "${package}" ${profile}
done <<< "${DOC_PACKAGES}"

assert_the_public_surface_is_published
assert_the_product_states_examples

fi

assert_no_violations "the code-intelligence configuration matrix drifted."

echo "code intelligence configuration matrix check: clean"
