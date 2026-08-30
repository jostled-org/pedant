#!/usr/bin/env bash
# code_intelligence_profiles.sh — the closed feature table of the
# code-intelligence product.
#
# Sourced by every reader; run directly it lists itself and nothing else.
#
# `pedant-snippet` publishes six language features and two graph producers, and
# four separate authorities used to state which features each named profile
# selects: the configuration matrix's compile arguments, its identity tokens,
# its liveness arguments, and the dependency closure's row arguments. Every one
# of them was a full spelling of the same twelve selections, and nothing checked
# that the four agreed — so a row whose compile line said `graph-go` while its
# liveness line said `graph-rust` passed every guard those files carry, and the
# two sections silently tested different profiles under one name. They had
# already drifted: the identity row for `snippet-all-features` hand-listed eight
# feature names because the exact-test runner had no `all` token, so a ninth
# crate feature would drop out of that row while compile and liveness picked it
# up through `--all-features`.
#
# Each row states one profile once:
#
#   <label>|<feature profile>|<graph>
#
#   label            the name every section prints and every model states
#   feature profile  the one vocabulary `cargo_infrastructure.sh` owns —
#                    `default`, `none`, `all`, or a comma-separated feature list
#   graph            `graph` when the profile selects a graph producer, and so
#                    publishes the graph navigation surface; empty otherwise
#
# The cargo arguments are derived from the feature profile rather than stated,
# because a profile and its flags are one fact: `cargo_feature_flags` is the one
# translator, and the exact-test runner, the step router, and this table all
# read a profile through it.
#
# Bash 3.2 compatible, because macOS ships nothing newer.

# The one translator from a feature profile to cargo flags is
# `cargo_infrastructure.sh`'s, and `code_intelligence_profile_args` below calls
# it. It arrives here rather than beside each caller so every consumer reads the
# same feature vocabulary without resetting another library's live state.
#
# Unloaded, `cargo_feature_flags` is "command not found" and
# `CARGO_FEATURE_FLAGS` is unset — so `CODE_INTELLIGENCE_ARGS` below would come
# back empty through its own `+` guard, and every label would run as the
# installed default. Twelve rows testing one profile, reported as twelve.
#
# Sourced only when the translator is absent. Both checkers read
# `repository_check_lib.sh` first, which loads that file and then keeps a
# running aggregate and a live capture in it; re-reading it here would reset
# both. It is also what lets a row table copy this file beside a falsified
# checker, which is the one consumer that holds the library and not its
# directory.
if ! command -v cargo_feature_flags > /dev/null 2>&1; then
    CODE_INTELLIGENCE_PROFILES_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" \
        || CODE_INTELLIGENCE_PROFILES_DIR=""
    if [ -z "${CODE_INTELLIGENCE_PROFILES_DIR}" ] \
        || [ ! -r "${CODE_INTELLIGENCE_PROFILES_DIR}/cargo_infrastructure.sh" ]; then
        echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
        exit 75
    fi
    # shellcheck source-path=SCRIPTDIR
    # shellcheck source=cargo_infrastructure.sh
    . "${CODE_INTELLIGENCE_PROFILES_DIR}/cargo_infrastructure.sh" || exit 75
fi

# The twelve profiles, in the order the plan names them: no feature, each of the
# six languages on its own, each resolved language, the combined selection, the
# installed default, and everything at once.
code_intelligence_profiles() {
    cat <<'PROFILES'
snippet-no-features|none|
snippet-lang-rust|lang-rust|
snippet-lang-go|lang-go|
snippet-lang-python|lang-python|
snippet-lang-javascript|lang-javascript|
snippet-lang-typescript|lang-typescript|
snippet-lang-bash|lang-bash|
snippet-graph-rust|graph-rust|graph
snippet-graph-go|graph-go|graph
snippet-combined|graph-rust,graph-go,lang-typescript|graph
snippet-default|default|graph
snippet-all-features|all|graph
PROFILES
}

# Every label the table states, one per line.
#
# The projection a section needs to prove it gave each profile a row. Four
# sections across two files write their rows out one label at a time — the
# compile, identity, and liveness matrices and the dependency closure — because
# a row table models and mutates each row by name. Nothing held those four
# lists to this table, so a thirteenth profile added here was compiled by no
# matrix row, closed by no closure row, and reported by nothing at all: the
# authority this file exists to be, read by none of its readers.
code_intelligence_profile_labels() {
    local row
    while IFS= read -r row; do
        [ -n "${row}" ] || continue
        printf '%s\n' "${row%%|*}"
    done <<< "$(code_intelligence_profiles)"
}

# The feature profile one label states, or nothing.
#
# The lookup is whole-field, so `snippet-lang-go` cannot answer for
# `snippet-lang-gopher`. A label the table does not carry answers with nothing,
# and every caller refuses that rather than running a profile the table never
# stated.
code_intelligence_profile_of() {
    local wanted="$1" row label
    while IFS= read -r row; do
        [ -n "${row}" ] || continue
        label="${row%%|*}"
        [ "${label}" = "${wanted}" ] || continue
        row="${row#*|}"
        printf '%s' "${row%%|*}"
        return 0
    done <<< "$(code_intelligence_profiles)"
    return 1
}

# Whether one label's profile selects a graph producer.
code_intelligence_profile_states_graph() {
    local wanted="$1" row label rest
    while IFS= read -r row; do
        [ -n "${row}" ] || continue
        label="${row%%|*}"
        [ "${label}" = "${wanted}" ] || continue
        rest="${row#*|}"
        [ "${rest#*|}" = "graph" ]
        return
    done <<< "$(code_intelligence_profiles)"
    return 1
}

# The cargo arguments one label's profile adds, in `CODE_INTELLIGENCE_ARGS`.
#
# An array rather than a string, because a feature list is one argument and a
# caller that split it on whitespace would hand cargo two. Bash 3.2 expands an
# empty array to an unbound variable under `set -u`, so every caller expands it
# through the `+` form — which is also what makes the installed default, whose
# profile adds no flag at all, a row like any other.
#
# Returns non-zero for a label the table does not carry, so a caller cannot run
# an unstated profile as if it were the default one.
#
# Read by the callers that source this file.
# shellcheck disable=SC2034
CODE_INTELLIGENCE_ARGS=()
code_intelligence_profile_args() {
    local profile
    profile="$(code_intelligence_profile_of "$1")" || return 1
    [ -n "${profile}" ] || return 1
    cargo_feature_flags "${profile}"
    # Read by the callers that source this file.
    # shellcheck disable=SC2034
    CODE_INTELLIGENCE_ARGS=(${CARGO_FEATURE_FLAGS[@]+"${CARGO_FEATURE_FLAGS[@]}"})
}

# Every language grammar this product can link, and the parser runtime beneath
# them.
#
# Here rather than in either reader, because two files ask the same question of
# one inventory. The dependency closure derives each row's `absent:` forbids from
# it; the configuration matrix derives each row's compiled-package forbids. Only
# the closure derived. The matrix kept the shape that had already failed in the
# closure — a separate runtime-plus-grammar string and a hand-typed forbid list
# on each of the six `lang-*` rows and on the combined one — and there the
# TypeScript row forbade Go, Python, and Bash and never named JavaScript, which
# is exactly where a `ts-typescript` that started forwarding to `ts-javascript`
# would land. Two lists that are complete on the day they are typed are two
# lists a sixth grammar joins neither of.
#
# Stated by name because a grammar is not a workspace member, so nothing derives
# it from `cargo metadata`. This is what is left of the hand-written half, and
# there is one of it.
CODE_INTELLIGENCE_GRAMMARS=(
    tree-sitter-python
    tree-sitter-javascript
    tree-sitter-typescript
    tree-sitter-go
    tree-sitter-bash
)
CODE_INTELLIGENCE_GRAMMAR_RUNTIME="tree-sitter"

# Every grammar one row does not link, in `CODE_INTELLIGENCE_NO_OTHER_GRAMMAR`.
#
# Usage: code_intelligence_no_other_grammar <prefix> [linked grammar ...]
#
# A row states the grammars it links and the rest are derived, so "and no other"
# is a complement rather than a list somebody has to keep.
#
# The runtime joins the complement when the row links no grammar at all, because
# a build that dispatches to no parser must not carry the parser library either.
# A row that links every grammar leaves the array empty.
#
# The prefix is the caller's vocabulary and nothing else. The closure speaks in
# specifications and wants `absent:tree-sitter-go`; the matrix reads an artifact
# stream and wants the package name on its own. One loop with a prefix is one
# complement; two loops would be two chances to derive it differently.
#
# Every expansion of the array takes the `+` form: bash 3.2 is what macOS ships,
# and there an empty array expands to an unbound variable under `set -u`. The two
# widest closure rows used to state no grammar set at all, so the array they
# would have expanded still held the previous row's forbids.
CODE_INTELLIGENCE_NO_OTHER_GRAMMAR=()
code_intelligence_no_other_grammar() {
    local prefix="$1"
    shift
    local grammar linked required
    CODE_INTELLIGENCE_NO_OTHER_GRAMMAR=()
    if [ "$#" -eq 0 ]; then
        CODE_INTELLIGENCE_NO_OTHER_GRAMMAR=("${prefix}${CODE_INTELLIGENCE_GRAMMAR_RUNTIME}")
    fi
    for grammar in "${CODE_INTELLIGENCE_GRAMMARS[@]}"; do
        linked=""
        for required in "$@"; do
            [ "${required}" != "${grammar}" ] || linked=1
        done
        [ -n "${linked}" ] || CODE_INTELLIGENCE_NO_OTHER_GRAMMAR+=("${prefix}${grammar}")
    done
}

# The refusal a label this table does not carry earns.
#
# One wording, because four sections asked the same question and each wrote the
# same three lines to refuse it: a row naming a profile that does not exist is
# the section misspelling itself, not a closure or a compile that drifted, and
# four owners for one sentence are four chances to say it differently.
#
# Left in the caller's own shell rather than answered through a substitution:
# `exit` inside one kills the subshell alone, and the caller would read the
# status as the label being unstated and carry on with the previous row's
# arguments.
code_intelligence_refuse_unstated_profile() {
    echo "error: $1 is no profile the shared table states" >&2
    exit 1
}

# The feature profile one label states, in `CODE_INTELLIGENCE_PROFILE`, or the
# refusal above.
#
# A variable rather than standard output for the reason the refusal gives.
CODE_INTELLIGENCE_PROFILE=""
code_intelligence_require_profile() {
    CODE_INTELLIGENCE_PROFILE="$(code_intelligence_profile_of "$1")" \
        || CODE_INTELLIGENCE_PROFILE=""
    [ -n "${CODE_INTELLIGENCE_PROFILE}" ] || code_intelligence_refuse_unstated_profile "$1"
}

# The cargo arguments one label's profile adds, or the refusal above.
code_intelligence_require_profile_args() {
    code_intelligence_profile_args "$1" || code_intelligence_refuse_unstated_profile "$1"
}

# Fail unless one section gave every label this table states a row.
#
# Usage: code_intelligence_assert_every_profile_ran <asked labels> <section>
#
# `asked` is the labels that section entered, one per line, recorded as each row
# ran rather than written down beside them: a list a section states about itself
# is the second authority this whole file exists to remove.
#
# An empty `asked` is refused on its own. A section whose rows were all removed
# asks about no label, and every table satisfies a comparison against nothing —
# which is the same silent pass a section missing one row makes, only wider.
#
# An empty label table is refused on its own terms too, and the guard was
# one-sided until it was: the membership loop below ranges over the table, so a
# table that answered with nothing ran its body no times, left `missing` at 0,
# and returned 0. A matrix that ran one profile of twelve passed — the very
# failure this function is named for, read backwards. The count is taken in that
# same loop rather than beside it, so it is a reading of the rows compared and
# not a second opinion about them.
#
# The membership test is a whole-line `case` rather than the repository
# library's `contains_line`, and both counts are loops rather than that library's
# `count_nonempty_lines`. This file is the profile authority and stays readable
# by a consumer that sources it and `cargo_infrastructure.sh` alone.
code_intelligence_assert_every_profile_ran() {
    local asked=$'\n'"$1"$'\n' section="$2" labels label ran=0 stated=0 missing=0
    while IFS= read -r label; do
        [ -n "${label}" ] || continue
        ran=$((ran + 1))
    done <<< "$1"
    if [ "${ran}" -eq 0 ]; then
        echo "error: ${section} ran no profile at all; it states a row for none of the table" >&2
        exit 1
    fi
    labels="$(code_intelligence_profile_labels)"
    while IFS= read -r label; do
        [ -n "${label}" ] || continue
        stated=$((stated + 1))
        case "${asked}" in
            *$'\n'"${label}"$'\n'*) ;;
            *)
                echo "error: ${section} states no row for ${label}, which the profile table carries" >&2
                missing=$((missing + 1))
                ;;
        esac
    done <<< "${labels}"
    if [ "${stated}" -eq 0 ]; then
        echo "error: the profile table carries no label at all; ${section} was held to nothing" >&2
        exit 1
    fi
    [ "${missing}" -eq 0 ] || exit 1
}

# Run directly, the table lists itself and reads nothing else.
#
# A caller that has to prove a profile is in the matrix reads the rows every
# section reads, rather than searching a checker for one of the four spellings
# this file replaced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        --list) code_intelligence_profiles ;;
        *)
            echo "usage: ${BASH_SOURCE[0]} --list" >&2
            exit 64
            ;;
    esac
fi
