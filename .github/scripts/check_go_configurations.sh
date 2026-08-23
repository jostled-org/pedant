#!/usr/bin/env bash
#
# Run every feature configuration the Go surface is claimed to support, and
# prove each one selected the tests it was named for.
#
# Clippy proving a configuration compiles is not the same as running it, and a
# `cargo test` that selected nothing exits 0. Both failure modes read as a
# passing matrix, and both have happened in this workspace: a feature-gated
# support module that stopped compiling in one profile, and a `--list` that
# came back with zero rows under a feature nobody executed.
#
# So each row lists first. The listing is compared with a written-down count of
# the Go predicates that configuration must select — stated here, never derived
# from the output — and the row runs only once the count matches. A row that
# selects no test at all fails on its own, before the count is read, because a
# broken test binary and an empty one print the same thing.
#
# The counts are per configuration rather than one number, and that is the whole
# point of the matrix:
#
#   * default-off — `pedant-core` and `pedant-graph` with no Go feature. The
#     count is what compiles in every profile and nothing more. That floor is
#     not zero: the release predicates read tracked manifests and scripts, so
#     they hold — and must run — in the profile a publication is cut from.
#   * Go-only — one Go feature and nothing else. This is the configuration a
#     consumer selects, and the one that has to run the Go predicates.
#   * all-feature — `--all-features`, which must not select less than the Go
#     feature named on its own.
#   * unified — two features resolved together, and one deliberate mismatch:
#     `pedant-core/go-resolution` enabled through `pedant-graph` while
#     `pedant-graph/go` stays off. The Go grammar is linked and the Go adapter
#     is not, so the graph root must still select only the profile-independent
#     rows. Without this row, a Go adapter that had quietly stopped gating on
#     its own feature would look identical to one that had not.
#
# Clippy and rustdoc close the same gap from the compile side: the Go feature
# graphs are default-off, so no other job in this repository lints the adapters
# or denies a missing doc on them.
#
# Runs beneath the caller's build lease and inherited `CARGO_TARGET_DIR`, opens
# no temporary root, and reaches no network beyond what the lockfile already
# pins. Exit 0 clean, exit 1 on violation.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root
require_tools cargo rg

# Every Go predicate this plan registers is named `go_<claim>`, so one pattern
# counts them across five roots. It is anchored on the module separator as well
# as on the start of the line, because libtest prints a test's full module path.
readonly GO_PREDICATE='(^|::)go_[a-z_0-9]+: test$'

# What libtest prints for any test at all, so an empty binary is told apart
# from a binary that holds no Go row.
readonly ANY_PREDICATE=': test$'

# Deny a missing doc on every Go-enabled documentation build.
readonly DOC_FLAGS="-D missing_docs"

status=0

violation() {
    echo "error: $*" >&2
    status=1
}

# Count the lines of a listing that match a pattern.
#
# `rg -c` exits 1 on no match, which is a count of zero rather than a failure,
# and it exits 2 when the matcher itself broke. Only the first is folded into a
# number; a broken matcher stops the check rather than reading as zero.
count_matching() {
    local listing="$1" pattern="$2" found rg_status=0
    found="$(rg -c "${pattern}" <<<"${listing}")" || rg_status=$?
    case "${rg_status}" in
        0) printf '%s' "${found}" ;;
        1) printf '0' ;;
        *)
            echo "error: rg exited ${rg_status} without answering; the count did not run." >&2
            exit 1
            ;;
    esac
}

# List one test root, prove the selection, then run it.
#
# `expected` is the number of Go predicates the configuration must select.
check_root() {
    local label="$1" expected="$2"
    shift 2
    local listing selected found

    printf '[go-config] %s: cargo test %s\n' "${label}" "$*"
    listing="$(cargo test --locked "$@" -- --list)"

    selected="$(count_matching "${listing}" "${ANY_PREDICATE}")"
    if [ "${selected}" -eq 0 ]; then
        violation "${label} selected no test at all; the row would pass having run nothing"
        return
    fi

    found="$(count_matching "${listing}" "${GO_PREDICATE}")"
    if [ "${found}" -ne "${expected}" ]; then
        violation "${label} selects ${found} Go predicates, and the matrix states ${expected}"
        rg "${GO_PREDICATE}" <<<"${listing}" >&2 || true
        return
    fi
    printf '[go-config] %s: %s of %s selected rows are Go predicates\n' \
        "${label}" "${found}" "${selected}"

    cargo test --locked "$@" || violation "${label} failed"
}

# Run one lint or documentation command that no other job reaches.
check_command() {
    local label="$1"
    shift
    printf '[go-config] %s: %s\n' "${label}" "$*"
    "$@" || violation "${label} failed"
}

# ---------------------------------------------------------------------------
# Default-off: the Go features are not selected, so no Go behaviour is linked.
#
# The graph root's two rows and the core root's one are structural: they read
# tracked source, manifests, and scripts rather than any Go type, and hold under
# every profile, so their count is the floor a default build selects rather than
# an exception to it. The core row is the release-owner predicate, which states
# what publishing the Go surface costs the eight published packages — a claim a
# release build has to be able to check without the feature it is about.
# ---------------------------------------------------------------------------

check_root core-default-off 1 \
    -p pedant-core --no-default-features --test substrate
check_root graph-default-off 2 \
    -p pedant-graph --test graph
check_root syntax-default-off 0 \
    -p pedant-syntax --no-default-features --test enclosing_unit

# ---------------------------------------------------------------------------
# Go-only: one Go feature, and nothing beside it.
#
# `pedant-core` runs twice. The first row is the configuration a consumer
# selects — the production feature alone — and it is the row that proves the
# support tree still compiles without the proof-only probe. The second adds the
# probe, which is what the observed predicates need.
# ---------------------------------------------------------------------------

check_root core-go-only 26 \
    -p pedant-core --no-default-features --features go-resolution --test substrate
check_root core-go-and-probe 30 \
    -p pedant-core --no-default-features --features go-resolution,resolution-test-support --test substrate
check_root graph-go-only 12 \
    -p pedant-graph --no-default-features --features go --test graph
check_root syntax-go-only 3 \
    -p pedant-syntax --no-default-features --features ts-go --test enclosing_unit
check_root lang-go-only 13 \
    -p pedant-lang --no-default-features --features ts-go --test capability

# The grammar-absent capability contract. `pedant-lang` keeps its regex fallback
# for Go, so this root selects Go rows without any Go grammar at all.
check_root lang-default-off 11 \
    -p pedant-lang --no-default-features --test capability

# ---------------------------------------------------------------------------
# All-feature: everything the crate publishes, at once.
# ---------------------------------------------------------------------------

check_root graph-all-features 12 \
    -p pedant-graph --all-features --test graph

# ---------------------------------------------------------------------------
# Unified: features resolved together, including one deliberate mismatch.
# ---------------------------------------------------------------------------

check_root core-unified 30 \
    -p pedant-core --features go-resolution,resolution-test-support --test substrate
check_root graph-core-go-without-adapter 2 \
    -p pedant-graph --no-default-features --features pedant-core/go-resolution --test graph

# ---------------------------------------------------------------------------
# Lint and document the configurations nothing else reaches.
# ---------------------------------------------------------------------------

check_command clippy-core-go \
    cargo clippy --locked -p pedant-core --no-default-features --features go-resolution -- -D warnings
check_command clippy-core-go-all-targets \
    cargo clippy --locked -p pedant-core --no-default-features --features go-resolution,resolution-test-support --all-targets -- -D warnings
check_command clippy-graph-all-features \
    cargo clippy --locked -p pedant-graph --all-features --all-targets -- -D warnings

# `env` rather than an assignment prefix: a prefix on a shell function leaves the
# variable set in this shell afterwards, so every later cargo command would
# inherit the doc flags too.
check_command doc-core-go env RUSTDOCFLAGS="${DOC_FLAGS}" \
    cargo doc --locked --no-deps -p pedant-core --no-default-features --features go-resolution
check_command doc-graph-all-features env RUSTDOCFLAGS="${DOC_FLAGS}" \
    cargo doc --locked --no-deps -p pedant-graph --all-features

if [ "${status}" -ne 0 ]; then
    echo "error: the Go configuration matrix drifted." >&2
    exit 1
fi

echo "go configuration matrix check: clean"
