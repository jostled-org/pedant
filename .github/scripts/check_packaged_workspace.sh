#!/usr/bin/env bash
#
# check_packaged_workspace.sh — compile the eight release archives the way a
# registry consumer receives them.
#
# `cargo check` in this repository proves nothing about publication. Every
# first-party edge resolves through a path dependency here, so a member may use
# an API that its packaged requirement will never carry; packaging replaces
# those paths with registry requirements, and the mistake surfaces only after
# the version is immutable. This proof stages the release the way finalization
# will squash it, lets release-plz generate every version and requirement,
# packages all eight members, and compiles the extracted archives against each
# other under exactly those generated requirements. It then installs the
# navigation product out of its own archive and asks it every question it
# publishes, over a mixed-language repository this run wrote outside the
# checkout, through both the command line and a real stdio MCP session — because
# a release that compiles and cannot answer is a release nobody can use.
#
# It owns its clone, its tool root, its archives, and its generated workspace.
# It releases all but the tool root on success, failure, and interruption; that
# one it keeps, inside the target and named for both pinned revisions, because
# rebuilding it is most of a cold run and it is what a later run reads its warm
# state from. It never writes a commit, tag, manifest, lockfile, or changelog
# into the caller's repository, and it never deletes the runner's registry cache
# or the caller's target root.
#
# Independently pinned tools are not the pinned GitHub action. This proof says
# the packaged graph compiles; the release workflow remains the publication
# authority.
#
# Two stages, because building the two pinned tools from source costs 1,429
# measured seconds against a 1,200-second verification slice, and five times
# what the release proof itself costs. `<repository-root> --install-tools
# <tool>` builds one of them into a revision-named root inside the caller's
# target and stops; `<repository-root>` alone runs the release proof, which asks
# those binaries their versions and is held to the warm budget they earn. Any
# stage run alone is still correct: a proof that finds no pinned build makes one
# and pays the cold budget for it.
#
# Exit 0 clean, 75 when the machine could not do the work, non-zero otherwise.

set -euo pipefail

# The revisions this proof builds, and the versions those revisions must be.
# A tag moves; a commit does not, and a proof whose tooling drifts silently
# stops describing the release it claims to.
RELEASE_PLZ_VERSION="0.3.160"
RELEASE_PLZ_REVISION="7e38e7a93dff31bbf6312400f79b9de36e8d3834"
SEMVER_CHECKS_VERSION="0.48.0"
SEMVER_CHECKS_REVISION="c9d2ce641c044846899ade23a34d3d5f40341ce9"
readonly RELEASE_PLZ_VERSION RELEASE_PLZ_REVISION
readonly SEMVER_CHECKS_VERSION SEMVER_CHECKS_REVISION

# The one breaking commit the isolated clone carries, and the identity that
# writes it. release-plz reads conventional-commit subjects to choose the next
# version, so the proof must show it the subject finalization will squash to
# rather than the checkpoint history this branch actually holds.
PROOF_COMMIT_SUBJECT="feat!: implement code-intelligence-index-and-surfaces"
RELEASE_STAGING_SUBJECT="chore: stage the release-plz update"
PROOF_IDENTITY_NAME="pedant packaged workspace proof"
PROOF_IDENTITY_EMAIL="packaged-workspace-proof@pedant.invalid"
PROOF_BRANCH_NAME="packaged-workspace-proof"
readonly PROOF_COMMIT_SUBJECT RELEASE_STAGING_SUBJECT
readonly PROOF_IDENTITY_NAME PROOF_IDENTITY_EMAIL PROOF_BRANCH_NAME

RELEASE_PACKAGE_COUNT=8
STAGING_PREFIX="pedant-packaged-workspace"
readonly RELEASE_PACKAGE_COUNT STAGING_PREFIX

# The navigation product this release ships, the binary installing it produces,
# and how many tools that binary serves.
#
# Three statements because they are three facts. A workspace whose binary is not
# named for its package would still install correctly and the journey would look
# for something that is not there. And the tool count is the product's own, not
# the release's package count: eight tools and eight packages agree today by
# coincidence, so a ninth published package borrowed as a tool count would refuse
# a correct listing and name a package total while doing it.
#
# Compiling the archives says the release links. It does not say the product an
# operator installs out of them can index a repository and answer a question,
# which is the whole reason this release exists — so the proof installs that
# binary and asks it, over a repository of its own outside the caller's
# checkout.
NAVIGATION_PACKAGE="pedant-snippet"
NAVIGATION_BINARY="pedant-snippet"
NAVIGATION_TOOL_COUNT=8
readonly NAVIGATION_PACKAGE NAVIGATION_BINARY NAVIGATION_TOOL_COUNT

# Where the pinned tools live, and what each stage is allowed to cost.
#
# The tool root sits inside the caller's target root and is named for both
# pinned revisions, because it is the warm claim and a claim has to be checkable.
# `cargo install` moves its binary out of the build directory, so nothing under
# `release/` survives to be asked; what survives is whatever the installation
# root kept. Naming that root for the revisions means a moved pin is a different
# root rather than a stale binary, and a pruned or copied target answers the
# same probe honestly: the binaries are there and pinned, or the run is cold.
#
# Every number below came off a measured run against an empty target root
# rather than off an estimate, and carries headroom over what that run cost. A
# budget nobody measured is discovered by the first genuinely cold caller, and
# a proof that cannot meet its own ceiling proves nothing about the release.
#
# Measured cold, empty target: cargo-semver-checks 836s and 808,620KiB,
# release-plz 593s and 1,476,192KiB, the release proof over those 266s and
# 925,252KiB, owned staging peaking at 92,528KiB.
#
# The packaged journey adds one debug installation of the navigation product,
# measured against an empty target at 11s and 473,428KiB on a ten-core Apple
# silicon host, under the same profile the stage states rather than the caller's.
# That is why the ceilings below are unchanged: the warm pair still holds the
# release proof and the journey together with room, and a budget raised for work
# nobody measured is a budget that no longer refuses anything.
TOOL_ROOT_NAME=".pedant-packaged-workspace-7e38e7a-c9d2ce64.tools"
INSTALL_RUNTIME_BUDGET_SECONDS=1100
INSTALL_TARGET_BUDGET_KIB=2097152
COLD_RUNTIME_BUDGET_SECONDS=2100
WARM_RUNTIME_BUDGET_SECONDS=600
COLD_TARGET_BUDGET_KIB=5242880
WARM_TARGET_BUDGET_KIB=2097152
OWNED_TEMP_BUDGET_KIB=1048576
readonly TOOL_ROOT_NAME
readonly INSTALL_RUNTIME_BUDGET_SECONDS INSTALL_TARGET_BUDGET_KIB
readonly COLD_RUNTIME_BUDGET_SECONDS WARM_RUNTIME_BUDGET_SECONDS
readonly COLD_TARGET_BUDGET_KIB WARM_TARGET_BUDGET_KIB OWNED_TEMP_BUDGET_KIB

REQUIRED_TOOLS="cargo cat cp date dirname du env git jq mkdir mktemp rg rm tar"
readonly REQUIRED_TOOLS

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`, and
# a match there both enters the wrong directory and prints it — leaving
# `script_dir` a two-line value naming a tree this repository does not own.
#
# Emptiness alone cannot catch a `dirname` that failed: `cd -- ""` succeeds and
# stays put, so `script_dir` comes back non-empty and names whatever directory
# the caller stood in — and the proof would then anchor its repository root two
# levels above that. The classifier's presence beside the script is what says
# the resolution landed here.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || script_dir=""
if [ -z "${script_dir}" ] || [ ! -r "${script_dir}/cargo_infrastructure.sh" ]; then
    echo "error: cannot resolve the directory holding ${BASH_SOURCE[0]}" >&2
    exit 75
fi
readonly script_dir
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh" || exit 75

# Everything this run owns or measures. Named before the first trap, because a
# handler that fires between two assignments must still be able to read them.
repository_root=""
target_root=""
staging_root=""
clone_root=""
tool_root=""
archive_root=""
workspace_root=""
staged_metadata=""
archive_metadata=""
clone_branch=""
release_order=()
release_order_json="[]"
release_versions=()
staged_version=""
inbound_packages=""
journey_root=""
journey_install_root=""
journey_binary=""
journey_revision=""
journey_answers=0
start_seconds=0
target_start_kib=0
temp_peak_kib=0
warm_state="cold"

# This tree is wrong.
fail() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

# This machine could not do the work, which is a different answer and a
# different retry. The classifier owns the status; this owns the wording.
unavailable() {
    printf 'error: %s\n' "$1" >&2
    exit "${CARGO_INFRASTRUCTURE_STATUS}"
}

# Run one external operation, classify it, and stop the proof if it failed.
#
# `cargo_run` folds an ordinary failure into the aggregate and continues, which
# is right for a batch of independent checks and wrong here: every later stage
# reads what the failed one was supposed to produce, so a proof that carried on
# would report a second, invented failure instead of the real first one.
run_classified() {
    cargo_run "$@"
    local worst
    worst="$(cargo_worst)"
    test "${worst}" -eq 0 || exit "${worst}"
}

# The same, for an operation whose output this proof has to read rather than
# replay. The transcript still reaches the operator and still reaches the
# classifier; only its destination differs.
#
# The classifier is handed the diagnostic stream alone, because that is where
# every infrastructure signature is written and the other stream is a metadata
# document this proof would otherwise slurp into a shell variable to grep. A
# stream that cannot be read at all is an unavailable machine: the redirect that
# was supposed to create it is the first thing an exhausted volume takes away,
# and reading that as an ordinary failure is the one mistake the classifier
# exists to prevent.
capture_classified() {
    local label="$1"
    local destination="$2"
    shift 2
    local status=0
    "$@" > "${destination}" 2> "${destination}.err" || status=$?
    cat -- "${destination}.err" >&2 \
        || unavailable "the ${label} transcript could not be read."
    cargo_receipt "${label}" "${destination}.err"
    local classified
    classified="$(cargo_classify "${status}" "${destination}.err")"
    cargo_record "${classified}"
    local worst
    worst="$(cargo_worst)"
    test "${worst}" -eq 0 || exit "${worst}"
}

# Every tool this proof shells out to, proved present before it starts.
#
# The interpreter is not on that list. A shell this script never invokes is a
# shell the list cannot claim to have checked, and a list holding a name nobody
# calls invites the next one to hold a name somebody does.
#
# The probe itself is the classifier's, and it leaves with the same 75 this
# file's own `unavailable` does. A private copy of the loop is a second owner of
# the answer "an absent tool is not this repository's fault".
require_proof_tools() {
    # The list is space-separated names, and splitting it is the point.
    # shellcheck disable=SC2086
    require_tools ${REQUIRED_TOOLS}
}

# Capture the one checkout this proof is allowed to read, and seal it.
#
# A scheduler or fixture may invoke this script from another directory. That
# working directory is not authority for the release under proof. The caller
# names the root; this function normalizes it and requires that exact directory,
# rather than a parent discovered from a nested path, to be Git's toplevel.
capture_repository_root() {
    local requested_root="${1:-}" git_root
    test -n "${requested_root}" \
        || fail "a repository-root argument is required."
    test -d "${requested_root}" \
        || fail "repository root must be an existing directory: ${requested_root}"
    repository_root="$(CDPATH='' cd -- "${requested_root}" && pwd -P)" \
        || fail "repository root could not be entered: ${requested_root}"
    git_root="$(git -C "${repository_root}" rev-parse --show-toplevel 2> /dev/null)" \
        || fail "repository root is not a Git working tree: ${repository_root}"
    git_root="$(CDPATH='' cd -- "${git_root}" && pwd -P)" \
        || fail "the Git toplevel could not be entered: ${git_root}"
    test "${repository_root}" = "${git_root}" \
        || fail "repository root ${repository_root} does not match its Git toplevel ${git_root}."
    readonly repository_root
    cd -- "${repository_root}"
}

# Capture the target root this proof inherits, and seal it.
#
# Every Cargo command below writes into it, including the two pinned tool
# builds, so a proof that chose its own would rebuild the world on every run
# and a proof that dropped it would scatter artifacts through the caller's
# tree. It is the caller's to choose and this run's to reuse unchanged.
capture_target_root() {
    target_root="${CARGO_TARGET_DIR:-}"
    readonly target_root
    test -n "${target_root}" \
        || fail "CARGO_TARGET_DIR must name one caller-owned target root."
    case "${target_root}" in
        /*) ;;
        *) fail "CARGO_TARGET_DIR must be absolute: ${target_root}" ;;
    esac
    test -d "${target_root}" \
        || fail "CARGO_TARGET_DIR must be an existing directory: ${target_root}"
    test -w "${target_root}" \
        || fail "CARGO_TARGET_DIR must be writable: ${target_root}"
    export CARGO_TARGET_DIR
    tool_root="${target_root}/${TOOL_ROOT_NAME}"
    readonly tool_root
}

# The release order, read from the file that owns it.
#
# release-plz publishes in this order and nothing else may restate it. The proof
# reads it for two things: the member inventory — which packages must have a
# manifest, an archive, and a workspace member — and one deterministic listing
# order, so the generated workspace, the patch table, and every refusal name the
# eight members the same way on every run. Packaging itself is a single
# workspace-wide invocation and needs no order at all.
#
# The matcher runs through `rg_status` and its answer is read from `RG_OUTPUT`,
# not from a process substitution. Fed from one of those, ripgrep's status is
# nobody's — the hazard this same file documents at `copy_untracked_files` — and
# a matcher that exited 2 produced "release-plz.toml names 0 packages rather
# than 8": a false statement about the tree, from a reader that never ran.
read_release_order() {
    local name read_status=0
    # `${1}` is ripgrep's own capture-group reference, so it stays unexpanded.
    # shellcheck disable=SC2016
    rg_status -N -o -r '${1}' '^name = "([^"]+)"$' -- release-plz.toml || read_status=$?
    case "${read_status}" in
        0) ;;
        1) fail "release-plz.toml names no package at all." ;;
        *) unavailable "release-plz.toml could not be read for its release order." ;;
    esac
    while IFS= read -r name; do
        test -n "${name}" || continue
        release_order+=("${name}")
    done <<< "${RG_OUTPUT}"
    test "${#release_order[@]}" -eq "${RELEASE_PACKAGE_COUNT}" \
        || fail "release-plz.toml names ${#release_order[@]} packages rather than ${RELEASE_PACKAGE_COUNT}."
    release_order_json="$(printf '%s\n' "${release_order[@]}" \
        | jq -R -s -c 'split("\n") | map(select(length > 0))')"
    assert_release_order_matches_manifests
    assert_release_order_names_the_navigation_product
}

# The release publishes the product the journey installs.
#
# Asked here rather than where the journey needs it, because everything between
# the two costs a clone, two pinned tool builds, a release-plz run, and eight
# archives. A release order that lost this package has no journey to run, and
# the cheapest moment to say so is before any of that.
assert_release_order_names_the_navigation_product() {
    local name
    for name in "${release_order[@]}"; do
        case "${name}" in
            "${NAVIGATION_PACKAGE}") return 0 ;;
            *) ;;
        esac
    done
    fail "the release order does not publish the navigation product ${NAVIGATION_PACKAGE}."
}

# Every named package has the manifest it claims, before anything is staged.
#
# The search runs through `rg_status`, so "the manifest does not declare this
# package" and "the matcher failed" stay two answers. Collapsed into one, a
# reader that never ran would be reported as a manifest that names the wrong
# package, and the operator would go and read a file that is already correct.
assert_release_order_matches_manifests() {
    local name manifest read_status
    for name in "${release_order[@]}"; do
        manifest="${repository_root}/${name}/Cargo.toml"
        test -f "${manifest}" \
            || fail "the release order names ${name}, which has no manifest at ${manifest}."
        read_status=0
        rg_status -N -q "^name = \"${name}\"\$" -- "${manifest}" || read_status=$?
        case "${read_status}" in
            0) ;;
            1) fail "${manifest} does not declare package ${name}." ;;
            *) unavailable "${manifest} could not be read for its package name." ;;
        esac
    done
}

# Prove the machine, the target root, and the release order before this proof
# changes any state at all.
preflight() {
    require_proof_tools
    capture_repository_root "$1"
    capture_target_root
    read_release_order
}

# Release the clone, the archives, and the generated workspace.
#
# Only those. The registry cache, the target root, the pinned tool root inside
# it, and the caller's repository belong to somebody else or to the next run,
# and a proof that tidied them would cost its next caller a quarter of an hour.
cleanup() {
    if [ -n "${staging_root}" ] && [ -d "${staging_root}" ]; then
        rm -rf -- "${staging_root}"
    fi
}

# Leave with the signal's status, so the build lease or test process guard that
# started this proof kills and reaps the whole command group rather than
# waiting on a shell that swallowed its own interruption.
interrupted() {
    cleanup
    exit "$((128 + $1))"
}

trap 'cleanup' EXIT
trap 'interrupted 1' HUP
trap 'interrupted 2' INT
trap 'interrupted 15' TERM

# One staging root, and every temporary file this run makes inside it.
#
# Redirecting TMPDIR is the point: the classifier's captures, tar's scratch,
# and Cargo's own temporaries would otherwise outlive an interrupted run in a
# directory nobody here owns.
create_staging_root() {
    staging_root="$(mktemp -d "${TMPDIR:-/tmp}/${STAGING_PREFIX}.XXXXXX")" \
        || unavailable "no staging root could be created."
    # An inherited TMPDIR may end in a slash, and mktemp keeps whatever it was
    # given. Cargo reports normalized manifest paths, so the graph check below
    # would refuse every member over a doubled separator. A logical `cd`
    # collapses that without resolving symlinks, which Cargo does not resolve
    # either.
    staging_root="$(cd -- "${staging_root}" && pwd)" \
        || unavailable "the staging root could not be resolved."
    clone_root="${staging_root}/clone"
    archive_root="${staging_root}/archives"
    workspace_root="${staging_root}/archive-workspace"
    staged_metadata="${staging_root}/capture/staged-metadata.json"
    archive_metadata="${staging_root}/capture/archive-metadata.json"
    journey_root="${staging_root}/journey"
    journey_install_root="${staging_root}/install"
    journey_binary="${journey_install_root}/bin/${NAVIGATION_BINARY}"
    mkdir -p -- "${archive_root}" "${workspace_root}" \
        "${staging_root}/capture" "${staging_root}/tmp"
    export TMPDIR="${staging_root}/tmp"
}

# An isolated copy of the repository, parked at the plan's base commit.
clone_isolated_base() {
    test -n "${PLAN_BASE_SHA:-}" \
        || fail "PLAN_BASE_SHA must name the plan's base commit."
    git cat-file -e "${PLAN_BASE_SHA}^{commit}" \
        || fail "PLAN_BASE_SHA does not name a commit: ${PLAN_BASE_SHA}"
    git clone --no-hardlinks --quiet -- "${repository_root}" "${clone_root}" \
        || fail "the isolated clone could not be created."
    clone_branch="$(git -C "${clone_root}" symbolic-ref --quiet --short HEAD)" \
        || fail "the isolated clone has no branch to track."
    git -C "${clone_root}" checkout --quiet --detach "${PLAN_BASE_SHA}" \
        || fail "the isolated clone could not check out ${PLAN_BASE_SHA}."
}

# Replay the caller's whole working tree onto that base.
#
# `--binary` carries every tracked addition, edit, and deletion; the untracked
# copy carries what Git has not been told about yet. Together they are the tree
# finalization will publish, which is the only tree worth packaging.
overlay_working_tree() {
    local patch="${staging_root}/overlay.patch"
    git -C "${repository_root}" diff --binary "${PLAN_BASE_SHA}" > "${patch}" \
        || fail "the working-tree overlay could not be computed."
    if [ -s "${patch}" ]; then
        git -C "${clone_root}" apply --binary --whitespace=nowarn -- "${patch}" \
            || fail "the working-tree overlay could not be applied."
    fi
    copy_untracked_files
}

# Every untracked, unignored file, copied into the isolated tree.
#
# The listing is captured before anything reads it. Feeding the reader from a
# process substitution puts Git in a subshell whose exit status nothing observes,
# so a Git that died after emitting one path would leave one path, copy it, and
# report a proof over a tree it never assembled. An empty listing is an answer
# and not a failure: a repository may hold no untracked file at all.
copy_untracked_files() {
    local listing="${staging_root}/untracked.list"
    local relative
    git -C "${repository_root}" ls-files --others --exclude-standard -z > "${listing}" \
        || fail "the untracked files of ${repository_root} could not be listed."
    while IFS= read -r -d '' relative; do
        mkdir -p -- "${clone_root}/$(dirname -- "${relative}")" \
            || fail "the isolated directory for ${relative} could not be created."
        cp -p -- "${repository_root}/${relative}" "${clone_root}/${relative}" \
            || fail "the untracked file ${relative} could not be copied."
    done < "${listing}"
}

# One commit in the isolated clone, with a command-scoped identity.
#
# `-c` scopes the author and the committer to this one invocation, so the proof
# neither reads nor writes the operator's Git identity.
isolated_commit() {
    git -C "${clone_root}" \
        -c "user.name=${PROOF_IDENTITY_NAME}" \
        -c "user.email=${PROOF_IDENTITY_EMAIL}" \
        -c commit.gpgsign=false \
        commit --quiet --no-verify -m "$1" \
        || fail "the isolated commit failed: $1"
}

# The release as finalization will present it: one breaking commit on top of
# the plan's base, holding the complete final tree.
#
# The base is checked out detached so nothing can be mistaken for the clone's
# own history, and the staged commit is then moved onto a tracking branch:
# release-plz resolves `@{upstream}` to locate the project and refuses a
# repository whose HEAD points at no branch.
stage_isolated_source() {
    clone_isolated_base
    overlay_working_tree
    git -C "${clone_root}" add --all \
        || fail "the overlaid tree could not be staged."
    if git -C "${clone_root}" diff --cached --quiet; then
        fail "the working tree matches ${PLAN_BASE_SHA}; there is no release to prove."
    fi
    isolated_commit "${PROOF_COMMIT_SUBJECT}"
    git -C "${clone_root}" checkout --quiet -B "${PROOF_BRANCH_NAME}" \
        || fail "the staged release could not be moved onto a branch."
    git -C "${clone_root}" branch --quiet \
        --set-upstream-to="origin/${clone_branch}" "${PROOF_BRANCH_NAME}" \
        || fail "the staged branch could not track origin/${clone_branch}."
}

# Whether one tool binary exists and reports the version this proof pinned it
# to. A question rather than a refusal, because the warm probe below asks it of
# binaries that are allowed to be absent.
tool_reports_version() {
    local binary="$1"
    local expected="$2"
    shift 2
    test -x "${binary}" || return 1
    local reported
    reported="$("${binary}" "$@" 2> /dev/null)" || return 1
    case "${reported}" in
        *"${expected}"*) ;;
        *) return 1 ;;
    esac
}

# One installed tool is the pinned version, or this proof describes something
# else.
assert_tool_version() {
    local binary="$1"
    local expected="$2"
    shift 2
    tool_reports_version "${binary}" "${expected}" "$@" \
        || fail "${binary} reports [$("${binary}" "$@" 2>&1 || true)] rather than ${expected}."
}

# The semantic checker `release-plz update` consults to decide whether this
# tree's API change forces a major version.
#
# Already-installed is answered before installing, not by Cargo's own
# already-installed message: the question the proof needs answered is whether
# the binary in that root is the version the pinned revision builds, and only
# the binary can say.
install_semver_checks() {
    if tool_reports_version "${tool_root}/bin/cargo-semver-checks" \
        "${SEMVER_CHECKS_VERSION}" semver-checks --version; then
        return 0
    fi
    run_classified install-semver-checks cargo install \
        --git https://github.com/obi1kenobi/cargo-semver-checks \
        --rev "${SEMVER_CHECKS_REVISION}" --locked \
        --root "${tool_root}" cargo-semver-checks
    assert_tool_version "${tool_root}/bin/cargo-semver-checks" \
        "${SEMVER_CHECKS_VERSION}" semver-checks --version
}

# The tool that stages every version, requirement, changelog, and lockfile.
install_release_plz() {
    if tool_reports_version "${tool_root}/bin/release-plz" \
        "${RELEASE_PLZ_VERSION}" --version; then
        return 0
    fi
    run_classified install-release-plz cargo install \
        --git https://github.com/release-plz/release-plz \
        --rev "${RELEASE_PLZ_REVISION}" --locked \
        --root "${tool_root}" release-plz
    assert_tool_version "${tool_root}/bin/release-plz" \
        "${RELEASE_PLZ_VERSION}" --version
}

# Both pinned tools, in the order the release proof needs them.
#
# cargo-semver-checks first, because a release-plz that could not find it would
# stage a version the registry would reject, and the proof would compile the
# wrong release. A warm root is skipped whole: the state that decided it is the
# same probe either installation would have to satisfy.
install_pinned_tools() {
    case "${warm_state}" in
        warm) return 0 ;;
        *) ;;
    esac
    install_semver_checks
    install_release_plz
}

# Let release-plz stage the release, then commit what it wrote.
#
# The versions, requirements, changelogs, and lockfile are its output and never
# this script's: a proof that computed a version would be checking its own
# arithmetic rather than the release. The second commit exists because
# `cargo package --locked` refuses a dirty tree, and the staged tree is exactly
# what has to be packaged.
run_release_update() {
    cd -- "${clone_root}"
    run_classified release-update env "PATH=${tool_root}/bin:${PATH}" \
        "${tool_root}/bin/release-plz" update
    cd -- "${repository_root}"
    git -C "${clone_root}" add --all \
        || fail "the release-plz update could not be staged."
    if git -C "${clone_root}" diff --cached --quiet; then
        fail "release-plz staged no version, requirement, or changelog change."
    fi
    isolated_commit "${RELEASE_STAGING_SUBJECT}"
}

# What release-plz decided, read once and consulted everywhere.
read_staged_metadata() {
    capture_classified staged-metadata "${staged_metadata}" \
        cargo metadata --no-deps --format-version 1 \
        --manifest-path "${clone_root}/Cargo.toml"
    read_release_versions
}

# The version release-plz staged for every released package, left in
# ${release_versions} index-parallel with ${release_order}.
#
# One pass over the document rather than one per lookup. The four sites that
# need a version ask for eight each, and a reader spawned thirty-two times to
# re-run the same assertion over the same file states that assertion no better
# than a reader spawned once.
read_release_versions() {
    local listing version
    listing="$(jq -er --argjson names "${release_order_json}" \
        '. as $metadata
         | $names[] as $name
         | [$metadata.packages[] | select(.name == $name) | .version]
         | if length == 1 then .[0]
           else error("release-plz staged no single version for " + $name) end' \
        "${staged_metadata}")" \
        || fail "release-plz staged no single version for every released package."
    release_versions=()
    while IFS= read -r version; do
        test -n "${version}" || continue
        release_versions+=("${version}")
    done <<< "${listing}"
    test "${#release_versions[@]}" -eq "${RELEASE_PACKAGE_COUNT}" \
        || fail "the staged metadata carries ${#release_versions[@]} versions rather than ${RELEASE_PACKAGE_COUNT}."
}

# The version release-plz staged for one package, left in ${staged_version}.
read_staged_version() {
    local wanted="$1" index
    for index in "${!release_order[@]}"; do
        if [ "${release_order[index]}" = "${wanted}" ]; then
            staged_version="${release_versions[index]}"
            return 0
        fi
    done
    fail "the release order does not name ${wanted}."
}

# Clear the one archive path this run is about to write, and nothing else.
#
# Absence before the invocation is what makes the archive afterwards this
# run's. Deleting the whole package directory would work too, and would throw
# away every unrelated archive the caller's target root holds.
remove_prior_archive() {
    local archive="$1"
    if [ -L "${archive}" ]; then
        fail "the expected archive path is a symlink: ${archive}"
    fi
    if [ -e "${archive}" ]; then
        test -f "${archive}" || fail "the expected archive path is not a regular file: ${archive}"
        rm -f -- "${archive}" || fail "the prior archive could not be removed: ${archive}"
    fi
}

# One packaged archive normalizes to exactly the package it claims to be.
assert_extracted_identity() {
    local name="$1"
    local version="$2"
    local reported
    reported="$(jq -r '[.packages[] | "\(.name) \(.version)"] | join(", ")' \
        "${staging_root}/capture/extracted-${name}.json")"
    test "${reported}" = "${name} ${version}" \
        || fail "the ${name} archive normalizes to [${reported}] rather than [${name} ${version}]."
}

# One string as a regular expression that matches exactly itself.
#
# A package name and a version become a pattern here, and a version is mostly
# separators: `.` matches any character, and `+` and its neighbours mean
# something too. Escaping every character that is not plainly a literal is what
# makes an anchored prefix test mean the prefix. `-F` would answer the escaping
# but takes the anchor away with it, and the anchor is half the claim.
regex_escaped() {
    local subject="$1" escaped="" index=0 character
    while [ "${index}" -lt "${#subject}" ]; do
        character="${subject:${index}:1}"
        case "${character}" in
            [A-Za-z0-9_/-]) ;;
            *) escaped="${escaped}\\" ;;
        esac
        escaped="${escaped}${character}"
        index=$((index + 1))
    done
    printf '%s' "${escaped}"
}

# Unpack one archive into the generated workspace and read what it holds.
#
# The listing is taken on its own, and its status is tar's alone. Read through a
# pipeline answered with `|| true`, an archive tar could not open and a matcher
# that never ran both produced the empty string the confinement test accepts — a
# proof that the archive holds nothing outside its package directory, from a run
# that never saw the archive.
#
# The matcher's own status is then split three ways. Inverted, 0 means an entry
# outside the package directory, 1 means every entry is inside it, and anything
# else is a reader that failed — which is an unavailable machine and not a clean
# archive.
extract_archive() {
    local name="$1"
    local version="$2"
    local archive="${archive_root}/${name}-${version}.crate"
    local extracted="${workspace_root}/${name}-${version}"
    local listing stray read_status=0
    listing="$(tar -tzf "${archive}")" \
        || fail "the ${name} archive could not be listed."
    # A here-string carries a trailing newline, so an empty listing reaches the
    # matcher as one empty line and is refused as a stray entry with nothing to
    # name. Refuse it here, where it can be named for what it is.
    test -n "${listing}" \
        || fail "the ${name} archive lists no entry at all."
    # The prefix is escaped before it becomes a pattern. Spliced in raw, the
    # version's `.` separators matched any character, so the inverted test was
    # looser than the sentence above it claims.
    rg_status_over "${listing}" -N -v -e "^$(regex_escaped "${name}-${version}/")" \
        || read_status=$?
    stray="${RG_OUTPUT}"
    case "${read_status}" in
        0) fail "the ${name} archive holds entries outside ${name}-${version}/: ${stray}" ;;
        1) ;;
        *) unavailable "the ${name} archive listing could not be read for stray entries." ;;
    esac
    tar -xzf "${archive}" -C "${workspace_root}" \
        || fail "the ${name} archive could not be extracted."
    test -d "${extracted}" \
        || fail "the ${name} archive holds no ${name}-${version}/ tree."
    capture_classified "extracted-${name}" \
        "${staging_root}/capture/extracted-${name}.json" \
        cargo metadata --no-deps --format-version 1 \
        --manifest-path "${extracted}/Cargo.toml"
    assert_extracted_identity "${name}" "${version}"
}

# Package all eight members, then unpack every archive this run produced.
#
# One workspace-wide invocation rather than eight per-member ones, because a
# member is packaged against the versions release-plz just staged and those
# versions are not on crates.io yet. Packaged alone, `pedant-core` would ask the
# registry for a `pedant-types` that will not exist until publication; packaged
# together, Cargo resolves each sibling from the workspace it is packaging.
#
# Every expected archive path is cleared before Cargo runs and required after
# it, so each archive is provably this run's rather than an earlier one's.
package_archives() {
    local name archive
    for name in "${release_order[@]}"; do
        read_staged_version "${name}"
        archive="${target_root}/package/${name}-${staged_version}.crate"
        remove_prior_archive "${archive}"
    done
    run_classified package-workspace cargo package --manifest-path "${clone_root}/Cargo.toml" \
        --workspace --locked --no-verify
    for name in "${release_order[@]}"; do
        read_staged_version "${name}"
        archive="${target_root}/package/${name}-${staged_version}.crate"
        test -f "${archive}" \
            || fail "cargo package produced no archive at ${archive}."
        cp -- "${archive}" "${archive_root}/${name}-${staged_version}.crate" \
            || fail "the ${name} archive could not be copied into the staging root."
        extract_archive "${name}" "${staged_version}"
    done
}

# Which packages the packaged manifests actually depend on.
#
# Read from the archives rather than from this repository, because the archives
# are what a consumer receives: a path dependency that survived packaging, or a
# requirement Cargo rewrote, shows up here and nowhere else.
derive_first_party_edges() {
    local name
    : > "${staging_root}/archive-edges.json"
    for name in "${release_order[@]}"; do
        jq -c --argjson names "${release_order_json}" \
            '.packages[] as $package
             | $package.dependencies[]
             | select(.name as $candidate | ($names | index($candidate)) != null)
             | {consumer: $package.name, dependency: .name, req: .req}' \
            "${staging_root}/capture/extracted-${name}.json" \
            >> "${staging_root}/archive-edges.json"
    done
    inbound_packages="$(jq -r -s --argjson names "${release_order_json}" \
        '[.[].dependency] as $inbound
         | $names
         | map(select(. as $name | ($inbound | index($name)) != null))
         | .[]' \
        "${staging_root}/archive-edges.json")"
}

# The generated workspace: eight archive members, and a patch entry for exactly
# the packages something in that workspace depends on.
write_archive_manifest() {
    local name
    {
        printf '[workspace]\n'
        printf 'resolver = "3"\n'
        printf 'members = [\n'
        for name in "${release_order[@]}"; do
            read_staged_version "${name}"
            printf '    "%s-%s",\n' "${name}" "${staged_version}"
        done
        printf ']\n\n'
        printf '[patch.crates-io]\n'
        if [ -n "${inbound_packages}" ]; then
            while IFS= read -r name; do
                read_staged_version "${name}"
                printf '%s = { path = "%s-%s" }\n' "${name}" "${name}" "${staged_version}"
            done <<< "${inbound_packages}"
        fi
    } > "${workspace_root}/Cargo.toml"
}

# Build the workspace the archives are compiled in.
generate_archive_workspace() {
    derive_first_party_edges
    write_archive_manifest
}

# The patch set is the inbound edge set — no wider, no narrower.
#
# A wider one hides a package that no longer needs patching; a narrower one
# lets a first-party edge fall through to crates.io, which is the exact failure
# this proof exists to catch.
#
# The required set is read back out of the metadata Cargo produced for the
# generated workspace, not out of the variable that wrote the manifest. A check
# that compared this manifest against its own input would agree with itself
# however wrong both of them were.
assert_patch_set_is_exact() {
    local required written read_status=0
    required="$(jq -r --argjson names "${release_order_json}" \
        'def first_party: . as $candidate | ($names | index($candidate)) != null;
         [.packages[]
          | select(.name | first_party)
          | .dependencies[]
          | select(.name | first_party)
          | .name] as $inbound
         | $names
         | map(select(. as $name | ($inbound | index($name)) != null))
         | .[]' \
        "${archive_metadata}")" \
        || fail "the packaged metadata could not be read for its inbound edges."
    # Both sides being empty satisfies the comparison below, and a check that
    # passes having constrained nothing is the one thing "no wider, no narrower"
    # must not mean. This release is eight packages that depend on each other, so
    # an archive set stating no first-party edge is a set nothing patched and
    # nothing would have to.
    test -n "${required}" \
        || fail "the packaged metadata states no first-party edge, so an empty patch table would satisfy this check having constrained nothing."
    # 1 is the classified "no match", which is a patch table this check may
    # still judge. 2 is a reader that failed, and an empty answer from a broken
    # reader would agree with an empty required set.
    #
    # `${1}` is ripgrep's own capture-group reference, so it stays unexpanded.
    # shellcheck disable=SC2016
    rg_status -N -o -r '${1}' '^([a-zA-Z0-9_-]+) = \{ path = ' \
        -- "${workspace_root}/Cargo.toml" || read_status=$?
    written="${RG_OUTPUT}"
    case "${read_status}" in
        0 | 1) ;;
        *) unavailable "the generated workspace manifest could not be read for its patch table." ;;
    esac
    test "${written}" = "${required}" \
        || fail "the generated workspace patches [${written}] rather than the inbound edge set [${required}]."
}

# A patch Cargo never consulted means the requirement it was meant to redirect
# does not exist, so the graph below proves nothing about it.
#
# The search runs outside the `if` and its status is kept, for the reason
# `assert_patch_set_is_exact` keeps ripgrep's: inside the condition, "the patch
# table is clean" and "the matcher never ran" are one false branch, and the
# second of those is a transcript nobody read.
assert_no_unused_patch() {
    local read_status=0
    rg_status -N -q "was not used in the crate graph" -- "${archive_metadata}.err" || read_status=$?
    case "${read_status}" in
        0) fail "the generated workspace holds a patch that was not used in the crate graph." ;;
        1) ;;
        *) unavailable "the packaged metadata transcript could not be read for unused patches." ;;
    esac
}

# Every way the packaged graph can be wrong, refused before anything compiles.
assert_packaged_graph_shape() {
    local violations
    violations="$(jq -r \
        --argjson names "${release_order_json}" \
        --arg workspace "${workspace_root}" \
        --arg origin "${repository_root}" \
        --slurpfile staged "${staged_metadata}" \
        'def first_party: . as $candidate | ($names | index($candidate)) != null;
         ($staged[0].packages) as $stagedpackages
         | (.packages | map(select(.name | first_party))) as $members
         | ($members | map(.id)) as $ids
         | [
             (if ($members | length) != ($names | length)
              then "the archive workspace holds \($members | length) first-party members rather than \($names | length)"
              else empty end),
             (.packages[]
              | select(.manifest_path | startswith($origin + "/"))
              | "\(.name) resolves through the original checkout at \(.manifest_path)"),
             ($members[]
              | select((.manifest_path | startswith($workspace + "/")) | not)
              | "\(.name) resolves outside the archive workspace at \(.manifest_path)"),
             ($members[]
              | select(.source != null)
              | "\(.name) resolves through the registry rather than its archive"),
             ($members[] as $member
              | (($stagedpackages[] | select(.name == $member.name) | .version) // "absent") as $expected
              | select($member.version != $expected)
              | "\($member.name) carries version \($member.version) rather than the staged \($expected)"),
             ($members[] as $member
              | $member.dependencies[]
              | select(.name | first_party)
              | . as $edge
              | (($stagedpackages[]
                  | select(.name == $member.name)
                  | .dependencies[]
                  | select(.name == $edge.name)
                  | .req) // "absent") as $expected
              | select($edge.req != $expected)
              | "\($member.name) states requirement \($edge.req) for \($edge.name) rather than the staged \($expected)"),
             (.resolve.nodes[] as $node
              | select(($node.id as $id | $ids | index($id)) != null)
              | ($members[] | select(.id == $node.id) | .name) as $consumer
              | $node.deps[]
              | select(.name | first_party)
              | select((.pkg as $resolved | $ids | index($resolved)) == null)
              | "\($consumer) resolves its \(.name) edge through the registry rather than the archive member")
           ]
         | .[]' \
        "${archive_metadata}")" \
        || fail "the packaged metadata could not be read."
    test -z "${violations}" \
        || fail "the packaged graph is not releaseable:"$'\n'"${violations}"
}

# Lock, read, refuse, and only then compile.
verify_packaged_graph() {
    run_classified archive-lockfile cargo generate-lockfile \
        --manifest-path "${workspace_root}/Cargo.toml"
    capture_classified archive-metadata "${archive_metadata}" \
        cargo metadata --format-version 1 --locked \
        --manifest-path "${workspace_root}/Cargo.toml"
    assert_no_unused_patch
    assert_patch_set_is_exact
    assert_packaged_graph_shape
    run_classified archive-check cargo check --workspace --all-features --locked \
        --manifest-path "${workspace_root}/Cargo.toml"
}

# The mixed-language repository the packaged binary is asked about.
#
# One file per language this product admits, plus the three project authorities
# that make two of them resolvable. The whole table is the point: this build
# links six grammars and both graph producers, and a fixture of one language
# would let a packaged binary that lost five of them answer the journey exactly
# as a complete one does.
#
# It is written under the staging root rather than anywhere in the caller's
# tree, so what the journey proves is a binary answering about a repository it
# was pointed at rather than about the workspace it was built from.
write_journey_repository() {
    mkdir -p -- "${journey_root}/crate-a/src" "${journey_root}/scripts" "${journey_root}/web" \
        || fail "the journey repository could not be created."
    printf '[workspace]\nmembers = ["crate-a"]\nresolver = "3"\n' \
        > "${journey_root}/Cargo.toml" || fail "the journey workspace manifest could not be written."
    printf '[package]\nname = "crate-a"\nversion = "0.1.0"\nedition = "2024"\n' \
        > "${journey_root}/crate-a/Cargo.toml" || fail "the journey package manifest could not be written."
    printf 'pub fn make() -> u8 {\n    1\n}\n' \
        > "${journey_root}/crate-a/src/lib.rs" || fail "the journey library could not be written."
    printf 'fn main() {\n    let value = crate_a::make();\n    assert_eq!(value, 1);\n}\n' \
        > "${journey_root}/crate-a/src/main.rs" || fail "the journey binary could not be written."
    printf 'module example.com/main\n\ngo 1.22\n' \
        > "${journey_root}/go.mod" || fail "the journey module manifest could not be written."
    printf 'package main\n\ntype Node struct{ Name string }\n\nfunc New(name string) *Node { return &Node{Name: name} }\n\nfunc main() { _ = New("root") }\n' \
        > "${journey_root}/main.go" || fail "the journey Go source could not be written."
    printf 'def build():\n    return 1\n' \
        > "${journey_root}/scripts/tool.py" || fail "the journey Python source could not be written."
    printf 'run_it() {\n    printf "hi\\n"\n}\n' \
        > "${journey_root}/scripts/tool.sh" || fail "the journey Bash source could not be written."
    printf 'export function widget() {\n  return 1;\n}\n' \
        > "${journey_root}/web/app.js" || fail "the journey JavaScript source could not be written."
    printf 'export function typed(): number {\n  return 1;\n}\n' \
        > "${journey_root}/web/app.ts" || fail "the journey TypeScript source could not be written."
}

# Install the navigation product the way a consumer receives it.
#
# The source is the extracted archive member, inside the generated workspace, so
# the binary this journey runs is built from the bytes crates.io would serve and
# resolves every first-party edge through the patch table the graph checks
# already accepted. `--locked` holds it to that resolution, `--debug` keeps the
# build to what a journey needs rather than what a release needs, and the
# profile is stated rather than inherited so the cost does not depend on the
# caller's environment.
#
# The version assertion is what makes every answer below this run's. An
# operator's own `pedant-snippet` earlier on `PATH` would answer the whole
# journey plausibly, and only its version says which binary spoke.
install_packaged_snippet() {
    read_staged_version "${NAVIGATION_PACKAGE}"
    run_classified journey-install env "CARGO_PROFILE_DEV_DEBUG=0" cargo install \
        --path "${workspace_root}/${NAVIGATION_PACKAGE}-${staged_version}" \
        --root "${journey_install_root}" --debug --locked
    assert_tool_version "${journey_binary}" "${staged_version}" --version
}

# Ask the installed binary one question, and require it to be about the one
# index this journey is over.
#
# The first question states the revision and every later one has to agree with
# it. Nine processes indexing one tree either state one identity or that
# identity is not the repository's, and no single answer can tell the two apart.
ask_journey() {
    local label="$1"
    shift
    local answer="${staging_root}/capture/journey-${label}.json"
    capture_classified "journey-${label}" "${answer}" \
        "${journey_binary}" "$@" --root "${journey_root}" --format json
    journey_answers=$((journey_answers + 1))
    local stated
    stated="$(journey_field "${label}" '.index_revision')"
    case "${journey_revision}" in
        "") journey_revision="${stated}" ;;
        "${stated}") ;;
        *) fail "the ${label} answer states index ${stated} rather than ${journey_revision}." ;;
    esac
}

# One field of one document the journey collected, which has to be there.
#
# Rendered rather than read raw, because half these fields are numbers and one
# is a boolean, and `jq -e` reports a false or a zero as a failed read. Absence
# is refused here instead: a filter that selected nothing prints nothing, a
# field that is not there prints `null`, and a journey that compared either as
# text would accept a binary answering nothing at all.
#
# One owner, two callers — the command line's answers and the server's session —
# because a second copy of this rule is a second answer to what "the binary said
# nothing" means.
document_field() {
    local document="$1"
    local filter="$2"
    local subject="$3"
    local reported
    reported="$(jq -r "${filter} | tostring" "${document}")" \
        || fail "${subject} could not be read for [${filter}]."
    case "${reported}" in
        "" | null) fail "${subject} states no [${filter}]." ;;
        *) ;;
    esac
    printf '%s\n' "${reported}"
}

# One field of one answer the command line printed.
journey_field() {
    local label="$1"
    document_field "${staging_root}/capture/journey-${label}.json" "$2" "the ${label} answer"
}

# One field of one answer is what it has to be.
assert_journey_field() {
    local label="$1"
    local filter="$2"
    local expected="$3"
    local reported
    reported="$(journey_field "${label}" "${filter}")"
    test "${reported}" = "${expected}" \
        || fail "the ${label} answer states [${reported}] rather than [${expected}]."
}

# Every question this product publishes, asked of the packaged binary.
#
# One field per answer and never only the exit status: a binary that printed an
# empty envelope for every question would exit zero nine times. The two graph
# questions are here for the same reason the six languages are — a feature
# closure that arrived at the registry without its graph producers would answer
# the first five and refuse these.
assert_packaged_cli_journey() {
    local make_id main_id project_id
    ask_journey projects list-projects
    assert_journey_field projects '[.result[].language] | sort | unique | join(",")' "go,rust"
    project_id="$(journey_field projects \
        '[.result[] | select(.unit == "crate-a::bin::crate-a")][0].handle.id')"

    ask_journey search search make --mode exact --language rust
    assert_journey_field search '.result | length' 1
    make_id="$(journey_field search '.result[0].handle.id')"

    ask_journey entry search main --mode exact --language rust
    assert_journey_field entry '.result | length' 1
    main_id="$(journey_field entry '.result[0].handle.id')"

    ask_journey outline outline crate-a/src/lib.rs
    assert_journey_field outline '.result.structures | length' 1

    ask_journey read read "${journey_revision}" "${make_id}"
    assert_journey_field read '.result.structure.qualified_name' "crate-a/src/lib.rs::make"

    ask_journey at at main.go 5
    assert_journey_field at '.result.structure.qualified_name' "main.go::New"

    ask_journey relations relations "${journey_revision}" "${main_id}" \
        --direction outgoing --max-depth 2 --edge-kind call --certainty resolved
    assert_journey_field relations '[.result[].edges[].kind] | join(",")' call

    ask_journey path path "${journey_revision}" "${main_id}" \
        "${journey_revision}" "${make_id}" --edge-kind call --certainty resolved
    assert_journey_field path '.result.selected.edges | length' 1

    ask_journey analysis graph "${journey_revision}" "${project_id}" components \
        --edge-kind call --certainty resolved
    assert_journey_field analysis '.result.mode' components
}

# The packaged server, fed one session on standard input.
#
# A function rather than a command line, because the transport reads its
# requests from a file and the one capture owner takes a command rather than a
# redirection. Standard input closing is the client disconnecting, which is what
# ends a stdio session.
serve_journey_mcp() {
    "${journey_binary}" mcp --root "${journey_root}" < "${staging_root}/capture/journey-requests.jsonl"
}

# One field of the server's session, read out of the responses it wrote.
mcp_field() {
    document_field "${staging_root}/capture/journey-mcp.jsonl" "$1" "the packaged MCP session"
}

# The same session, over the same repository, through the other transport.
#
# The listing is required whole rather than searched: a build that reached the
# registry without its graph producers serves five of these eight, and every
# membership check the five satisfy would pass. Parity is the claim the other
# readings cannot make — two transports that each answer plausibly and
# differently are two products, and the bytes are where that shows.
assert_packaged_mcp_journey() {
    local served cli
    cat > "${staging_root}/capture/journey-requests.jsonl" <<'REQUESTS' || fail "the packaged MCP session could not be written."
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"packaged-workspace-proof","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}
REQUESTS
    capture_classified journey-mcp "${staging_root}/capture/journey-mcp.jsonl" serve_journey_mcp
    journey_answers=$((journey_answers + 1))

    served="$(mcp_field 'select(.id == 2) | [.result.tools[].name] | join(",")')"
    test "${served}" = "list_projects,search_symbols,outline_file,read_structure,structure_at,query_relations,find_path,analyze_graph" \
        || fail "the packaged server lists [${served}] rather than this product's eight tools."
    served="$(mcp_field 'select(.id == 2) | [.result.tools[] | select(.annotations.readOnlyHint == true and .annotations.idempotentHint == true and .annotations.openWorldHint == false)] | length')"
    test "${served}" = "${NAVIGATION_TOOL_COUNT}" \
        || fail "the packaged server annotates ${served} tools read-only, idempotent, and closed-world."
    served="$(mcp_field 'select(.id == 3) | .result.isError')"
    test "${served}" = "false" \
        || fail "the packaged server answered its own listed tool with an error."

    served="$(mcp_field 'select(.id == 3) | .result.content[0].text' | jq -S -c .)" \
        || fail "the packaged server's answer is not one JSON document."
    cli="$(jq -S -c . "${staging_root}/capture/journey-projects.json")" \
        || fail "the packaged CLI answer is not one JSON document."
    test "${served}" = "${cli}" \
        || fail "the two transports answer one question differently:"$'\n'"${served}"$'\n'"${cli}"
}

# No answer this journey collected names the tree the proof was started from.
#
# The binary, the repository, and the install root are all this run's own, so a
# path from the caller's checkout in any of them means something resolved
# through the workspace rather than through the archives — which is the failure
# the whole proof exists to catch, arriving one stage later than the graph
# checks look.
#
# A pure forbid needs both halves. The search's status is split rather than
# discarded — 0 is the leak, 1 is a clean capture set, and anything else is a
# matcher that never ran — because `|| true` gave a broken matcher, an unreadable
# capture directory, and a glob that selected nothing the same empty answer a
# clean run gives.
#
# The other half is the range. Ripgrep reports "no file matched" and "no file was
# searched" identically, so the captures are counted here and held to the number
# of answers the two journeys collected. Every answer leaves a document and a
# diagnostic stream, and the session is fed one request script, so the count is
# comfortably above that floor; what the floor rejects is a directory the search
# never opened.
assert_no_checkout_leakage() {
    local leaked capture read_status=0 searched=0
    for capture in "${staging_root}/capture"/journey-*; do
        test -e "${capture}" || continue
        searched=$((searched + 1))
    done
    test "${searched}" -ge "${journey_answers}" \
        || fail "the leakage search ranges over ${searched} captures for ${journey_answers} collected journey answers."
    rg_status -N -l -F -g 'journey-*' -e "${repository_root}/" -- "${staging_root}/capture" \
        || read_status=$?
    leaked="${RG_OUTPUT}"
    case "${read_status}" in
        0) fail "a packaged journey answer names the original checkout: ${leaked}" ;;
        1) ;;
        *) unavailable "the packaged journey answers could not be searched for checkout paths." ;;
    esac
}

# Install the packaged navigation product and complete both transports over one
# repository of this run's own.
run_packaged_snippet_journey() {
    write_journey_repository
    install_packaged_snippet
    assert_packaged_cli_journey
    assert_packaged_mcp_journey
    assert_no_checkout_leakage
}

# One directory's size, in kibibytes.
directory_kib() {
    local reported
    reported="$(du -sk -- "$1" | rg -N -o '^[0-9]+')" \
        || unavailable "the size of $1 could not be measured."
    printf '%s\n' "${reported}"
}

# The largest this run's own staging ever got.
measure_owned_temp() {
    local current
    current="$(directory_kib "${staging_root}")"
    if [ "${current}" -gt "${temp_peak_kib}" ]; then
        temp_peak_kib="${current}"
    fi
}

# The wall clock, read through the tool rather than through the shell.
#
# An external clock is a clock this script does not control, which is what lets
# a lifecycle row hand it one that jumps. The runtime refusal below is minutes
# away from anything a test can afford to wait for, and a refusal nobody can
# reach is a refusal nobody has checked.
now_seconds() {
    date +%s
}

# Whether this target root already holds the pinned tool builds.
#
# Asked of the binaries, not of a marker file. A file saying the tools are here
# is a claim; a pruned target, or one copied out of another tree, keeps the
# claim and loses the tools, and the run that believed it would be held to the
# warm budget for a quarter hour of work it still has to do. Both binaries have
# to be in the revision-named root and both have to report the version that
# revision builds. Anything else is cold, which is the answer that cannot fail
# wrongly.
read_warm_state() {
    tool_reports_version "${tool_root}/bin/cargo-semver-checks" \
        "${SEMVER_CHECKS_VERSION}" semver-checks --version || return 0
    tool_reports_version "${tool_root}/bin/release-plz" \
        "${RELEASE_PLZ_VERSION}" --version || return 0
    warm_state="warm"
}

# Start the clock and the target reading this stage is measured against.
begin_measurement() {
    start_seconds="$(now_seconds)"
    target_start_kib="$(directory_kib "${target_root}")"
}

# What this stage cost, and whether that is more than it was allowed to.
#
# Reported before it is judged, because an operator reading a budget refusal
# needs the number that caused it.
measure_budget() {
    local stage="$1"
    local runtime_budget="$2"
    local target_budget="$3"
    local elapsed target_end_kib target_growth_kib
    elapsed="$(($(now_seconds) - start_seconds))"
    target_end_kib="$(directory_kib "${target_root}")"
    target_growth_kib="$((target_end_kib - target_start_kib))"
    if [ "${target_growth_kib}" -lt 0 ]; then
        target_growth_kib=0
    fi
    printf 'packaged workspace proof: stage=%s state=%s elapsed=%ss target_growth=%sKiB owned_temp_peak=%sKiB\n' \
        "${stage}" "${warm_state}" "${elapsed}" "${target_growth_kib}" "${temp_peak_kib}"
    test "${elapsed}" -le "${runtime_budget}" \
        || fail "the ${stage} stage took ${elapsed}s, over its ${runtime_budget}s budget."
    test "${target_growth_kib}" -le "${target_budget}" \
        || fail "the ${stage} stage grew the target root by ${target_growth_kib}KiB, over its ${target_budget}KiB budget."
    test "${temp_peak_kib}" -le "${OWNED_TEMP_BUDGET_KIB}" \
        || fail "the ${stage} stage held ${temp_peak_kib}KiB of staging, over its ${OWNED_TEMP_BUDGET_KIB}KiB budget."
}

# Which pair of numbers the release proof is held to.
measure_proof_budget() {
    case "${warm_state}" in
        warm)
            measure_budget verify \
                "${WARM_RUNTIME_BUDGET_SECONDS}" "${WARM_TARGET_BUDGET_KIB}"
            ;;
        *)
            measure_budget verify \
                "${COLD_RUNTIME_BUDGET_SECONDS}" "${COLD_TARGET_BUDGET_KIB}"
            ;;
    esac
}

# Everything both stages do before either does its own work: prove the machine,
# the target root and the release order, take the staging root this run owns,
# read the warm state, and start the clock.
#
# One function rather than a prologue each entry point repeats. A stage that
# omitted the warm reading would be judged against the other stage's pair of
# numbers and report a cost nobody measured, and the omission would look like
# four lines that were nearly the same as four other lines.
begin_stage() {
    preflight "$1"
    create_staging_root
    read_warm_state
    begin_measurement
}

# Build one pinned tool into the caller's target and stop.
#
# One tool per invocation because one tool is what a verification slice holds.
# Measured cold on an empty target: cargo-semver-checks 836s, release-plz 593s,
# 1,429s together against a 1,200-second slice. Split, each fits with room; the
# release proof that follows them measures the release rather than the
# toolchain.
#
# The installer arrives already chosen, because the entry point is where an
# unknown name has to be refused: a stage that decided the name here would first
# create a staging root, run both pinned binaries to read the warm state, and
# start the measurement for a request it was never going to accept.
run_tool_installation() {
    begin_stage "$1"
    "$2"
    measure_owned_temp
    measure_budget install \
        "${INSTALL_RUNTIME_BUDGET_SECONDS}" "${INSTALL_TARGET_BUDGET_KIB}"
}

# Stage the release, package all eight members, compile the archives, and run
# the product they ship.
run_packaged_workspace_proof() {
    begin_stage "$1"
    stage_isolated_source
    install_pinned_tools
    measure_owned_temp
    run_release_update
    read_staged_metadata
    package_archives
    measure_owned_temp
    generate_archive_workspace
    verify_packaged_graph
    run_packaged_snippet_journey
    measure_owned_temp
    measure_proof_budget
}

# The stage a caller asked for is its whole argument list, not its first word.
#
# Counting first is the point. A proof that dispatched on `$1` alone would read
# `--install-tools release-plz --and-skip-the-check` as the release-plz stage,
# build one tool, discard the rest of the sentence, and report success for a run
# nobody asked for; the caller would read that zero as an answer to the question
# it actually asked. The tool name is read in the same breath as the count, so
# the two accepted sentences are spelled out whole here: an unknown name refused
# further in would already have created a staging root and run both pinned
# binaries. Two exact lists after the required root select a tool stage, no
# selector selects the release proof, and everything else is refused before any
# state moves.
main() {
    case "$#" in
        0) fail "a repository-root argument is required." ;;
        *) ;;
    esac
    case "$#:${2:-}:${3:-}" in
        3:--install-tools:cargo-semver-checks) run_tool_installation "$1" install_semver_checks ;;
        3:--install-tools:release-plz) run_tool_installation "$1" install_release_plz ;;
        1::) run_packaged_workspace_proof "$1" ;;
        *)
            shift
            fail "unknown arguments [$*]; after its repository root this proof takes \
--install-tools cargo-semver-checks, --install-tools release-plz, or nothing."
            ;;
    esac
}

main "$@"
