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
# other under exactly those generated requirements.
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
# what the release proof itself costs. `--install-tools <tool>` builds one of
# them into a revision-named root inside the caller's target and stops; the
# release proof that follows asks those binaries their versions and is held to
# the warm budget they earn. Any stage run alone is still correct: a proof that
# finds no pinned build makes one and pays the cold budget for it.
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
PROOF_COMMIT_SUBJECT="feat!: implement symbol capability profiles"
RELEASE_STAGING_SUBJECT="chore: stage the release-plz update"
PROOF_IDENTITY_NAME="pedant packaged workspace proof"
PROOF_IDENTITY_EMAIL="packaged-workspace-proof@pedant.invalid"
PROOF_BRANCH_NAME="packaged-workspace-proof"
readonly PROOF_COMMIT_SUBJECT RELEASE_STAGING_SUBJECT
readonly PROOF_IDENTITY_NAME PROOF_IDENTITY_EMAIL PROOF_BRANCH_NAME

RELEASE_PACKAGE_COUNT=8
STAGING_PREFIX="pedant-packaged-workspace"
readonly RELEASE_PACKAGE_COUNT STAGING_PREFIX

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

REQUIRED_TOOLS="bash cargo date du find git jq mktemp rg rm tar"
readonly REQUIRED_TOOLS

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
# shellcheck source-path=SCRIPTDIR
# shellcheck source=cargo_infrastructure.sh
. "${script_dir}/cargo_infrastructure.sh"

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
inbound_packages=""
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
capture_classified() {
    local label="$1"
    local destination="$2"
    shift 2
    local status=0
    "$@" > "${destination}" 2> "${destination}.err" || status=$?
    cat -- "${destination}.err" >&2
    if [ -n "${PROOF_OUTPUT_DIR:-}" ] && [ -d "${PROOF_OUTPUT_DIR}" ]; then
        cp -- "${destination}.err" "${PROOF_OUTPUT_DIR}/${label}.log" 2> /dev/null || true
    fi
    local transcript
    transcript="$(cat -- "${destination}" "${destination}.err")"
    cargo_record "${status}" "${transcript}"
    local worst
    worst="$(cargo_worst)"
    test "${worst}" -eq 0 || exit "${worst}"
}

# Every tool this proof shells out to, proved present before it starts.
require_tools() {
    local tool
    for tool in ${REQUIRED_TOOLS}; do
        command -v "${tool}" > /dev/null 2>&1 \
            || unavailable "${tool} is required on PATH."
    done
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
# release-plz publishes in this order and nothing else may restate it, so the
# proof packages in it too: an archive built before its dependency's archive
# exists would resolve against the registry and prove the opposite of the
# claim.
read_release_order() {
    local name
    while IFS= read -r name; do
        release_order+=("${name}")
    done < <(rg -N -o -r '${1}' '^name = "([^"]+)"$' release-plz.toml)
    test "${#release_order[@]}" -eq "${RELEASE_PACKAGE_COUNT}" \
        || fail "release-plz.toml names ${#release_order[@]} packages rather than ${RELEASE_PACKAGE_COUNT}."
    release_order_json="$(printf '%s\n' "${release_order[@]}" \
        | jq -R -s -c 'split("\n") | map(select(length > 0))')"
    assert_release_order_matches_manifests
}

# Every named package has the manifest it claims, before anything is staged.
assert_release_order_matches_manifests() {
    local name manifest
    for name in "${release_order[@]}"; do
        manifest="${repository_root}/${name}/Cargo.toml"
        test -f "${manifest}" \
            || fail "the release order names ${name}, which has no manifest at ${manifest}."
        rg -N -q "^name = \"${name}\"\$" "${manifest}" \
            || fail "${manifest} does not declare package ${name}."
    done
}

# Prove the machine, the target root, and the release order before this proof
# changes any state at all.
preflight() {
    require_tools
    repository_root="$(git rev-parse --show-toplevel)" \
        || fail "the packaged-workspace proof must run inside a Git repository."
    cd -- "${repository_root}"
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
    git diff --binary "${PLAN_BASE_SHA}" > "${patch}" \
        || fail "the working-tree overlay could not be computed."
    if [ -s "${patch}" ]; then
        git -C "${clone_root}" apply --binary --whitespace=nowarn -- "${patch}" \
            || fail "the working-tree overlay could not be applied."
    fi
    copy_untracked_files
}

# Every untracked, unignored file, copied into the isolated tree.
copy_untracked_files() {
    local relative
    while IFS= read -r -d '' relative; do
        mkdir -p -- "${clone_root}/$(dirname -- "${relative}")"
        cp -p -- "${repository_root}/${relative}" "${clone_root}/${relative}" \
            || fail "the untracked file ${relative} could not be copied."
    done < <(git ls-files --others --exclude-standard -z)
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
}

# The version release-plz staged for one package.
staged_version() {
    jq -er --arg name "$1" \
        '[.packages[] | select(.name == $name) | .version]
         | if length == 1 then .[0]
           else error("release-plz staged no single version for " + $name) end' \
        "${staged_metadata}"
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

# Unpack one archive into the generated workspace and read what it holds.
extract_archive() {
    local name="$1"
    local version="$2"
    local archive="${archive_root}/${name}-${version}.crate"
    local extracted="${workspace_root}/${name}-${version}"
    local stray
    stray="$(tar -tzf "${archive}" | rg -N -v -e "^${name}-${version}/" || true)"
    test -z "${stray}" \
        || fail "the ${name} archive holds entries outside ${name}-${version}/: ${stray}"
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
    local name version archive
    for name in "${release_order[@]}"; do
        version="$(staged_version "${name}")"
        archive="${target_root}/package/${name}-${version}.crate"
        remove_prior_archive "${archive}"
    done
    run_classified package-workspace cargo package --manifest-path "${clone_root}/Cargo.toml" \
        --workspace --locked --no-verify
    for name in "${release_order[@]}"; do
        version="$(staged_version "${name}")"
        archive="${target_root}/package/${name}-${version}.crate"
        test -f "${archive}" \
            || fail "cargo package produced no archive at ${archive}."
        cp -- "${archive}" "${archive_root}/${name}-${version}.crate" \
            || fail "the ${name} archive could not be copied into the staging root."
        extract_archive "${name}" "${version}"
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
    local name version
    {
        printf '[workspace]\n'
        printf 'resolver = "3"\n'
        printf 'members = [\n'
        for name in "${release_order[@]}"; do
            version="$(staged_version "${name}")"
            printf '    "%s-%s",\n' "${name}" "${version}"
        done
        printf ']\n\n'
        printf '[patch.crates-io]\n'
        if [ -n "${inbound_packages}" ]; then
            while IFS= read -r name; do
                version="$(staged_version "${name}")"
                printf '%s = { path = "%s-%s" }\n' "${name}" "${name}" "${version}"
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
    local required written
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
    written="$(rg -N -o -r '${1}' '^([a-zA-Z0-9_-]+) = \{ path = ' \
        "${workspace_root}/Cargo.toml" || true)"
    test "${written}" = "${required}" \
        || fail "the generated workspace patches [${written}] rather than the inbound edge set [${required}]."
}

# A patch Cargo never consulted means the requirement it was meant to redirect
# does not exist, so the graph below proves nothing about it.
assert_no_unused_patch() {
    if rg -N -q "was not used in the crate graph" "${archive_metadata}.err"; then
        fail "the generated workspace holds a patch that was not used in the crate graph."
    fi
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
             (.resolve.nodes[]
              | select((.id as $node | $ids | index($node)) != null)
              | .deps[]
              | select(.name | first_party)
              | select((.pkg as $resolved | $ids | index($resolved)) == null)
              | "\(.name) resolves through the registry rather than its archive")
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
    preflight
    create_staging_root
    read_warm_state
    begin_measurement
    "$1"
    measure_owned_temp
    measure_budget install \
        "${INSTALL_RUNTIME_BUDGET_SECONDS}" "${INSTALL_TARGET_BUDGET_KIB}"
}

# Stage the release, package all eight members, and compile the archives.
run_packaged_workspace_proof() {
    preflight
    create_staging_root
    read_warm_state
    begin_measurement
    stage_isolated_source
    install_pinned_tools
    measure_owned_temp
    run_release_update
    read_staged_metadata
    package_archives
    measure_owned_temp
    generate_archive_workspace
    verify_packaged_graph
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
# binaries. Two exact lists select a tool stage, none selects the release proof,
# and everything else is refused before any state moves.
main() {
    case "$#:${1:-}:${2:-}" in
        2:--install-tools:cargo-semver-checks) run_tool_installation install_semver_checks ;;
        2:--install-tools:release-plz) run_tool_installation install_release_plz ;;
        0::) run_packaged_workspace_proof ;;
        *) fail "unknown arguments [$*]; this proof takes --install-tools \
cargo-semver-checks, --install-tools release-plz, or nothing." ;;
    esac
}

main "$@"
