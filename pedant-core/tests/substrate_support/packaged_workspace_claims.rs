//! Every table the tracked packaged-workspace release proof is compared
//! against.
//!
//! The tables sit beside their readings rather than inside them, for the
//! source-file budget alone — the way `fingerprint_claims` sits beside
//! `fingerprint`. [`crate::packaged_workspace`] reads the structure they
//! describe and [`crate::packaged_workspace_budget`] reads the cost, and both
//! spell the script the same way because they spell it once, here.

/// The responsibilities that script gives one function each, sorted.
///
/// Nine stages, because a stage that shares a function with its neighbour
/// cannot be reordered, skipped, or read; and the two sequences that run them,
/// because the script has two entry points and a cold tool build belongs to
/// only one of them.
pub(crate) const PACKAGE_SCRIPT_FUNCTIONS: &[&str] = &[
    "cleanup",
    "generate_archive_workspace",
    "install_pinned_tools",
    "install_release_plz",
    "install_semver_checks",
    "measure_budget",
    "package_archives",
    "preflight",
    "run_packaged_workspace_proof",
    "run_release_update",
    "run_tool_installation",
    "stage_isolated_source",
    "verify_packaged_graph",
];

/// The entry point that chooses a stage, as the script spells it.
///
/// Building both pinned tools cold costs 1,429 measured seconds against a
/// 1,200-second verification slice, so `--install-tools` takes one tool and is
/// its own invocation. Nothing else may be an argument, and both the count and
/// the name are part of that: a proof that accepted an unknown flag would run
/// the wrong stage silently, one that dispatched on the first word alone would
/// answer a two-word question for a caller that asked a longer one, and one
/// that left an unknown tool name to the installer would refuse it only after
/// creating a staging root and running both pinned binaries. So the entry point
/// spells out the two sentences it accepts, whole.
pub(crate) const STAGE_SELECTION: &[&str] = &[
    "case \"$#:${1:-}:${2:-}\" in",
    "2:--install-tools:cargo-semver-checks) run_tool_installation install_semver_checks ;;",
    "2:--install-tools:release-plz) run_tool_installation install_release_plz ;;",
    "0::) run_packaged_workspace_proof ;;",
    "*) fail \"unknown arguments",
];

/// Dispatch spellings that read part of the request and act on the rest.
///
/// The first answers a longer sentence than it read. The second counts the
/// words but leaves the tool name to a function that has already created a
/// staging root, probed both pinned binaries, and started the clock.
pub(crate) const REJECTED_STAGE_SELECTIONS: &[&str] =
    &["case \"${1:-}\" in", "case \"$#:${1:-}\" in"];

/// One revision-pinned tool the proof builds before it stages anything.
pub(crate) struct PinnedTool {
    /// The installed binary, which is also the crate `cargo install` names.
    pub(crate) binary: &'static str,
    /// The function that owns building it, so a warm root can skip one tool.
    pub(crate) installer: &'static str,
    /// The exact probe that must precede the installation, after line joining.
    pub(crate) probe: &'static str,
    /// The exact installation the script must run, after line joining.
    pub(crate) installation: &'static str,
    /// The exact version assertion that installation must be followed by.
    pub(crate) assertion: &'static str,
}

/// Both pinned tools, in the order the script installs them.
///
/// cargo-semver-checks comes first because `release-plz update` consults it to
/// decide whether this tree's API change requires a major version, and a
/// release-plz that cannot find it would stage a version the registry would
/// reject rather than the one finalization will publish.
pub(crate) const PINNED_TOOLS: &[PinnedTool] = &[
    PinnedTool {
        binary: "cargo-semver-checks",
        installer: "install_semver_checks",
        probe: "if tool_reports_version \"${tool_root}/bin/cargo-semver-checks\" \
                \"${SEMVER_CHECKS_VERSION}\" semver-checks --version; then",
        installation: "run_classified install-semver-checks cargo install \
                       --git https://github.com/obi1kenobi/cargo-semver-checks \
                       --rev \"${SEMVER_CHECKS_REVISION}\" --locked \
                       --root \"${tool_root}\" cargo-semver-checks",
        assertion: "assert_tool_version \"${tool_root}/bin/cargo-semver-checks\" \
                    \"${SEMVER_CHECKS_VERSION}\" semver-checks --version",
    },
    PinnedTool {
        binary: "release-plz",
        installer: "install_release_plz",
        probe: "if tool_reports_version \"${tool_root}/bin/release-plz\" \
                \"${RELEASE_PLZ_VERSION}\" --version; then",
        installation: "run_classified install-release-plz cargo install \
                       --git https://github.com/release-plz/release-plz \
                       --rev \"${RELEASE_PLZ_REVISION}\" --locked \
                       --root \"${tool_root}\" release-plz",
        assertion: "assert_tool_version \"${tool_root}/bin/release-plz\" \
                    \"${RELEASE_PLZ_VERSION}\" --version",
    },
];

/// The pinned identities, as the script must spell them.
pub(crate) const PINNED_IDENTITIES: &[&str] = &[
    "RELEASE_PLZ_VERSION=\"0.3.160\"",
    "RELEASE_PLZ_REVISION=\"7e38e7a93dff31bbf6312400f79b9de36e8d3834\"",
    "SEMVER_CHECKS_VERSION=\"0.48.0\"",
    "SEMVER_CHECKS_REVISION=\"c9d2ce641c044846899ade23a34d3d5f40341ce9\"",
];

/// Every Git command the isolated staging stage must run, in order.
///
/// The clone is local and hard-link free, the checkout is detached at the
/// plan's base, the overlay carries the caller's complete working tree, and the
/// staged result is refused when it is empty. Order is the claim: a commit
/// created before the overlay would describe the base rather than the release.
///
/// The staged commit then moves onto a tracking branch, because release-plz
/// resolves `@{upstream}` to find the project and refuses a repository whose
/// HEAD points at no branch.
pub(crate) const ISOLATED_STAGING_STEPS: &[&str] = &[
    "test -n \"${PLAN_BASE_SHA:-}\"",
    "git cat-file -e \"${PLAN_BASE_SHA}^{commit}\"",
    "git clone --no-hardlinks --quiet -- \"${repository_root}\" \"${clone_root}\"",
    "git -C \"${clone_root}\" checkout --quiet --detach \"${PLAN_BASE_SHA}\"",
    "git diff --binary \"${PLAN_BASE_SHA}\"",
    "git -C \"${clone_root}\" apply --binary --whitespace=nowarn -- \"${patch}\"",
    "git ls-files --others --exclude-standard -z",
    "git -C \"${clone_root}\" add --all",
    "git -C \"${clone_root}\" diff --cached --quiet",
    "isolated_commit \"${PROOF_COMMIT_SUBJECT}\"",
    "git -C \"${clone_root}\" checkout --quiet -B \"${PROOF_BRANCH_NAME}\"",
    "git -C \"${clone_root}\" branch --quiet \
     --set-upstream-to=\"origin/${clone_branch}\" \"${PROOF_BRANCH_NAME}\"",
];

/// The command-scoped identity settings the isolated commit must carry.
///
/// `-c` scopes both the author and the committer to this one command, so the
/// proof never reads, writes, or depends on the operator's Git identity.
pub(crate) const ISOLATED_COMMIT_IDENTITY: &[&str] = &[
    "-c \"user.name=${PROOF_IDENTITY_NAME}\"",
    "-c \"user.email=${PROOF_IDENTITY_EMAIL}\"",
];

/// Every step that turns the release-plz update into the tree Cargo packages,
/// in order.
///
/// The versions, requirements, changelogs, and lockfile are release-plz's
/// output, and `cargo package --locked` refuses a tree carrying uncommitted
/// changes, so the run's second isolated commit is what the eight archives are
/// built from. A proof that staged the update and never committed it would
/// package the tree release-plz was handed rather than the one it wrote.
pub(crate) const RELEASE_STAGING_STEPS: &[&str] = &[
    "run_classified release-update env \"PATH=${tool_root}/bin:${PATH}\" \
     \"${tool_root}/bin/release-plz\" update",
    "git -C \"${clone_root}\" add --all",
    "git -C \"${clone_root}\" diff --cached --quiet",
    "isolated_commit \"${RELEASE_STAGING_SUBJECT}\"",
];

/// The archive-packaging steps, in the order the eight members require.
///
/// Every expected archive is removed before Cargo runs and required after it,
/// which is what makes each archive this run's rather than an earlier one's.
/// The packaging itself is one workspace-wide invocation: the staged versions
/// are not on crates.io yet, so a member packaged alone would ask the registry
/// for a sibling that does not exist until publication.
pub(crate) const ARCHIVE_PACKAGING_STEPS: &[&str] = &[
    "archive=\"${target_root}/package/${name}-${version}.crate\"",
    "remove_prior_archive \"${archive}\"",
    "run_classified package-workspace cargo package --manifest-path \"${clone_root}/Cargo.toml\" \
     --workspace --locked --no-verify",
    "test -f \"${archive}\"",
    "extract_archive \"${name}\" \"${version}\"",
];

/// Where the generated workspace's member list begins.
pub(crate) const MEMBER_LIST_OPEN: &str = "printf 'members = [\\n'";

/// Where that member list ends.
pub(crate) const MEMBER_LIST_CLOSE: &str = "printf ']\\n\\n'";

/// The one line that may add a member to the generated workspace.
///
/// Spelled from its format string onward, because line joining collapses the
/// indentation this `printf` carries inside its own quotes.
pub(crate) const ARCHIVE_MEMBER_ENTRY: &str = "\"%s-%s\",\\n' \"${name}\" \"${version}\"";

/// What proves an extracted member directory is the archive it is named for.
///
/// A member is a directory Cargo compiles, so the archive must land in the
/// generated workspace under its own `name-version`, and must hold nothing
/// outside it. An archive that unpacked a second tree beside its own would add
/// a member the manifest never listed and the graph checks never read.
pub(crate) const ARCHIVE_MEMBER_EXTRACTION: &[&str] = &[
    "extracted=\"${workspace_root}/${name}-${version}\"",
    "rg -N -v -e \"^${name}-${version}/\"",
    "tar -xzf \"${archive}\" -C \"${workspace_root}\"",
    "test -d \"${extracted}\"",
];

/// How the expected archive path is refused when it is not this run's to write.
pub(crate) const ARCHIVE_IDENTITY_REFUSALS: &[&str] = &[
    "if [ -L \"${archive}\" ]; then",
    "test -f \"${archive}\" || fail \"the expected archive path is not a regular file:",
    "rm -f -- \"${archive}\"",
];

/// The three Cargo commands the generated archive workspace is proved with.
pub(crate) const ARCHIVE_GRAPH_COMMANDS: &[&str] = &[
    "run_classified archive-lockfile cargo generate-lockfile \
     --manifest-path \"${workspace_root}/Cargo.toml\"",
    "cargo metadata --format-version 1 --locked --manifest-path \"${workspace_root}/Cargo.toml\"",
    "run_classified archive-check cargo check --workspace --all-features --locked \
     --manifest-path \"${workspace_root}/Cargo.toml\"",
];

/// Every state the packaged graph must refuse, named by its refusal message.
///
/// Each one is a way the proof could pass while publication still failed: a
/// first-party package pulled from the registry, a staged version the archive
/// does not carry, a requirement the archive does not state, a patch the graph
/// never used, or a member still resolving through the operator's checkout.
pub(crate) const GRAPH_REFUSALS: &[&str] = &[
    "resolves through the registry rather than its archive",
    "carries version",
    "states requirement",
    "was not used in the crate graph",
    "resolves through the original checkout",
];

/// The budget contract, as the script spells it.
///
/// Every number here was read off a measured run rather than chosen: the two
/// pinned tool builds and the release proof were each timed against an empty
/// target root, and the budgets are those readings with headroom. A ceiling
/// nobody measured is a ceiling the first genuinely cold run discovers.
pub(crate) const BUDGET_CONSTANTS: &[&str] = &[
    "TOOL_ROOT_NAME=\".pedant-packaged-workspace-7e38e7a-c9d2ce64.tools\"",
    "INSTALL_RUNTIME_BUDGET_SECONDS=1100",
    "INSTALL_TARGET_BUDGET_KIB=2097152",
    "COLD_RUNTIME_BUDGET_SECONDS=2100",
    "WARM_RUNTIME_BUDGET_SECONDS=600",
    "COLD_TARGET_BUDGET_KIB=5242880",
    "WARM_TARGET_BUDGET_KIB=2097152",
    "OWNED_TEMP_BUDGET_KIB=1048576",
];

/// Every tool the proof proves present before it changes any state.
///
/// The clock is on that list because the proof reads wall time through it
/// rather than through the shell, which is what lets a lifecycle row hand the
/// runtime refusal a clock it can reach.
pub(crate) const REQUIRED_TOOLS: &str =
    "REQUIRED_TOOLS=\"bash cargo date du find git jq mktemp rg rm tar\"";

/// What the inherited target root must satisfy before any state changes.
pub(crate) const TARGET_ROOT_REQUIREMENTS: &[&str] = &[
    "target_root=\"${CARGO_TARGET_DIR:-}\"",
    "readonly target_root",
    "test -n \"${target_root}\"",
    "case \"${target_root}\" in",
    "/*) ;;",
    "*) fail \"CARGO_TARGET_DIR must be absolute: ${target_root}\" ;;",
    "test -d \"${target_root}\"",
    "test -w \"${target_root}\"",
    "export CARGO_TARGET_DIR",
];
