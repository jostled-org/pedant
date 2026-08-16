//! The structural contract of the tracked packaged-workspace release proof.
//!
//! [`crate::release_workflow`] states the claim as one test; this module holds the tables it
//! compares against and the readings that compare them. The split is the
//! 500-line boundary, not a second owner: nothing here is reachable from any
//! other predicate.

use crate::release_workflow::{
    function_body, offset_of, read_repository_file, tracked_shell_scripts,
};

/// Read the tracked proof once and require every part of it.
pub(crate) fn assert_release_graph_is_exact() {
    let source = read_repository_file(PACKAGED_WORKSPACE_SCRIPT);
    let joined = joined_lines(&source);

    assert_package_script_stages(&source);
    assert_target_root_contract(&source);
    assert_release_order_authority(&source);
    assert_isolated_staging(&joined);
    assert_pinned_tool_installation(&joined);
    assert_release_update_precedes_packaging(&joined);
    assert_archive_packaging(&joined);
    assert_generated_workspace(&joined);
    assert_packaged_graph_verification(&joined);
    assert_budget_contract(&joined);
    assert_package_script_ownership(&source, &joined);
}

/// The tracked proof that compiles the release archives as a registry consumer
/// receives them.
const PACKAGED_WORKSPACE_SCRIPT: &str = ".github/scripts/check_packaged_workspace.sh";

/// The responsibilities that script gives one function each, sorted.
///
/// Nine names, because the proof has nine stages and a stage that shares a
/// function with its neighbour cannot be reordered, skipped, or read.
const PACKAGE_SCRIPT_FUNCTIONS: &[&str] = &[
    "cleanup",
    "generate_archive_workspace",
    "install_pinned_tools",
    "measure_budget",
    "package_archives",
    "preflight",
    "run_release_update",
    "stage_isolated_source",
    "verify_packaged_graph",
];

/// One revision-pinned tool the proof builds before it stages anything.
struct PinnedTool {
    /// The installed binary, which is also the crate `cargo install` names.
    binary: &'static str,
    /// The exact installation the script must run, after line joining.
    installation: &'static str,
    /// The exact version assertion that installation must be followed by.
    assertion: &'static str,
}

/// Both pinned tools, in the order the script installs them.
///
/// cargo-semver-checks comes first because `release-plz update` consults it to
/// decide whether this tree's API change requires a major version, and a
/// release-plz that cannot find it would stage a version the registry would
/// reject rather than the one finalization will publish.
const PINNED_TOOLS: &[PinnedTool] = &[
    PinnedTool {
        binary: "cargo-semver-checks",
        installation: "run_classified install-semver-checks cargo install \
                       --git https://github.com/obi1kenobi/cargo-semver-checks \
                       --rev \"${SEMVER_CHECKS_REVISION}\" --locked \
                       --root \"${tool_root}\" cargo-semver-checks",
        assertion: "assert_tool_version \"${tool_root}/bin/cargo-semver-checks\" \
                    \"${SEMVER_CHECKS_VERSION}\" semver-checks --version",
    },
    PinnedTool {
        binary: "release-plz",
        installation: "run_classified install-release-plz cargo install \
                       --git https://github.com/release-plz/release-plz \
                       --rev \"${RELEASE_PLZ_REVISION}\" --locked \
                       --root \"${tool_root}\" release-plz",
        assertion: "assert_tool_version \"${tool_root}/bin/release-plz\" \
                    \"${RELEASE_PLZ_VERSION}\" --version",
    },
];

/// The pinned identities, as the script must spell them.
const PINNED_IDENTITIES: &[&str] = &[
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
const ISOLATED_STAGING_STEPS: &[&str] = &[
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
const ISOLATED_COMMIT_IDENTITY: &[&str] = &[
    "-c \"user.name=${PROOF_IDENTITY_NAME}\"",
    "-c \"user.email=${PROOF_IDENTITY_EMAIL}\"",
];

/// The archive-packaging steps, in the order the eight members require.
///
/// Every expected archive is removed before Cargo runs and required after it,
/// which is what makes each archive this run's rather than an earlier one's.
/// The packaging itself is one workspace-wide invocation: the staged versions
/// are not on crates.io yet, so a member packaged alone would ask the registry
/// for a sibling that does not exist until publication.
const ARCHIVE_PACKAGING_STEPS: &[&str] = &[
    "archive=\"${target_root}/package/${name}-${version}.crate\"",
    "remove_prior_archive \"${archive}\"",
    "run_classified package-workspace cargo package --manifest-path \"${clone_root}/Cargo.toml\" \
     --workspace --locked --no-verify",
    "test -f \"${archive}\"",
    "extract_archive \"${name}\" \"${version}\"",
];

/// How the expected archive path is refused when it is not this run's to write.
const ARCHIVE_IDENTITY_REFUSALS: &[&str] = &[
    "if [ -L \"${archive}\" ]; then",
    "test -f \"${archive}\" || fail \"the expected archive path is not a regular file:",
    "rm -f -- \"${archive}\"",
];

/// The three Cargo commands the generated archive workspace is proved with.
const ARCHIVE_GRAPH_COMMANDS: &[&str] = &[
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
const GRAPH_REFUSALS: &[&str] = &[
    "resolves through the registry rather than its archive",
    "carries version",
    "states requirement",
    "was not used in the crate graph",
    "resolves through the original checkout",
];

/// The budget contract, as the script spells it.
const BUDGET_CONSTANTS: &[&str] = &[
    "WARM_MARKER_NAME=\".pedant-packaged-workspace-7e38e7a-c9d2ce64.warm\"",
    "COLD_RUNTIME_BUDGET_SECONDS=1100",
    "WARM_RUNTIME_BUDGET_SECONDS=600",
    "COLD_TARGET_BUDGET_KIB=6291456",
    "WARM_TARGET_BUDGET_KIB=524288",
    "OWNED_TEMP_BUDGET_KIB=1048576",
];

/// What the inherited target root must satisfy before any state changes.
const TARGET_ROOT_REQUIREMENTS: &[&str] = &[
    "target_root=\"${CARGO_TARGET_DIR:-}\"",
    "readonly target_root",
    "test -n \"${target_root}\"",
    "case \"${target_root}\" in",
    "test -d \"${target_root}\"",
    "test -w \"${target_root}\"",
    "export CARGO_TARGET_DIR",
];

/// One logical shell command per line, so a fragment states a whole command
/// rather than whichever slice of it survived the author's line wrapping.
fn joined_lines(source: &str) -> Box<str> {
    let continued = source.replace("\\\n", " ");
    let lines: Box<[Box<str>]> = continued
        .lines()
        .map(|line| {
            let words: Box<[&str]> = line.split_whitespace().collect();
            words.join(" ").into()
        })
        .collect();
    lines.join("\n").into()
}

/// Every stage the proof owns is one function, and no stage is missing.
fn assert_package_script_stages(source: &str) {
    let defined: Box<[Box<str>]> = source
        .lines()
        .filter_map(|line| line.strip_suffix("() {"))
        .map(Box::from)
        .collect();
    for stage in PACKAGE_SCRIPT_FUNCTIONS {
        assert_eq!(
            defined
                .iter()
                .filter(|name| name.as_ref() == *stage)
                .count(),
            1,
            "the packaged-workspace proof needs exactly one {stage} owner"
        );
    }
}

/// The inherited target root is checked, captured, sealed, and re-exported
/// unchanged; nothing in the script may write or drop it.
fn assert_target_root_contract(source: &str) {
    for requirement in TARGET_ROOT_REQUIREMENTS {
        assert!(
            source.contains(requirement),
            "the target-root contract is missing [{requirement}]"
        );
    }
    assert!(
        !source.contains("CARGO_TARGET_DIR="),
        "the proof must inherit its target root rather than choose one"
    );
    assert!(
        !source.contains("unset "),
        "the proof must not unset the environment it inherits"
    );
}

/// The release order comes from `release-plz.toml`, is exactly eight packages,
/// and is reconciled with the tracked manifests before anything is staged.
fn assert_release_order_authority(source: &str) {
    assert!(
        source.contains("release-plz.toml"),
        "release-plz.toml is the release-order authority"
    );
    assert!(
        source.contains("RELEASE_PACKAGE_COUNT=8"),
        "the release graph holds exactly eight packages"
    );
    assert!(
        function_body(source, "preflight").contains("read_release_order"),
        "preflight reads the release order before any state changes"
    );
    assert!(
        function_body(source, "read_release_order")
            .contains("assert_release_order_matches_manifests"),
        "the release order is reconciled with the tracked manifests"
    );
}

/// The isolated tree is the caller's whole working tree replayed onto the
/// plan's base as one breaking commit, in that order.
fn assert_isolated_staging(joined: &str) {
    let mut previous = 0;
    for step in ISOLATED_STAGING_STEPS {
        let offset = offset_of(joined, step);
        assert!(
            offset > previous,
            "the isolated staging step [{step}] runs out of order"
        );
        previous = offset;
    }
    for setting in ISOLATED_COMMIT_IDENTITY {
        assert!(
            joined.contains(setting),
            "the isolated commit needs command-scoped identity [{setting}]"
        );
    }
    assert_eq!(
        joined
            .matches("PROOF_COMMIT_SUBJECT=\"feat!: implement symbol capability profiles\"")
            .count(),
        1,
        "the proof stages exactly one breaking release commit subject"
    );
    assert_eq!(
        joined
            .matches("isolated_commit \"${PROOF_COMMIT_SUBJECT}\"")
            .count(),
        1,
        "that subject is committed exactly once"
    );
}

/// Both tools are installed from their pinned revisions and proved to be the
/// pinned versions.
fn assert_pinned_tool_installation(joined: &str) {
    for identity in PINNED_IDENTITIES {
        assert!(
            joined.contains(identity),
            "the pinned identity [{identity}] is missing"
        );
    }
    for tool in PINNED_TOOLS {
        let installation = offset_of(joined, tool.installation);
        let assertion = offset_of(joined, tool.assertion);
        assert!(
            installation < assertion,
            "{} is installed before its version is proved",
            tool.binary
        );
    }
}

/// release-plz runs against the isolated clone with both pinned binaries on
/// `PATH`, and it runs before any archive is packaged.
fn assert_release_update_precedes_packaging(joined: &str) {
    let update = offset_of(
        joined,
        "run_classified release-update env \"PATH=${tool_root}/bin:${PATH}\" \
         \"${tool_root}/bin/release-plz\" update",
    );
    let installation = offset_of(joined, PINNED_TOOLS[1].installation);
    let packaging = offset_of(joined, "cargo package --manifest-path");
    assert!(
        installation < update && update < packaging,
        "release-plz is installed, then runs, then packaging begins"
    );
    assert!(
        joined.contains("cd -- \"${clone_root}\""),
        "release-plz runs from the isolated clone"
    );
}

/// Every member is packaged from its staged manifest into a fresh archive this
/// run owns.
fn assert_archive_packaging(joined: &str) {
    let body = function_body(joined, "package_archives");
    let mut previous = 0;
    for step in ARCHIVE_PACKAGING_STEPS {
        let offset = offset_of(&body, step);
        assert!(
            offset > previous,
            "the packaging step [{step}] runs out of order"
        );
        previous = offset;
    }
    assert!(
        body.contains("for name in \"${release_order[@]}\""),
        "packaging follows the release order"
    );
    for refusal in ARCHIVE_IDENTITY_REFUSALS {
        assert!(
            joined.contains(refusal),
            "the archive identity check is missing [{refusal}]"
        );
    }
}

/// The generated workspace holds the extracted archives and patches exactly the
/// packages with an inbound first-party edge.
///
/// Exactly is checked against the metadata Cargo produced, not against the value
/// that wrote the manifest. Those two are the same number by construction, and a
/// check that compared them would pass whatever the patch set was.
fn assert_generated_workspace(joined: &str) {
    let body = function_body(joined, "generate_archive_workspace");
    assert!(
        body.contains("derive_first_party_edges"),
        "the patch set is derived from the packaged manifests"
    );
    assert!(
        body.contains("write_archive_manifest"),
        "one function writes the generated workspace manifest"
    );
    assert!(
        joined.contains("[patch.crates-io]"),
        "the generated workspace patches crates.io"
    );
    let exactness = function_body(joined, "assert_patch_set_is_exact");
    assert!(
        exactness.contains("${archive_metadata}"),
        "the required patch set is read from the packaged metadata"
    );
    assert!(
        !exactness.contains("${inbound_packages}"),
        "a patch-set check that reads the value that wrote the manifest \
         compares that manifest against itself"
    );
    let verification = function_body(joined, "verify_packaged_graph");
    for check in [
        "assert_no_unused_patch",
        "assert_patch_set_is_exact",
        "assert_packaged_graph_shape",
    ] {
        assert!(
            verification.contains(check),
            "the packaged graph is not proved by [{check}]"
        );
    }
}

/// The packaged graph is locked, read, refused for every wrong shape, and only
/// then compiled.
fn assert_packaged_graph_verification(joined: &str) {
    let mut previous = 0;
    for command in ARCHIVE_GRAPH_COMMANDS {
        let offset = offset_of(joined, command);
        assert!(
            offset > previous,
            "the packaged-graph command [{command}] runs out of order"
        );
        previous = offset;
    }
    for refusal in GRAPH_REFUSALS {
        assert!(
            joined.contains(refusal),
            "the packaged graph does not refuse [{refusal}]"
        );
    }
    let check = offset_of(joined, ARCHIVE_GRAPH_COMMANDS[2]);
    for refusal in GRAPH_REFUSALS {
        assert!(
            offset_of(joined, refusal) < check,
            "[{refusal}] must be refused before the packaged check runs"
        );
    }
}

/// The proof states its own cost and fails when it exceeds the budget its warm
/// marker selects.
fn assert_budget_contract(joined: &str) {
    for constant in BUDGET_CONSTANTS {
        assert!(
            joined.contains(constant),
            "the budget contract is missing [{constant}]"
        );
    }
    let body = function_body(joined, "measure_budget");
    for fragment in [
        "elapsed=",
        "target_growth_kib=",
        "temp_peak_kib",
        "warm_state",
    ] {
        assert!(
            body.contains(fragment),
            "the budget report omits [{fragment}]"
        );
    }
    assert!(
        joined.contains("du -sk"),
        "target growth and owned temporary peak are measured, not estimated"
    );
    assert!(
        offset_of(joined, "write_warm_marker") > offset_of(joined, "measure_budget"),
        "the warm marker is written only after a proof that stayed in budget"
    );
}

/// The proof owns one staging root, releases it on every path, classifies
/// through the one tracked owner, and joins the ShellCheck inventory once.
fn assert_package_script_ownership(source: &str, joined: &str) {
    assert!(
        source.contains(". \"${script_dir}/cargo_infrastructure.sh\""),
        "the packaged-workspace proof classifies through the tracked owner"
    );
    assert!(
        !source.contains("docs/scripts"),
        "a tracked proof must not reach into ignored lifecycle files"
    );
    assert!(
        joined.contains("STAGING_PREFIX=\"pedant-packaged-workspace\""),
        "the staging root carries the stable prefix its owners search for"
    );
    let staging_root = offset_of(
        joined,
        "mktemp -d \"${TMPDIR:-/tmp}/${STAGING_PREFIX}.XXXXXX\"",
    );
    for handler in [
        "trap 'cleanup' EXIT",
        "trap 'interrupted 1' HUP",
        "trap 'interrupted 2' INT",
        "trap 'interrupted 15' TERM",
    ] {
        assert!(
            offset_of(joined, handler) < staging_root,
            "[{handler}] must be installed before the staging root exists"
        );
    }
    assert!(
        function_body(joined, "cleanup").contains("rm -rf -- \"${staging_root}\""),
        "cleanup removes the staging root and nothing else"
    );
    assert!(
        function_body(joined, "interrupted").contains("exit \"$((128 + $1))\""),
        "a signalled proof leaves with its signal status"
    );
    assert_shellcheck_covers_every_tracked_script();
}

/// The pinned ShellCheck run lints every tracked shell script, each once.
///
/// Step 5 added a shell surface outside `.github/scripts` for the first time —
/// the three fake tools a lifecycle row installs on `PATH` — and a fault
/// injector nobody lints is a fault injector nobody can trust. Requiring the
/// subject list to equal the tracked inventory keeps that true for the next
/// script too, rather than for these three.
fn assert_shellcheck_covers_every_tracked_script() {
    let wrapper = read_repository_file(".github/scripts/run_shellcheck.sh");
    let subjects: Box<[Box<str>]> = wrapper
        .lines()
        .map(|line| line.trim().trim_end_matches('\\').trim())
        .filter(|token| token.ends_with(".sh"))
        .map(Box::from)
        .collect();
    let mut sorted = subjects.clone();
    sorted.sort();
    let mut tracked = tracked_shell_scripts();
    tracked.sort();
    assert_eq!(
        sorted, tracked,
        "the pinned ShellCheck run must lint exactly the tracked shell scripts"
    );
    assert_eq!(
        subjects
            .iter()
            .filter(|subject| subject.as_ref() == PACKAGED_WORKSPACE_SCRIPT)
            .count(),
        1,
        "the packaged-workspace proof is a ShellCheck subject exactly once"
    );
}
