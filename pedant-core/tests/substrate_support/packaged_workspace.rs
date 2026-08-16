//! The structural contract of the tracked packaged-workspace release proof.
//!
//! [`crate::release_workflow`] states the claim as one test; this module holds
//! the readings that prove the proof stages, packages, and compiles what it
//! says it does. [`crate::packaged_workspace_claims`] owns the tables those
//! readings compare against, and [`crate::packaged_workspace_budget`] reads
//! what the run costs. Both splits are the 500-line boundary, not a second
//! owner: nothing here is reachable from any other predicate.

use crate::packaged_workspace_budget::assert_budget_contract;
use crate::packaged_workspace_claims::{
    ARCHIVE_GRAPH_COMMANDS, ARCHIVE_IDENTITY_REFUSALS, ARCHIVE_PACKAGING_STEPS, GRAPH_REFUSALS,
    ISOLATED_COMMIT_IDENTITY, ISOLATED_STAGING_STEPS, PACKAGE_SCRIPT_FUNCTIONS, PINNED_IDENTITIES,
    PINNED_TOOLS, RELEASE_STAGING_STEPS, TARGET_ROOT_REQUIREMENTS,
};
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
/// `PATH`, what it wrote becomes the run's second isolated commit, and only
/// then is anything packaged.
fn assert_release_update_precedes_packaging(joined: &str) {
    let body = function_body(joined, "run_release_update");
    let mut previous = 0;
    for step in RELEASE_STAGING_STEPS {
        let offset = offset_of(&body, step);
        assert!(
            offset > previous,
            "the release staging step [{step}] runs out of order"
        );
        previous = offset;
    }
    let update = offset_of(joined, RELEASE_STAGING_STEPS[0]);
    let installation = offset_of(joined, PINNED_TOOLS[1].installation);
    let packaging = offset_of(joined, "cargo package --manifest-path");
    assert!(
        installation < update && update < packaging,
        "release-plz is installed, then runs, then packaging begins"
    );
    assert!(
        body.contains("cd -- \"${clone_root}\""),
        "release-plz runs from the isolated clone"
    );
    assert_eq!(
        joined
            .matches("RELEASE_STAGING_SUBJECT=\"chore: stage the release-plz update\"")
            .count(),
        1,
        "the proof names exactly one release-staging commit subject"
    );
    assert_eq!(
        joined
            .matches("isolated_commit \"${RELEASE_STAGING_SUBJECT}\"")
            .count(),
        1,
        "that subject is committed exactly once, and only after release-plz wrote it"
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
