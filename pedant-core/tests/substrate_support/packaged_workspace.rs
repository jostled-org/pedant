//! The structural contract of the tracked packaged-workspace release proof.
//!
//! [`crate::release_workflow`] states the claim as one test; this module holds
//! the readings that prove the proof stages, packages, and compiles what it
//! says it does. [`crate::packaged_workspace_claims`] owns the tables those
//! readings compare against, the readers that take the script, and the three
//! shared assertions; [`crate::packaged_workspace_budget`] reads what the run
//! costs. Both splits are the 500-line boundary, not a second owner: nothing
//! here is reachable from any other predicate.

use crate::packaged_workspace_budget::assert_budget_contract;
use crate::packaged_workspace_claims::{
    ARCHIVE_GRAPH_COMMANDS, ARCHIVE_IDENTITY_REFUSALS, ARCHIVE_MEMBER_ENTRY,
    ARCHIVE_MEMBER_EXTRACTION, ARCHIVE_PACKAGING_STEPS, GRAPH_REFUSAL_CHECKS, GRAPH_REFUSALS,
    ISOLATED_BASE_STEPS, ISOLATED_COMMIT_IDENTITY, ISOLATED_STAGING_SEQUENCE, MEMBER_LIST_CLOSE,
    MEMBER_LIST_OPEN, PACKAGE_SCRIPT_FUNCTIONS, PINNED_IDENTITIES, PINNED_TOOLS,
    PROOF_STAGE_SEQUENCE, RELEASE_STAGING_STEPS, TARGET_ROOT_REQUIREMENTS, UNTRACKED_COPY_STEPS,
    WORKING_TREE_OVERLAY_STEPS, assert_contains_all, assert_exactly_once, assert_in_order,
    function_body, offset_of, read_repository_file, tracked_shell_scripts,
};

/// Read the tracked proof once and require every part of it.
pub(crate) fn assert_release_graph_is_exact() {
    let source = read_repository_file(PACKAGED_WORKSPACE_SCRIPT);
    let joined = joined_lines(&source);

    assert_package_script_stages(&source);
    assert_target_root_contract(&source);
    assert_release_order_authority(&source);
    assert_proof_stage_sequence(&joined);
    assert_isolated_staging(&joined);
    assert_pinned_tool_installation(&joined);
    assert_release_update_precedes_packaging(&joined);
    assert_archive_packaging(&joined);
    assert_generated_workspace(&joined);
    assert_members_are_extracted_archives(&joined);
    assert_packaged_graph_verification(&joined);
    assert_budget_contract(&joined);
    assert_package_script_ownership(&source, &joined);
}

/// The tracked proof that compiles the release archives as a registry consumer
/// receives them.
const PACKAGED_WORKSPACE_SCRIPT: &str = ".github/scripts/check_packaged_workspace.sh";

/// The twelve stages the proof owns and the two sequences that run them.
const PACKAGE_SCRIPT_FUNCTION_COUNT: usize = 14;

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

/// Every stage the proof owns is one function, no stage is missing, and the
/// inventory is the sorted list it says it is.
fn assert_package_script_stages(source: &str) {
    assert_eq!(
        PACKAGE_SCRIPT_FUNCTIONS.len(),
        PACKAGE_SCRIPT_FUNCTION_COUNT,
        "the proof owns twelve stages and the two sequences that run them"
    );
    let mut sorted: Box<[&str]> = PACKAGE_SCRIPT_FUNCTIONS.into();
    sorted.sort_unstable();
    assert_eq!(
        &*sorted, PACKAGE_SCRIPT_FUNCTIONS,
        "the stage inventory is stated sorted"
    );
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
    assert_contains_all(
        &function_body(source, "capture_target_root"),
        TARGET_ROOT_REQUIREMENTS,
        "the target-root contract",
    );
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

/// The release proof runs its stages in the order the release requires.
///
/// Read inside the entry point that calls them. The stages are defined in
/// whatever order reads best, so the same sequence taken over the whole script
/// would prove where they were written rather than when they run: moving the
/// packaging call above the update call inside this function would leave every
/// definition where it is.
fn assert_proof_stage_sequence(joined: &str) {
    assert_in_order(
        &function_body(joined, "run_packaged_workspace_proof"),
        PROOF_STAGE_SEQUENCE,
        "the release proof sequence",
    );
}

/// The isolated tree is the caller's whole working tree replayed onto the
/// plan's base as one breaking commit, in that order.
///
/// Four tables against four function bodies. The staging is spread over four
/// functions, and an order read over all of them at once would hold however
/// they called each other.
fn assert_isolated_staging(joined: &str) {
    for (owner, steps) in [
        ("clone_isolated_base", ISOLATED_BASE_STEPS),
        ("overlay_working_tree", WORKING_TREE_OVERLAY_STEPS),
        ("copy_untracked_files", UNTRACKED_COPY_STEPS),
        ("stage_isolated_source", ISOLATED_STAGING_SEQUENCE),
    ] {
        assert_in_order(&function_body(joined, owner), steps, owner);
    }
    assert_contains_all(
        joined,
        ISOLATED_COMMIT_IDENTITY,
        "the command-scoped isolated commit identity",
    );
    assert_exactly_once(
        joined,
        "PROOF_COMMIT_SUBJECT=\"feat!: implement symbol capability profiles\"",
        "the breaking release commit subject",
    );
    assert_exactly_once(
        joined,
        "isolated_commit \"${PROOF_COMMIT_SUBJECT}\"",
        "the commit that carries that subject",
    );
}

/// Both tools are installed from their pinned revisions, and each is asked for
/// its version before it is built and again after.
///
/// All three readings come from the body of the one function that owns that
/// tool, which is where a warm root skips the build and a cold one pays for it.
fn assert_pinned_tool_installation(joined: &str) {
    assert_eq!(PINNED_TOOLS.len(), 2, "the proof pins exactly two tools");
    assert_contains_all(joined, PINNED_IDENTITIES, "the pinned identities");
    for tool in PINNED_TOOLS {
        assert_in_order(
            &function_body(joined, tool.installer),
            &[tool.probe, tool.installation, tool.assertion],
            tool.installer,
        );
    }
}

/// release-plz runs against the isolated clone with both pinned binaries on
/// `PATH`, and what it wrote becomes the run's second isolated commit.
///
/// That this happens after the installation and before the packaging is
/// [`assert_proof_stage_sequence`]'s claim, taken where those three stages are
/// called.
fn assert_release_update_precedes_packaging(joined: &str) {
    let body = function_body(joined, "run_release_update");
    assert_in_order(&body, RELEASE_STAGING_STEPS, "the release staging");
    assert!(
        body.contains("cd -- \"${clone_root}\""),
        "release-plz runs from the isolated clone"
    );
    assert_exactly_once(
        joined,
        "RELEASE_STAGING_SUBJECT=\"chore: stage the release-plz update\"",
        "the release-staging commit subject",
    );
    assert_exactly_once(
        joined,
        "isolated_commit \"${RELEASE_STAGING_SUBJECT}\"",
        "the commit that carries that subject, written only after release-plz did",
    );
}

/// Every member is packaged from its staged manifest into a fresh archive this
/// run owns.
fn assert_archive_packaging(joined: &str) {
    let body = function_body(joined, "package_archives");
    assert_in_order(&body, ARCHIVE_PACKAGING_STEPS, "the archive packaging");
    assert!(
        body.contains("for name in \"${release_order[@]}\""),
        "packaging follows the release order"
    );
    assert_contains_all(
        &function_body(joined, "remove_prior_archive"),
        ARCHIVE_IDENTITY_REFUSALS,
        "the archive identity check",
    );
    assert_packaging_is_one_workspace_invocation(joined);
}

/// Exactly one command in the whole proof runs `cargo package`, and it is the
/// workspace-wide one.
///
/// The staged versions are not on crates.io yet, so a member packaged on its own
/// asks the registry for a sibling that does not exist until publication. The
/// ordered steps above cannot see that: a per-member `cargo package` added to
/// either loop leaves every one of them in its place, and the run would report a
/// green check for archives built the way publication never builds them. So the
/// count is the claim, and it is taken over the whole script rather than over
/// one function, because a second invocation elsewhere packages the same tree.
fn assert_packaging_is_one_workspace_invocation(joined: &str) {
    let invocations: Box<[&str]> = joined
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(command_of)
        .filter(|command| command.contains("cargo package"))
        .collect();
    assert_eq!(
        &*invocations,
        &[ARCHIVE_PACKAGING_STEPS[2]],
        "the eight archives come from exactly one workspace-wide packaging command"
    );
}

/// The command one joined line runs, with any refusal message cut away.
///
/// A `fail` message quotes the command it is about, and a message is text rather
/// than an invocation; counting it would let the proof's own prose decide
/// whether the proof passes.
fn command_of(line: &str) -> &str {
    line.split_once(" || fail ")
        .map_or(line, |(command, _)| command)
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
}

/// Every member of the generated workspace is an archive this run extracted,
/// one per released package.
///
/// The patch table decides which requirements are redirected; the member list
/// decides which trees Cargo compiles at all. A member from anywhere but the
/// release order — the operator's checkout, a directory an earlier run left, a
/// path the script kept for convenience — would compile beside the archives and
/// answer for them, and the proof would report a green check for source no
/// consumer receives.
fn assert_members_are_extracted_archives(joined: &str) {
    let manifest = function_body(joined, "write_archive_manifest");
    let subject = "the generated workspace member list";
    let open = offset_of(&manifest, MEMBER_LIST_OPEN, subject) + MEMBER_LIST_OPEN.len();
    let close = offset_of(&manifest, MEMBER_LIST_CLOSE, subject);
    assert!(
        open < close,
        "the member list is filled before it is closed"
    );
    let members = &manifest[open..close];
    assert_exactly_once(members, "printf", "the line that names a workspace member");
    assert_exactly_once(
        members,
        ARCHIVE_MEMBER_ENTRY,
        "the extracted archive directory that line names",
    );
    assert!(
        members.contains("for name in \"${release_order[@]}\"; do"),
        "the members are the release order and nothing beside it"
    );
    assert!(
        members.contains("read_staged_version \"${name}\""),
        "each member directory carries the version release-plz staged"
    );
    assert_contains_all(
        &function_body(joined, "extract_archive"),
        ARCHIVE_MEMBER_EXTRACTION,
        "an extracted member proved to be its own archive",
    );
}

/// The packaged graph is locked, read, refused for every wrong shape, and only
/// then compiled.
///
/// The order is read inside `verify_packaged_graph`, which is where the three
/// refusals and the compile are called. Their messages live in the functions
/// those calls name, so an order taken over the whole script would compare the
/// line a refusal was written on against the line the compile was written on and
/// hold whatever order they ran in.
fn assert_packaged_graph_verification(joined: &str) {
    let body = function_body(joined, "verify_packaged_graph");
    let subject = "the packaged-graph verification";
    assert_in_order(&body, ARCHIVE_GRAPH_COMMANDS, subject);
    assert_contains_all(joined, GRAPH_REFUSALS, "the packaged graph refusals");
    assert_contains_all(&body, GRAPH_REFUSAL_CHECKS, subject);
    let check = offset_of(&body, ARCHIVE_GRAPH_COMMANDS[2], subject);
    for refusal in GRAPH_REFUSAL_CHECKS {
        assert!(
            offset_of(&body, refusal, subject) < check,
            "[{refusal}] must run before the packaged check"
        );
    }
}

/// The proof owns one staging root, releases it on every path, classifies
/// through the one tracked owner, and joins the ShellCheck inventory once.
fn assert_package_script_ownership(source: &str, joined: &str) {
    let subject = "the proof's ownership of its staging root";
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
        subject,
    );
    for handler in [
        "trap 'cleanup' EXIT",
        "trap 'interrupted 1' HUP",
        "trap 'interrupted 2' INT",
        "trap 'interrupted 15' TERM",
    ] {
        assert!(
            offset_of(joined, handler, subject) < staging_root,
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
/// Steps 6 and 7 add shell surfaces outside `.github/scripts` — the five fake
/// tools their lifecycle and budget rows install on `PATH` — and a fault
/// injector nobody lints is a fault injector nobody can trust. The subject list
/// must equal the tracked inventory, which is duplicate-free, so every script
/// including this proof and the tracked classifier is a subject exactly once,
/// and the next script added is too.
fn assert_shellcheck_covers_every_tracked_script() {
    let wrapper = read_repository_file(".github/scripts/run_shellcheck.sh");
    let mut subjects: Box<[Box<str>]> = wrapper
        .lines()
        .map(|line| line.trim().trim_end_matches('\\').trim())
        .filter(|token| token.ends_with(".sh"))
        .map(Box::from)
        .collect();
    subjects.sort();
    let mut tracked = tracked_shell_scripts();
    tracked.sort();
    assert!(
        !tracked.is_empty(),
        "this repository tracks shell scripts, so the inventory cannot be empty"
    );
    assert_eq!(
        subjects, tracked,
        "the pinned ShellCheck run must lint exactly the tracked shell scripts"
    );
}
