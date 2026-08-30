//! Lifecycle contract of the tracked packaged-workspace release proof.
//!
//! `.github/scripts/check_packaged_workspace.sh` clones the repository, builds
//! two pinned tools, lets release-plz stage eight versions, packages every
//! member, and compiles the extracted archives against each other. The indexed
//! proof runs that against the real registry and the real Cargo; nothing about
//! it is cheap, and nothing about it is deterministic enough to state what
//! happens when a package step exits 3, when a volume fills mid-install, or
//! when the operator presses Ctrl-C.
//!
//! That is what this tree owns. [`fixture`] installs the fake tools, [`row`]
//! runs one row, and [`verdict`] states what a finished row must show. This
//! module names every claim the root registers, and holds the one every other
//! row rests on: that the proof reads the repository root it was handed and no
//! other. Each remaining subject has a module of its own — [`lifecycle_cases`]
//! for what a row must do on every path out of it, [`release_cases`] for the
//! protocol a releaseable workspace is published through, [`graph_cases`] for
//! what the packaged graph must refuse, and [`budget_cases`] for what the run
//! is allowed to cost.

/// The repository, staged tree, and fake tools every row is given. Same
/// `#[path]` reason as the modules `supply_chain.rs` declares.
#[path = "packaged_workspace_support/fixture.rs"]
mod fixture;

/// One row's root, and the fault its fake tools carry. Same `#[path]` reason.
#[path = "packaged_workspace_support/row.rs"]
mod row;

/// What one row's fake tools left behind, read back. Split from [`row`] because
/// a root is built once and a record is read after the run. Same `#[path]`
/// reason.
#[path = "packaged_workspace_support/record.rs"]
mod record;

/// What every finished row must show. Same `#[path]` reason.
#[path = "packaged_workspace_support/verdict.rs"]
mod verdict;

/// What one row must do on every path out of it, and which stage it selected.
/// Same `#[path]` reason.
#[path = "packaged_workspace_support/lifecycle_cases.rs"]
mod lifecycle_cases;

/// The release protocol a releaseable packaged workspace is published through.
/// Same `#[path]` reason.
#[path = "packaged_workspace_support/release_cases.rs"]
mod release_cases;

/// The packaged graphs the proof has to refuse. Same `#[path]` reason.
#[path = "packaged_workspace_support/graph_cases.rs"]
mod graph_cases;

/// What the proof is allowed to cost, and which budget says so. Same `#[path]`
/// reason.
#[path = "packaged_workspace_support/budget_cases.rs"]
mod budget_cases;

use row::{Fault, RELEASE_STAGE, RowRoot};
use verdict::{assert_refusal, assert_refused_before_anything_ran};

/// Linux `/bin/sh` does not guarantee that `exec` can dispatch the `command`
/// shell builtin. The budget fakes must delegate through the builtin itself,
/// or every packaged-workspace row exits 127 before reaching its subject.
#[test]
fn fake_budget_tools_do_not_exec_a_shell_builtin() {
    for (name, source) in [("date", fixture::FAKE_DATE), ("du", fixture::FAKE_DU)] {
        assert!(
            !source.contains("exec command"),
            "the fake {name} tool must not exec the command builtin"
        );
        assert!(
            source.contains(&format!("command -p {name}")),
            "the fake {name} tool must delegate through the portable command builtin"
        );
    }
}

/// The packaged-workspace proof keeps an ordinary failure, reclassifies every
/// infrastructure signature, honours TERM, and leaves nothing behind on any of
/// them.
#[test]
fn packaged_workspace_cleanup_is_bounded_on_success_failure_infrastructure_and_interrupt() {
    lifecycle_cases::verify_bounded_cleanup();
}

/// The proof reads one explicit Git toplevel rather than whichever repository
/// happens to contain its caller's working directory, and rejects every
/// malformed root before it moves state.
///
/// Only the refusals are stated here. Every row this tree runs already starts
/// from its own root and names its repository explicitly, so a clean run under
/// a well-formed root is what [`lifecycle_cases`] and [`release_cases`] prove
/// in full; a third one would restate a strict subset of both.
#[test]
fn packaged_workspace_requires_one_explicit_matching_repository_root_before_mutation() {
    let missing = RowRoot::new();
    let completed = missing.run_without_repository_root(&Fault::None);
    assert_root_refusal(
        &missing,
        "a missing repository root",
        &completed,
        "a repository-root argument is required",
    );

    let file = RowRoot::new();
    let root_file = file.repository_root_file();
    let completed = file.run_stage_with_repository_root(&Fault::None, &root_file, RELEASE_STAGE);
    assert_root_refusal(
        &file,
        "a repository root naming a file",
        &completed,
        "repository root must be an existing directory",
    );

    let non_git = RowRoot::new();
    let completed =
        non_git.run_stage_with_repository_root(&Fault::None, non_git.non_git_root(), RELEASE_STAGE);
    assert_root_refusal(
        &non_git,
        "a non-Git repository root",
        &completed,
        "repository root is not a Git working tree",
    );

    let mismatched = RowRoot::new();
    let nested = mismatched.nested_repository_root();
    let completed = mismatched.run_stage_with_repository_root(&Fault::None, &nested, RELEASE_STAGE);
    assert_root_refusal(
        &mismatched,
        "a directory below the Git toplevel",
        &completed,
        "does not match its Git toplevel",
    );
}

/// One malformed root has the same closed refusal verdict in every row.
fn assert_root_refusal(
    root: &RowRoot,
    label: &str,
    completed: &crate::process_guard::Completed,
    message: &str,
) {
    assert_refused_before_anything_ran(root, label, completed, &[]);
    assert_refusal(label, completed, message);
}

/// Every unreleaseable packaged graph is refused before compilation begins.
#[test]
fn packaged_graph_refuses_every_unreleaseable_shape() {
    graph_cases::verify_packaged_graph_refusals();
}

/// 12.T3 (Invariant 22): a release whose dependency graph holds optional,
/// feature-gated edges is staged, packaged, and resolved from the archives, in
/// the order those edges force.
///
/// The released workspace holds three of them, and they are why `pedant-syntax`
/// releases before `pedant-core` and why `pedant-core` and `pedant-graph`
/// release before the navigation product that takes both. What that costs is
/// invisible in this repository until publication: Cargo replaces the path edge
/// with a registry edge while packaging an optional dependency exactly as it
/// does an unconditional one, so a consumer released before its dependency asks
/// crates.io for a version that does not exist yet.
///
/// This row drives the whole protocol against tools that compile nothing, and
/// claims nothing about compilation — the indexed packaged-workspace proof owns
/// that. What it owns is the four documents between the release and the
/// archives: the order, the manifests the archives carry, the workspace those
/// archives are resolved in, and the caller's own repository.
#[test]
fn packaged_workspace_dependency_order_models_release_protocol() {
    release_cases::verify_dependency_ordered_release_protocol();
}

/// The packaged proof selects its warm budget and refuses every overrun.
#[test]
fn packaged_workspace_budget_selects_state_and_refuses_every_overrun() {
    budget_cases::verify_packaged_workspace_budgets();
}
