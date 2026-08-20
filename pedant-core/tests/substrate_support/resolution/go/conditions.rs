//! Build predicates a snapshot retains without ever selecting a host.
//!
//! Every conditioned variant stays in the source universe and carries its
//! unevaluated predicate, so the model a resolver reads is the repository's
//! rather than this machine's. The rows are snapshotted twice under opposite
//! fixture-creation order, because a walk that leaked enumeration order into
//! its answer would otherwise pass.

use pedant_core::resolution::go::{GoProject, GoResolutionLimits};

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root};
use crate::resolution::go::snapshot_fixtures::BUILD_PREDICATES;
use crate::resolution::go::snapshot_views::{source_conditions, source_paths, units};
use crate::resolution::go::views::borrowed;

/// Every source [`BUILD_PREDICATES`] admits, in snapshot order.
const CONDITIONED_SOURCES: &[&str] = &[
    "base.go",
    "base_test.go",
    "bridge.go",
    "legacy.go",
    "plat_linux_arm64.go",
    "plat_windows.go",
    "tagged.go",
];

/// The predicates each of those sources carries.
const CONDITIONED_PREDICATES: &[&str] = &[
    "base.go|",
    "base_test.go|test",
    "bridge.go|foreign",
    "legacy.go|stated:legacy:darwin",
    "plat_linux_arm64.go|suffix:linux,suffix:arm64",
    "plat_windows.go|suffix:windows",
    "tagged.go|stated:directive:linux && !purego",
];

/// Both units the directory states, with every conditioned variant present in
/// each.
const CONDITIONED_UNITS: &[&str] = &[
    "example.com/build|production|example.com/build|build||base.go,bridge.go,legacy.go,plat_linux_arm64.go,plat_windows.go,tagged.go",
    "example.com/build|internal_test|example.com/build|build||base.go,base_test.go,bridge.go,legacy.go,plat_linux_arm64.go,plat_windows.go,tagged.go",
];

/// 4.T4 (Invariant 19): every build-conditioned source stays in the snapshot
/// with its unevaluated predicate, and neither the host nor the caller's
/// enumeration order changes what the snapshot holds.
#[test]
fn go_build_conditions_are_host_independent_possible_evidence() {
    for reversed in [false, true] {
        assert_conditioned_snapshot(BUILD_PREDICATES, reversed);
    }
}

fn assert_conditioned_snapshot(files: &[FixtureFile], reversed: bool) {
    let tree = build_repository(files, reversed);
    let project = GoProject::load(&repository_root(&tree), GoResolutionLimits::default())
        .expect("the fixture should load");
    let snapshot = project
        .snapshot_resolution()
        .expect("the fixture should snapshot");
    drop(project);

    assert_eq!(
        &*borrowed(&source_paths(&snapshot)),
        CONDITIONED_SOURCES,
        "reversed={reversed}: every conditioned variant stays in the source universe"
    );
    assert_eq!(
        &*borrowed(&source_conditions(&snapshot)),
        CONDITIONED_PREDICATES,
        "reversed={reversed}: every predicate is retained unevaluated"
    );
    assert_eq!(
        &*borrowed(&units(&snapshot)),
        CONDITIONED_UNITS,
        "reversed={reversed}: both package contexts hold every conditioned source"
    );
    drop(tree);
}
