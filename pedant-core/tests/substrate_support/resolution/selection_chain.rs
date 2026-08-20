//! Dependency-selection ancestry behavior and structural-work proofs.

use pedant_core::resolution::ResolutionProbe;
use pedant_core::resolution::rust::{
    ClosureSite, ResolutionLimit, ResolutionLimits, RustSnapshotError, SourceClosureFailure,
    SourceClosureFailureKind,
};

use crate::resolution::fixture;
use crate::resolution::selection_chain_fixtures::BRANCHING_DEEP_CHAIN;
use crate::resolution::unit_fixtures::DEPENDENCY_CYCLE;
use crate::resolution::views::app_library;

const TRAVERSED_EDGES: u64 = 8;

#[test]
fn branching_deep_selection_extends_once_per_edge_without_copying_history() {
    let root = fixture::build_repository(BRANCHING_DEEP_CHAIN, false);
    let project = fixture::load_default(&root);
    let probe = ResolutionProbe::install();

    project
        .snapshot_resolution(app_library(&project))
        .expect("both four-edge branches should resolve");

    assert_eq!(
        probe.dependency_chain_extensions(),
        TRAVERSED_EDGES,
        "every traversed edge must extend exactly one ancestry link",
    );
    assert_eq!(
        probe.dependency_chain_history_copies(),
        0,
        "an extension must retain its parent rather than copy prior entries",
    );
}

#[test]
fn a_cycle_precedes_the_depth_refusal_and_keeps_ordered_evidence() {
    let root = fixture::build_repository(DEPENDENCY_CYCLE, false);
    let project = fixture::load_project(
        &root,
        ResolutionLimits {
            max_dependency_depth: 2,
            ..ResolutionLimits::default()
        },
    )
    .expect("the cyclic project should index");
    let error = project
        .snapshot_resolution(app_library(&project))
        .expect_err("the repeated package should refuse selection before the depth limit");
    let failure = only_failure(&error);

    assert_eq!(failure.kind(), SourceClosureFailureKind::DependencyCycle);
    assert_eq!(
        failure.site(),
        &ClosureSite::Dependency {
            package: Box::from("second"),
            dependency: Box::from("first"),
        },
    );
    assert_eq!(
        failure.message(),
        "the dependency chain app -> first -> second -> first repeats a package",
    );
}

#[test]
fn dependency_depth_accepts_the_ceiling_and_refuses_the_next_edge() {
    let root = fixture::build_repository(BRANCHING_DEEP_CHAIN, false);
    let project = fixture::load_project(
        &root,
        ResolutionLimits {
            max_dependency_depth: 3,
            ..ResolutionLimits::default()
        },
    )
    .expect("the branching project should index");
    let error = project
        .snapshot_resolution(app_library(&project))
        .expect_err("a dependency four edges below the root exceeds a ceiling of three");
    let failure = only_failure(&error);

    assert_eq!(
        failure.kind(),
        SourceClosureFailureKind::LimitExceeded(ResolutionLimit::DependencyDepth),
    );
    assert_eq!(
        failure.message(),
        "the configured max_dependency_depth ceiling of 3 is exceeded",
    );
}

fn only_failure(error: &RustSnapshotError) -> &SourceClosureFailure {
    let RustSnapshotError::SourceClosure(closure) = error else {
        panic!("expected a source-closure error, got {error:?}");
    };
    let [failure] = closure.failures() else {
        panic!("expected one failure, got {:?}", closure.failures());
    };
    failure
}
