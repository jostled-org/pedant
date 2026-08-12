//! Refusals taken before a graph exists.
//!
//! The identity cases pair values a caller can hold at the same time. The
//! malformed cases use the core proof adapter, because the validated public
//! boundary binds every report unit by its stable key and cannot state a
//! resolution whose joins disagree with the snapshot it is handed.

use pedant_core::resolution::rust::{
    CargoTargetKind, resolution_with_shared_unit_binding, resolution_with_swapped_unit_sources,
    resolution_without_unit_binding,
};
use pedant_graph::{GraphBuildError, GraphLimits, build_rust_graph, build_rust_graph_with_limits};

use super::corpus::{GRAPH_CORPUS, IDENTICAL_SOURCE_CORPUS, MINIMAL_CORPUS, OTHER_ROOT_CORPUS};
use super::fixture::{self, Fixture};

/// The minimal corpus library after a source-only edit. Every manifest, path,
/// and target identity is unchanged; only the bytes differ.
const EDITED_SOURCE: &str = "pub fn run() { work(); }\npub fn work() { let _ = 1; }\n";

/// Both identity refusals precede every capacity check and every allocation.
///
/// The ceilings are zero, so a build that reached the first insertion would
/// return `CapacityExceeded` instead. Only a check taken before the projection
/// state exists can produce the identity refusals below.
pub fn assert_identity_refusals_dominate() {
    let zero = GraphLimits::new(0, 0, 0);
    let (_original, first) = fixture::resolve_library(MINIMAL_CORPUS);
    let (_other, other) = fixture::resolve_library(OTHER_ROOT_CORPUS);
    let mismatch = build_rust_graph_with_limits(&other.snapshot, &first.resolution, zero)
        .expect_err("a resolution for another root target is refused");
    assert!(
        matches!(mismatch, GraphBuildError::RootTargetMismatch),
        "unexpected refusal {mismatch:?}"
    );

    let mut edited = Fixture::build(MINIMAL_CORPUS);
    let before = edited.resolve_library();
    edited.rewrite("repo/src/lib.rs", EDITED_SOURCE);
    let after = edited.resolve_library();
    assert_eq!(
        after.snapshot.root_target(),
        before.snapshot.root_target(),
        "a source-only edit leaves the manifests and the target identity alone"
    );
    let stale = build_rust_graph_with_limits(&after.snapshot, &before.resolution, zero)
        .expect_err("a resolution taken before a source edit is refused");
    assert!(
        matches!(stale, GraphBuildError::SnapshotFingerprintMismatch),
        "unexpected refusal {stale:?}"
    );

    let admitted = build_rust_graph_with_limits(&first.snapshot, &first.resolution, zero)
        .expect_err("zero ceilings refuse a matching pairing too");
    assert!(
        matches!(admitted, GraphBuildError::CapacityExceeded { .. }),
        "the zero ceilings are not vacuous: a matching pairing reaches them, got {admitted:?}"
    );
}

/// Every malformed join the core proof adapter can state is refused with its
/// exact variant and payload, and none returns a partial graph.
pub fn assert_malformed_joins_refuse() {
    let corpus = Fixture::build(GRAPH_CORPUS);
    let resolved = corpus.resolve(corpus.target("app", CargoTargetKind::Library, "app"));
    let units = resolved.resolution.units().len();
    assert_eq!(units, 4, "the corpus binds four resolution units");

    let unbound = resolution_without_unit_binding(&resolved.resolution)
        .expect("four bindings leave one to drop");
    match build_rust_graph(&resolved.snapshot, &unbound) {
        Err(GraphBuildError::MissingUnitBinding { unit }) => assert_eq!(
            unit, 3,
            "the refusal names the report unit that lost its binding"
        ),
        other => panic!("an unbound report unit must be refused, got {other:?}"),
    }

    let swapped = resolution_with_swapped_unit_sources(&resolved.resolution)
        .expect("four bindings leave two to swap");
    match build_rust_graph(&resolved.snapshot, &swapped) {
        Err(GraphBuildError::MissingSourceNode { unit, path }) => assert_eq!(
            (unit, &*path),
            (0, "src/alpha.rs"),
            "the refusal names the unit and the source it does not instantiate"
        ),
        other => panic!("a site outside the bound unit must be refused, got {other:?}"),
    }

    let identical = Fixture::build(IDENTICAL_SOURCE_CORPUS);
    let shared = identical.resolve(identical.target("app", CargoTargetKind::Binary, "tool"));
    assert_eq!(
        shared.resolution.units().len(),
        2,
        "the identical-source corpus binds two units over one path"
    );
    let doubled = resolution_with_shared_unit_binding(&shared.resolution)
        .expect("two bindings leave two to share one snapshot unit");
    match build_rust_graph(&shared.snapshot, &doubled) {
        Err(GraphBuildError::SharedUnitBinding { held, unit }) => assert_eq!(
            (held, unit),
            (0, 1),
            "the refusal names the report unit holding the build unit and the one rebinding it"
        ),
        other => panic!("a doubled unit binding must be refused, got {other:?}"),
    }
}
