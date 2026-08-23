//! Refusals a Go build takes before a graph exists.
//!
//! Two kinds of input reach these cases. A real repository, snapshotted twice
//! across a source-only edit, is what proves the pairing check; the same
//! repository under lowered ceilings is what proves each collection refuses
//! before it grows. Beside them sit reports a resolver would never write but
//! the validated public boundary still admits, because the claims they break
//! are the adapter's own and nothing below it would notice.

use std::sync::Arc;

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionSnapshot};
use pedant_graph::{GraphBuildError, GraphCollection, GraphLimits};
use pedant_types::{
    Language, ResolutionReport, ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier,
    SourcePosition, SourceSpan, SymbolKind,
};

use super::go_corpus::{GO_CORPUS, GO_MINIMAL_CORPUS};
use super::go_fixture::{GoFixture, refused, resolve_go};

/// The source-only edit that changes the bytes and no manifest.
const REVISED_BUILD: &str = r#"package app

func Build() int {
	return 7
}
"#;

/// A resolution taken before a source-only edit is refused against the snapshot
/// taken after it, and no graph record is allocated.
pub fn assert_stale_resolution_is_refused() {
    let fixture = GoFixture::build(GO_CORPUS);
    let stale = fixture.resolve();
    fixture.rewrite("repo/build.go", REVISED_BUILD);
    let current = fixture.resolve();
    assert_ne!(
        stale.snapshot.fingerprint(),
        current.snapshot.fingerprint(),
        "a source-only edit produces another snapshot"
    );

    let refusal = pedant_graph::build_go_graph(&current.snapshot, &stale.resolution)
        .err()
        .unwrap_or_else(|| panic!("a stale resolution must not project"));
    assert!(
        matches!(refusal, GraphBuildError::SnapshotFingerprintMismatch),
        "a stale pairing is refused by identity: {refusal}"
    );
    let paired = pedant_graph::build_go_graph(&current.snapshot, &current.resolution)
        .unwrap_or_else(|error| panic!("the current pairing projects: {error}"));
    assert!(
        !paired.nodes().is_empty(),
        "the current pairing is the one that produces a graph"
    );
}

/// Every graph ceiling refuses the collection that reaches it first, and
/// returns no graph at all.
pub fn assert_limits_refuse_before_partial_records() {
    let (_fixture, resolved) = resolve_go(GO_CORPUS);
    let full = pedant_graph::build_go_graph(&resolved.snapshot, &resolved.resolution)
        .unwrap_or_else(|error| panic!("the unbounded build projects: {error}"));
    let counts = [
        (
            GraphCollection::Node,
            full.nodes().len(),
            GraphLimits::new(0, u32::MAX, u32::MAX),
        ),
        (
            GraphCollection::Reference,
            full.references().len(),
            GraphLimits::new(u32::MAX, 0, u32::MAX),
        ),
        (
            GraphCollection::Edge,
            full.edges().len(),
            GraphLimits::new(u32::MAX, u32::MAX, 0),
        ),
    ];
    for (collection, held, zero) in counts {
        assert!(held > 1, "{collection} holds records to refuse");
        assert_refuses(&resolved, zero, collection);
        assert_refuses(&resolved, one_short(collection, held), collection);
    }
    let (_tiny, minimal) = resolve_go(GO_MINIMAL_CORPUS);
    assert_refuses(
        &minimal,
        GraphLimits::new(1, u32::MAX, u32::MAX),
        GraphCollection::Node,
    );
    assert_malformed_claims_refuse();
}

/// The ceilings that admit every collection but one, one record short.
fn one_short(collection: GraphCollection, held: usize) -> GraphLimits {
    let ceiling = u32::try_from(held.saturating_sub(1)).unwrap_or(u32::MAX);
    match collection {
        GraphCollection::Node => GraphLimits::new(ceiling, u32::MAX, u32::MAX),
        GraphCollection::Reference => GraphLimits::new(u32::MAX, ceiling, u32::MAX),
        GraphCollection::Edge => GraphLimits::new(u32::MAX, u32::MAX, ceiling),
    }
}

/// One bounded build refuses the named collection at the ceiling it was given.
fn assert_refuses(
    resolved: &super::go_fixture::GoResolved,
    limits: GraphLimits,
    expected: GraphCollection,
) {
    match refused(resolved, limits) {
        GraphBuildError::CapacityExceeded { collection, limit } => {
            assert_eq!(
                collection, expected,
                "the refusal names the bounded collection"
            );
            assert_eq!(
                limit,
                stated_ceiling(limits, expected),
                "the refusal names the ceiling it was given"
            );
        }
        other => panic!("a lowered {expected} ceiling refuses by capacity, not {other}"),
    }
}

/// The ceiling one set of limits states for one collection.
fn stated_ceiling(limits: GraphLimits, collection: GraphCollection) -> u32 {
    match collection {
        GraphCollection::Node => limits.max_nodes(),
        GraphCollection::Reference => limits.max_references(),
        GraphCollection::Edge => limits.max_edges(),
    }
}

/// A report the public boundary admits but the adapter's own claims reject.
///
/// `GoProjectResolution` proves units, kinds, and coordinates; it does not
/// prove that each package context opened exactly one package. A report with
/// none and a report with two are therefore reachable, and each must refuse
/// rather than root a unit at nothing or at two nodes.
fn assert_malformed_claims_refuse() {
    let (_fixture, resolved) = resolve_go(GO_MINIMAL_CORPUS);
    let absent = claimed(&resolved.snapshot, &[SymbolKind::Function]);
    assert!(
        matches!(
            pedant_graph::build_go_graph(&resolved.snapshot, &absent),
            Err(GraphBuildError::MissingUnitDeclaration { unit: 0 })
        ),
        "a unit whose report opens no package is rooted at nothing"
    );
    let doubled = claimed(
        &resolved.snapshot,
        &[SymbolKind::Package, SymbolKind::Package],
    );
    assert!(
        matches!(
            pedant_graph::build_go_graph(&resolved.snapshot, &doubled),
            Err(GraphBuildError::RepeatedUnitDeclaration { unit: 0 })
        ),
        "a unit whose report opens two packages would take two roots"
    );
}

/// A range inside the package clause of one source, which every draft here
/// states its definitions at.
fn package_clause(path: &Arc<str>) -> SourceSpan {
    SourceSpan::new(
        Arc::clone(path),
        SourcePosition::new(0, 8),
        SourcePosition::new(0, 12),
    )
}

/// One validated resolution over `snapshot`'s sole unit, stating exactly the
/// definition kinds asked for.
fn claimed(snapshot: &GoResolutionSnapshot, kinds: &[SymbolKind]) -> GoProjectResolution {
    let report = drafted(snapshot, kinds);
    GoProjectResolution::try_new(snapshot, report)
        .unwrap_or_else(|error| panic!("the public boundary admits this report: {error}"))
}

/// The report itself, written against the one unit and source the snapshot has.
fn drafted(snapshot: &GoResolutionSnapshot, kinds: &[SymbolKind]) -> ResolutionReport {
    let [unit] = snapshot.units() else {
        panic!("the minimal corpus states exactly one package context");
    };
    let [path] = unit.sources() else {
        panic!("the minimal corpus states exactly one source");
    };
    let mut builder =
        ResolutionReportBuilder::new(ResolutionTier::Syntactic, ResolutionReportLimits::default());
    let handle = builder
        .add_unit(
            Language::Go,
            Arc::from(format!("{}#{}", unit.import_path(), unit.context().token())),
            Arc::from(unit.import_path()),
        )
        .unwrap_or_else(|error| panic!("the draft states one unit: {error}"));
    for (index, kind) in kinds.iter().enumerate() {
        builder
            .add_definition(
                &handle,
                *kind,
                Arc::from(format!("claim{index}")),
                package_clause(path),
                None,
            )
            .unwrap_or_else(|error| panic!("the draft states one definition: {error}"));
    }
    builder
        .finish()
        .unwrap_or_else(|error| panic!("the draft is a valid report: {error}"))
}
