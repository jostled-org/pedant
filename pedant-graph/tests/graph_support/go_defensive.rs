//! Refusals a Go build takes before a graph exists, and the one input that
//! looks like another and must not be refused at all.
//!
//! Two kinds of input reach the refusal cases. A real repository, snapshotted
//! twice across a source-only edit, is what proves the pairing check; the same
//! repository under lowered ceilings is what proves each collection refuses
//! before it grows. Beside them sit reports a resolver would never write but
//! the validated public boundary still admits, because the claims they break
//! are the adapter's own and nothing below it would notice. Last comes a
//! repository the loader and the resolver both admit whose report carries a
//! definition with no holder: refusing it would be this module's failure mode
//! rather than its subject, so it is proved here beside the refusals it is
//! nearest to.

use std::sync::Arc;

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionSnapshot};
use pedant_graph::{
    CodeGraph, GraphBuildError, GraphCollection, GraphLimits, GraphNode, GraphNodeKind,
};
use pedant_types::{
    Language, ResolutionReport, ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier,
    SourcePosition, SourceSpan, SymbolDefinition, SymbolKind,
};

use super::go_corpus::{GO_CORPUS, GO_MINIMAL_CORPUS, GO_UNDECLARED_RECEIVER_CORPUS};
use super::go_fixture::{GoFixture, GoResolved, close_repository, project_go, refused, resolve_go};
use super::go_model::PACKAGE_LEVEL;
use super::go_topology::container_level;
use super::topology::containment_parents;

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
    close_repository(fixture);
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
    assert_the_pairing_dominates_every_ceiling(&current, &stale);
    let paired = pedant_graph::build_go_graph(&current.snapshot, &current.resolution)
        .unwrap_or_else(|error| panic!("the current pairing projects: {error}"));
    assert!(
        !paired.nodes().is_empty(),
        "the current pairing is the one that produces a graph"
    );
}

/// The stale pairing is refused whatever the ceilings are, so the identity
/// check is proved to run before the first record is admitted.
///
/// Every collection is held at zero. A build that reached the store at all
/// would refuse the first node by capacity, so a capacity refusal here would
/// mean the pairing was checked after something had already been allocated.
/// Winning against three zeroed ceilings is what "before allocation" means as
/// something a caller can observe.
fn assert_the_pairing_dominates_every_ceiling(current: &GoResolved, stale: &GoResolved) {
    let refusal = pedant_graph::build_go_graph_with_limits(
        &current.snapshot,
        &stale.resolution,
        GraphLimits::new(0, 0, 0),
    )
    .err()
    .unwrap_or_else(|| panic!("a stale resolution must not project at any ceiling"));
    assert!(
        matches!(refusal, GraphBuildError::SnapshotFingerprintMismatch),
        "the pairing is proved before the first record is admitted, not {refusal}"
    );
}

/// Every graph ceiling refuses the collection that reaches it first, and
/// returns no graph at all.
pub fn assert_limits_refuse_before_partial_records() {
    let (fixture, resolved) = resolve_go(GO_CORPUS);
    close_repository(fixture);
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
    let (tiny, minimal) = resolve_go(GO_MINIMAL_CORPUS);
    close_repository(tiny);
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
fn assert_refuses(resolved: &GoResolved, limits: GraphLimits, expected: GraphCollection) {
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
    let (fixture, resolved) = resolve_go(GO_MINIMAL_CORPUS);
    close_repository(fixture);
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

/// A method the report holds nowhere is projected at the receiver level, and
/// the repository it came from still builds a graph.
///
/// Go requires a method's receiver base type to be declared in the same
/// package, so a receiver the resolver cannot identify names a type the corpus
/// does not hold and the report states the method under no holder. The loader
/// and the resolver both admit that repository, so the projection has to draw
/// it: a method with no holder is still a receiver-level method, and reading it
/// as an interface's method, as a container, or as a kind this projection does
/// not name would turn an admitted repository into a graph that cannot be
/// built. Both sides are read — the report first, so a resolver that went back
/// to filing such a method under its package fails here rather than leaving the
/// graph claim proved against an input that no longer reaches it.
pub fn assert_holderless_method_projects_at_the_receiver_level() {
    let (resolved, graph) = project_go(GO_UNDECLARED_RECEIVER_CORPUS);
    assert_eq!(
        stated_method_claims(resolved.resolution.report()),
        "Drift|Method|no holder",
        "the resolver admits the repository and holds its one method nowhere"
    );
    assert_eq!(
        declared_as(&graph, "Drift"),
        "function:method",
        "a holderless method takes the receiver level, not the interface level"
    );
    assert_eq!(
        held_by(&graph, "Drift"),
        Some(PACKAGE_LEVEL),
        "the receiver-level node is rooted at the package that declares it"
    );
}

/// Every method claim one report states, as its name, kind, and holder.
fn stated_method_claims(report: &ResolutionReport) -> String {
    report
        .definitions()
        .iter()
        .filter(|definition| definition.kind() == SymbolKind::Method)
        .map(|definition| {
            format!(
                "{}|{:?}|{}",
                definition.name(),
                definition.kind(),
                holder_of(report, definition)
            )
        })
        .collect::<Vec<String>>()
        .join(" ")
}

/// The name of the definition one claim is held by, or that it is held by none.
fn holder_of(report: &ResolutionReport, definition: &SymbolDefinition) -> String {
    let held = definition
        .parent()
        .and_then(|parent| usize::try_from(parent.index()).ok())
        .and_then(|index| report.definitions().get(index))
        .map(SymbolDefinition::name);
    match held {
        Some(name) => name.to_owned(),
        None => "no holder".to_owned(),
    }
}

/// The category and token every graph node of one name states, in dense order.
fn declared_as(graph: &CodeGraph, name: &str) -> String {
    named_nodes(graph, name)
        .into_iter()
        .map(|node| match node.kind() {
            GraphNodeKind::File => "file".to_owned(),
            GraphNodeKind::Container { level } => format!("container:{level}"),
            GraphNodeKind::Function { declaration } => format!("function:{declaration}"),
            GraphNodeKind::Type { declaration } => format!("type:{declaration}"),
            GraphNodeKind::Value { declaration } => format!("value:{declaration}"),
        })
        .collect::<Vec<String>>()
        .join(" ")
}

/// The container level the sole node of one name sits beneath.
fn held_by<'graph>(graph: &'graph CodeGraph, name: &str) -> Option<&'graph str> {
    let parents = containment_parents(graph);
    let stated = named_nodes(graph, name);
    let [node] = stated.as_slice() else {
        panic!("the corpus declares {name} exactly once");
    };
    let parent = parents.get(&node.id())?;
    graph.node(*parent).and_then(container_level)
}

/// Every node of one name, in dense order.
fn named_nodes<'graph>(graph: &'graph CodeGraph, name: &str) -> Vec<&'graph GraphNode> {
    graph
        .nodes()
        .iter()
        .filter(|node| node.name() == name)
        .collect()
}
