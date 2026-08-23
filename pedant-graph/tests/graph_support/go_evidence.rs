//! Go reference records, candidate edges, and dependency evidence.
//!
//! What a report answered is what the graph carries: the same records, in the
//! same order, with the same certainty and the same gaps. Every expectation is
//! read out of the report beside the graph, so the corpus can grow a site
//! without the case being rewritten, and the few claims the corpus exists to
//! make — an external record with no candidate, a conversion that is not a
//! call, an always-possible interface dispatch, and a proven implementation —
//! are stated on top of it.

use pedant_graph::{
    CodeGraph, GraphCertainty, GraphDependencyKind, GraphEdgeKind, GraphEdgeOrigin,
    GraphReferenceKind,
};
use pedant_types::{ReferenceKind, ResolutionCertainty, ResolutionGap, SymbolReference};

use super::go_corpus::GO_CORPUS;
use super::go_fixture::project_go;
use super::go_model::MODULE_LEVEL;
use super::go_topology::containers;

/// The main module this corpus is rooted at.
const ROOT_MODULE: &str = "example.com/app";

/// The one local replacement it requires and admits.
const LOCAL_MODULE: &str = "example.com/helper";

/// The one requirement it leaves external, which reads nothing and adds no
/// node.
const EXTERNAL_MODULE: &str = "github.com/external/pkg";

/// One graph reference per report reference, one edge per candidate, and exact
/// certainty and gaps throughout.
pub fn assert_every_reference_candidate_certainty_and_gap_is_copied() {
    let (resolved, graph) = project_go(GO_CORPUS);
    let report = resolved.resolution.report();
    assert_eq!(
        graph.references().len(),
        report.references().len(),
        "every report reference produces one graph reference"
    );
    assert_eq!(
        graph.references().len(),
        report.resolutions().len(),
        "every graph reference answers for one resolution record"
    );

    let mut candidates: usize = 0;
    for (index, (reference, record)) in report
        .references()
        .iter()
        .zip(report.resolutions())
        .enumerate()
    {
        let held = graph
            .references()
            .get(index)
            .unwrap_or_else(|| panic!("reference {index} has a graph record"));
        assert_eq!(held.kind(), denoted(reference.kind()), "reference {index}");
        assert_eq!(held.text(), reference.text(), "reference {index}");
        assert_eq!(
            held.span(),
            SymbolReference::span(reference),
            "reference {index}"
        );
        assert_eq!(held.gaps(), record.gaps(), "reference {index}");
        assert_eq!(
            held.edges().len(),
            record.candidates().len(),
            "reference {index} produces one edge per candidate"
        );
        for (edge, candidate) in held.edges().iter().zip(record.candidates()) {
            let stated = graph
                .edge(*edge)
                .unwrap_or_else(|| panic!("reference {index} names an edge the graph holds"));
            assert_eq!(
                stated.certainty(),
                known(candidate.certainty()),
                "reference {index} copies its candidate's certainty"
            );
            assert_eq!(
                stated.origin(),
                &GraphEdgeOrigin::Reference {
                    reference: held.id()
                },
                "reference {index} owns the edge it produced"
            );
            candidates = candidates.saturating_add(1);
        }
    }
    assert!(
        candidates > 0,
        "the corpus states candidates for this case to copy"
    );
    assert_external_records_are_candidate_free(&graph);
    assert_conversions_produce_no_call_edge(&graph);
    assert_interface_dispatch_is_only_possible(&graph);
    assert_implementations_are_resolved(&graph);
}

/// What one Go reference kind denotes at the graph layer.
fn denoted(kind: ReferenceKind) -> GraphReferenceKind {
    match kind {
        ReferenceKind::Call => GraphReferenceKind::Call,
        ReferenceKind::Import => GraphReferenceKind::Import,
        ReferenceKind::Implementation => GraphReferenceKind::Implementation,
        ReferenceKind::Type | ReferenceKind::Value => GraphReferenceKind::Reference,
        ReferenceKind::Module => panic!("a Go report states no module reference"),
    }
}

/// How much one answered candidate is known.
fn known(certainty: ResolutionCertainty) -> GraphCertainty {
    match certainty {
        ResolutionCertainty::Resolved => GraphCertainty::Resolved,
        ResolutionCertainty::Possible => GraphCertainty::Possible,
    }
}

/// A record whose target is outside the snapshot keeps its gap and offers no
/// candidate, and no node is fabricated for it.
fn assert_external_records_are_candidate_free(graph: &CodeGraph) {
    let external: Vec<&pedant_graph::GraphReference> = graph
        .references()
        .iter()
        .filter(|held| held.gaps().contains(&ResolutionGap::ExternalDefinition))
        .collect();
    assert!(
        !external.is_empty(),
        "the corpus states a reference to a definition outside the snapshot"
    );
    for held in external {
        assert!(
            held.edges().is_empty(),
            "external record {} offers no candidate",
            held.id().index()
        );
    }
}

/// A conversion writes a call site's syntax and produces no call edge.
fn assert_conversions_produce_no_call_edge(graph: &CodeGraph) {
    let converted: Vec<&pedant_graph::GraphReference> = graph
        .references()
        .iter()
        .filter(|held| held.kind() == GraphReferenceKind::Call && held.text() == "int")
        .collect();
    assert!(
        !converted.is_empty(),
        "the corpus writes a conversion at a call site"
    );
    for held in converted {
        assert!(
            held.edges().is_empty(),
            "conversion {} produces no call edge",
            held.id().index()
        );
    }
    let named: Vec<&pedant_graph::GraphReference> = graph
        .references()
        .iter()
        .filter(|held| held.text() == "Size")
        .collect();
    assert!(
        !named.is_empty(),
        "the corpus converts through a defined type as well"
    );
    for held in named {
        assert_ne!(
            held.kind(),
            GraphReferenceKind::Call,
            "converting through {} is a reference, not a call",
            held.text()
        );
    }
}

/// Every candidate of a dynamically dispatched call stays possible.
fn assert_interface_dispatch_is_only_possible(graph: &CodeGraph) {
    let dispatched: Vec<&pedant_graph::GraphReference> = graph
        .references()
        .iter()
        .filter(|held| held.gaps().contains(&ResolutionGap::DynamicDispatch))
        .collect();
    assert!(
        !dispatched.is_empty(),
        "the corpus dispatches a call through an interface value"
    );
    for held in dispatched {
        assert!(
            !held.edges().is_empty(),
            "interface dispatch {} offers the candidates it found",
            held.id().index()
        );
        for edge in held.edges() {
            let stated = graph.edge(*edge).expect("a named edge exists");
            assert_eq!(
                stated.certainty(),
                GraphCertainty::Possible,
                "interface dispatch is never resolved"
            );
        }
    }
}

/// A proven structural implementation is one resolved implementation edge.
fn assert_implementations_are_resolved(graph: &CodeGraph) {
    let implemented: Vec<&pedant_graph::GraphEdge> = graph
        .edges()
        .iter()
        .filter(|edge| edge.kind() == GraphEdgeKind::Implementation)
        .collect();
    assert!(
        !implemented.is_empty(),
        "the corpus proves a concrete type implements an interface"
    );
    for edge in implemented {
        assert_eq!(
            edge.certainty(),
            GraphCertainty::Resolved,
            "a proven implementation is resolved"
        );
        assert_eq!(
            graph.node(edge.source()).map(|node| node.name()),
            Some("Widget"),
            "the concrete type is the source of the implementation edge"
        );
        assert_eq!(
            graph.node(edge.target()).map(|node| node.name()),
            Some("Shape"),
            "the interface is its target"
        );
    }
}

/// One admitted local replacement is one resolved `DependsOn` edge between
/// module containers, and an unreplaced requirement is nothing at all.
pub fn assert_local_replacement_projects_one_dependency_edge() {
    let (resolved, graph) = project_go(GO_CORPUS);
    let modules: Vec<&str> = containers(&graph, MODULE_LEVEL)
        .iter()
        .map(|node| node.name())
        .collect();
    assert_eq!(
        modules,
        vec![ROOT_MODULE, LOCAL_MODULE],
        "the admitted modules are the main module and its local replacement"
    );
    assert!(
        !graph
            .nodes()
            .iter()
            .any(|node| node.name() == EXTERNAL_MODULE),
        "an unreplaced external requirement produces no placeholder node"
    );

    let dependencies: Vec<&pedant_graph::GraphEdge> = graph
        .edges()
        .iter()
        .filter(|edge| edge.kind() == GraphEdgeKind::DependsOn)
        .collect();
    let [edge] = dependencies.as_slice() else {
        panic!("the corpus states one dependency edge, not {dependencies:?}");
    };
    assert_eq!(
        resolved.snapshot.edges().len(),
        1,
        "the snapshot states the one local edge the graph carries"
    );
    assert_eq!(edge.certainty(), GraphCertainty::Resolved);
    assert_eq!(
        graph.node(edge.source()).map(|node| node.name()),
        Some(ROOT_MODULE),
        "the requiring module is the source"
    );
    assert_eq!(
        graph.node(edge.target()).map(|node| node.name()),
        Some(LOCAL_MODULE),
        "the replacement it resolved to is the target"
    );
    let GraphEdgeOrigin::Dependency { evidence } = edge.origin() else {
        panic!("a dependency edge carries its declaration as evidence");
    };
    assert_eq!(evidence.alias(), LOCAL_MODULE);
    assert_eq!(evidence.kind(), GraphDependencyKind::Normal);
    assert_eq!(evidence.predicate(), None);
}
