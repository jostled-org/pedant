//! The public reading, identity, and lifecycle surface, exercised through the
//! published API alone.

use std::hash::Hash;

use pedant_graph::{
    CodeGraph, ContainmentEdge, GraphBuildError, GraphCollection, GraphEdge, GraphEdgeId,
    GraphEdgeKind, GraphEdgeOrigin, GraphLimits, GraphNode, GraphNodeId, GraphNodeKind,
    GraphNodeLocation, GraphReference, GraphReferenceId, GraphReferenceKind, build_rust_graph,
    build_rust_graph_with_limits,
};
use pedant_types::{Language, ResolutionGap, ResolutionTier, SourceSpan};
use serde::Serialize;

use super::corpus::MINIMAL_CORPUS;
use super::fixture;

/// One lowered ceiling and the refusal it must produce.
struct CapacityCase {
    label: &'static str,
    limits: GraphLimits,
    collection: GraphCollection,
    limit: u32,
}

/// Compile-time proof that a type carries the closed identity value semantics.
fn assert_identity_semantics<T: Copy + Eq + Ord + Hash + Serialize>() {}

/// Every specified accessor exists with its exact borrowed or value shape.
pub fn assert_reading_surface_is_complete() {
    let (_fixture, resolved) = fixture::resolve_library(MINIMAL_CORPUS);
    let graph: CodeGraph = build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .expect("the minimal corpus projects");

    let schema_version: u32 = graph.schema_version();
    let tier: ResolutionTier = graph.tier();
    let nodes: &[GraphNode] = graph.nodes();
    let containment: &[ContainmentEdge] = graph.containment();
    let references: &[GraphReference] = graph.references();
    let edges: &[GraphEdge] = graph.edges();
    assert_eq!(schema_version, 1);
    assert_eq!(tier, ResolutionTier::Syntactic);
    assert_eq!((nodes.len(), references.len(), edges.len()), (4, 1, 1));
    assert_eq!(containment.len(), 3);

    let node: &GraphNode = graph
        .node(nodes[2].id())
        .expect("a node identity selects its own node");
    let node_id: GraphNodeId = node.id();
    let node_language: Language = node.language();
    let node_name: &str = node.name();
    let node_kind: &GraphNodeKind = node.kind();
    let node_location: Option<&GraphNodeLocation> = node.location();
    assert_eq!(node_id.index(), 2);
    assert_eq!(node_language, Language::Rust);
    assert_eq!(node_name, "run");
    assert!(matches!(node_kind, GraphNodeKind::Function { .. }));
    assert!(matches!(
        node_location,
        Some(GraphNodeLocation::Span { .. })
    ));

    let parent: GraphNodeId = containment[0].parent();
    let child: GraphNodeId = containment[0].child();
    assert_eq!((parent.index(), child.index()), (0, 1));

    let reference: &GraphReference = graph
        .reference(references[0].id())
        .expect("a reference identity selects its own record");
    let reference_id: GraphReferenceId = reference.id();
    let reference_source: GraphNodeId = reference.source();
    let reference_language: Language = reference.language();
    let reference_kind: GraphReferenceKind = reference.kind();
    let reference_text: &str = reference.text();
    let reference_span: &SourceSpan = reference.span();
    let reference_gaps: &[ResolutionGap] = reference.gaps();
    let reference_edges: &[GraphEdgeId] = reference.edges();
    assert_eq!(reference_id.index(), 0);
    assert_eq!(reference_source.index(), 2);
    assert_eq!(reference_language, Language::Rust);
    assert_eq!(reference_kind, GraphReferenceKind::Call);
    assert_eq!(reference_text, "work");
    assert_eq!(reference_span.file(), "src/lib.rs");
    assert!(reference_gaps.is_empty());
    assert_eq!(reference_edges.len(), 1);

    let edge: &GraphEdge = graph
        .edge(edges[0].id())
        .expect("an edge identity selects its own edge");
    let edge_id: GraphEdgeId = edge.id();
    let edge_source: GraphNodeId = edge.source();
    let edge_target: GraphNodeId = edge.target();
    let edge_kind: GraphEdgeKind = edge.kind();
    let edge_origin: &GraphEdgeOrigin = edge.origin();
    assert_eq!(edge_id.index(), 0);
    assert_eq!((edge_source.index(), edge_target.index()), (2, 3));
    assert_eq!(edge_kind, GraphEdgeKind::Call);
    assert!(matches!(edge_origin, GraphEdgeOrigin::Reference { .. }));

    let limits = GraphLimits::new(7, 5, 3);
    let ceilings: (u32, u32, u32) = (
        limits.max_nodes(),
        limits.max_references(),
        limits.max_edges(),
    );
    assert_eq!(ceilings, (7, 5, 3));
}

/// Typed identities, default ceilings, the schema constant, and the equality of
/// ordinary and explicitly bounded construction.
pub fn assert_identity_defaults_and_schema() {
    assert_identity_semantics::<GraphNodeId>();
    assert_identity_semantics::<GraphReferenceId>();
    assert_identity_semantics::<GraphEdgeId>();

    let defaults = GraphLimits::default();
    assert_eq!(
        (
            defaults.max_nodes(),
            defaults.max_references(),
            defaults.max_edges()
        ),
        (u32::MAX, u32::MAX, u32::MAX),
        "every default ceiling is the fixed-width identity ceiling"
    );
    assert_eq!(CodeGraph::SCHEMA_VERSION, 1);

    let (_fixture, resolved) = fixture::resolve_library(MINIMAL_CORPUS);
    let ordinary = build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .expect("the ordinary builder projects");
    let bounded = build_rust_graph_with_limits(&resolved.snapshot, &resolved.resolution, defaults)
        .expect("the explicitly bounded builder projects");
    assert_eq!(
        ordinary, bounded,
        "the ordinary builder is the bounded builder at its defaults"
    );
    assert_eq!(ordinary.schema_version(), CodeGraph::SCHEMA_VERSION);
}

/// Identities are dense, languages are carried, and each lowered ceiling
/// refuses through the same production insertion path with no partial graph.
pub fn assert_dense_checked_and_atomic() {
    let (_fixture, resolved) = fixture::resolve_library(MINIMAL_CORPUS);
    let graph = build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .expect("the minimal corpus projects");

    for (position, node) in graph.nodes().iter().enumerate() {
        assert_eq!(node.id().index() as usize, position, "node ids are dense");
        assert_eq!(node.language(), Language::Rust, "every node carries Rust");
    }
    for (position, reference) in graph.references().iter().enumerate() {
        assert_eq!(
            reference.id().index() as usize,
            position,
            "reference ids are dense"
        );
        assert_eq!(reference.language(), Language::Rust);
    }
    for (position, edge) in graph.edges().iter().enumerate() {
        assert_eq!(edge.id().index() as usize, position, "edge ids are dense");
    }

    let exact = build_rust_graph_with_limits(
        &resolved.snapshot,
        &resolved.resolution,
        GraphLimits::new(4, 1, 1),
    )
    .expect("ceilings equal to the produced counts admit the whole graph");
    assert_eq!(
        exact, graph,
        "an exactly sufficient ceiling changes nothing"
    );

    for case in capacity_cases() {
        let refused =
            build_rust_graph_with_limits(&resolved.snapshot, &resolved.resolution, case.limits)
                .err()
                .unwrap_or_else(|| panic!("{}: the lowered ceiling was admitted", case.label));
        match refused {
            GraphBuildError::CapacityExceeded { collection, limit } => {
                assert_eq!(
                    (collection, limit),
                    (case.collection, case.limit),
                    "{}: the refusal must name its own collection and ceiling",
                    case.label
                );
            }
            other => panic!("{}: unexpected refusal {other:?}", case.label),
        }
    }
}

fn capacity_cases() -> [CapacityCase; 3] {
    [
        CapacityCase {
            label: "nodes",
            limits: GraphLimits::new(3, u32::MAX, u32::MAX),
            collection: GraphCollection::Node,
            limit: 3,
        },
        CapacityCase {
            label: "references",
            limits: GraphLimits::new(u32::MAX, 0, u32::MAX),
            collection: GraphCollection::Reference,
            limit: 0,
        },
        CapacityCase {
            label: "edges",
            limits: GraphLimits::new(u32::MAX, u32::MAX, 0),
            collection: GraphCollection::Edge,
            limit: 0,
        },
    ]
}
