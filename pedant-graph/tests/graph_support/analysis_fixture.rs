//! Real workspaces, shared graph lookups, analysis views, and comparable text.
//!
//! The lookups here are the one place a case turns a name into an identity, so
//! the predecessor topology cases and the analysis cases ask the same question
//! the same way.
//!
//! Every case here projects a temporary Cargo repository through the production
//! loader, snapshot, resolver, and graph builder. The repository is released
//! before the graph is handed back: a projected graph owns every value it
//! answers with, which `rust_graph_builds_and_serializes_after_fixture_teardown`
//! proves separately, so no analysis case keeps a directory alive while it
//! asserts.

use pedant_core::resolution::rust::CargoTargetKind;
use pedant_graph::{
    BetweennessCentrality, BoundaryCrossingComponent, CodeGraph, CondensationEdge,
    DegreeCentrality, GraphAnalysis, GraphAnalysisLimits, GraphCertainty, GraphComponent,
    GraphComponents, GraphEdgeId, GraphEdgeKind, GraphEdgeSelection, GraphNeighbor, GraphNode,
    GraphNodeId, GraphNodeLocation, LayoutEdgeMetadata, LayoutNodeMetadata, MisplacementCandidate,
    ModuleCohesion,
};

use super::corpus_analysis::{
    ANALYSIS_COMPONENT_CORPUS, ANALYSIS_DIVERGENCE_CORPUS, ANALYSIS_PARTITION_CORPUS,
    ANALYSIS_TRAVERSAL_CORPUS,
};
use super::corpus_generated::GeneratedFile;
use super::fixture;
use super::render;

/// The library root every analysis corpus declares.
///
/// Named rather than taken as the sole library, because a corpus that states a
/// package dependency declares a second one and the case under test is always
/// the graph of this root.
const ANALYSIS_LIBRARY: fixture::DeclaredTarget = ("app", CargoTargetKind::Library, "app");

/// The graph one analysis corpus projects, with its repository released.
pub fn graph_of(files: &[(&str, &str)]) -> CodeGraph {
    let (directory, _, graph) = fixture::project_target(files, ANALYSIS_LIBRARY);
    drop(directory);
    graph
}

/// The graph one generated single-package corpus projects.
///
/// The one place a generated corpus is borrowed for materialization, so a case
/// that states its repository as a rule reaches the same production loader,
/// snapshot, resolver, and builder every written corpus does.
pub fn generated_graph(files: &[GeneratedFile]) -> CodeGraph {
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, contents)| (*path, contents.as_str()))
        .collect();
    graph_of(&borrowed)
}

/// The diamond, cycle, self-loop, and parallel-evidence call graph.
pub fn traversal_graph() -> CodeGraph {
    graph_of(ANALYSIS_TRAVERSAL_CORPUS)
}

/// The isolate, self-loop, two-node cycle, and parallel-crossing call graph.
pub fn component_graph() -> CodeGraph {
    graph_of(ANALYSIS_COMPONENT_CORPUS)
}

/// The nested inline and external module graph.
pub fn partition_graph() -> CodeGraph {
    graph_of(ANALYSIS_PARTITION_CORPUS)
}

/// The nested-module graph whose calls cross partitions in both directions.
pub fn divergence_graph() -> CodeGraph {
    graph_of(ANALYSIS_DIVERGENCE_CORPUS)
}

/// The mixed-edge graph: calls, imports, implementations, references, and
/// resolved and possible build-unit dependencies.
pub fn selection_graph() -> CodeGraph {
    let (directory, _, graph) = fixture::project_corpus_library();
    drop(directory);
    graph
}

/// Ceilings no admitted Step 1 case reaches.
pub fn generous_limits() -> GraphAnalysisLimits {
    GraphAnalysisLimits::new(u32::MAX, u32::MAX, u32::MAX, u64::MAX)
}

/// One analysis over `graph` at `selection`, bounded only by the ceilings no
/// case reaches.
pub fn analysis(graph: &CodeGraph, selection: GraphEdgeSelection) -> GraphAnalysis<'_> {
    GraphAnalysis::new(graph, selection, generous_limits())
        .unwrap_or_else(|error| panic!("the fixture graph should admit an analysis: {error}"))
}

/// The selection admitting call edges alone, at both certainties.
pub fn calls_only() -> GraphEdgeSelection {
    GraphEdgeSelection::new(
        &[GraphEdgeKind::Call],
        &[GraphCertainty::Resolved, GraphCertainty::Possible],
    )
}

/// The one definition node named `name`.
pub fn definition(graph: &CodeGraph, name: &str) -> GraphNodeId {
    sole(
        selected_nodes(graph, |node| {
            node.name() == name && render::is_definition(node)
        }),
        name,
    )
}

/// The one file node instantiating `path`.
pub fn file_node(graph: &CodeGraph, path: &str) -> GraphNodeId {
    sole(
        selected_nodes(graph, |node| render::file_path(node) == Some(path)),
        path,
    )
}

/// The one unit root container, for a corpus that states exactly one.
pub fn unit_root(graph: &CodeGraph) -> GraphNodeId {
    sole(
        selected_nodes(graph, |node| node.location().is_none()),
        "the unit root",
    )
}

/// The unit root container one build unit is named by.
pub fn unit_container(graph: &CodeGraph, name: &str) -> GraphNodeId {
    sole(
        selected_nodes(graph, |node| {
            node.location().is_none() && node.name() == name
        }),
        name,
    )
}

/// One node identity minted by a larger graph, which `graph` holds no record
/// for.
pub fn foreign_node(graph: &CodeGraph) -> GraphNodeId {
    let other = selection_graph();
    let last = other
        .nodes()
        .last()
        .expect("the mixed-edge corpus states nodes")
        .id();
    assert!(
        last.index() as usize >= graph.nodes().len(),
        "the foreign identity must address no node of the graph under test"
    );
    last
}

/// Every node one predicate admits.
fn selected_nodes(graph: &CodeGraph, admits: impl Fn(&GraphNode) -> bool) -> Vec<GraphNodeId> {
    graph
        .nodes()
        .iter()
        .filter(|node| admits(node))
        .map(|node| node.id())
        .collect()
}

/// The one node a lookup admitted, or a failure naming what it looked for.
fn sole(found: Vec<GraphNodeId>, subject: &str) -> GraphNodeId {
    match found.as_slice() {
        [only] => *only,
        other => panic!("the corpus states {} nodes for {subject}", other.len()),
    }
}

/// The file node one span-located node's bytes sit in.
pub fn span_file(graph: &CodeGraph, node: GraphNodeId) -> GraphNodeId {
    match graph.node(node).and_then(|found| found.location()) {
        Some(GraphNodeLocation::Span { file, .. }) => *file,
        other => panic!("node {} has no span location: {other:?}", node.index()),
    }
}

/// One node's declared name.
pub fn name(graph: &CodeGraph, node: GraphNodeId) -> String {
    graph
        .node(node)
        .map(|found| found.name().to_owned())
        .unwrap_or_else(|| panic!("node {} is not in this graph", node.index()))
}

/// Every named node, in the order supplied.
pub fn names(graph: &CodeGraph, nodes: &[GraphNodeId]) -> Vec<String> {
    nodes.iter().map(|node| name(graph, *node)).collect()
}

/// One edge as `source>target|kind|certainty`, by node name.
pub fn edge_text(graph: &CodeGraph, edge: GraphEdgeId) -> String {
    let found = graph
        .edge(edge)
        .unwrap_or_else(|| panic!("edge {} is not in this graph", edge.index()));
    format!(
        "{}>{}|{:?}|{:?}",
        name(graph, found.source()),
        name(graph, found.target()),
        found.kind(),
        found.certainty(),
    )
}

/// Every named edge, in the order supplied.
pub fn edge_texts(graph: &CodeGraph, edges: &[GraphEdgeId]) -> Vec<String> {
    edges.iter().map(|edge| edge_text(graph, *edge)).collect()
}

/// Every neighbor as `name:distance`, in the order supplied.
pub fn neighbor_texts(graph: &CodeGraph, neighbors: &[GraphNeighbor]) -> Vec<String> {
    neighbors
        .iter()
        .map(|neighbor| format!("{}:{}", name(graph, neighbor.node()), neighbor.distance()))
        .collect()
}

/// Every edge id the stated kinds and certainties admit, in raw id order.
///
/// Written as two slice memberships rather than as a mask, so the expectation
/// every selection case compares against is an independent statement of the
/// same Cartesian rule rather than a second call into the type under test.
pub fn admitted_ids(
    graph: &CodeGraph,
    kinds: &[GraphEdgeKind],
    certainties: &[GraphCertainty],
) -> Vec<GraphEdgeId> {
    graph
        .edges()
        .iter()
        .filter(|edge| kinds.contains(&edge.kind()) && certainties.contains(&edge.certainty()))
        .map(|edge| edge.id())
        .collect()
}

/// Every selected edge id between one ordered node pair, in raw id order.
pub fn admitted_between(
    graph: &CodeGraph,
    selection: GraphEdgeSelection,
    pair: (GraphNodeId, GraphNodeId),
) -> Vec<GraphEdgeId> {
    let (source, target) = pair;
    graph
        .edges()
        .iter()
        .filter(|edge| selection.allows(edge) && edge.source() == source && edge.target() == target)
        .map(|edge| edge.id())
        .collect()
}

/// Every degree record as `name|incoming|outgoing`, in the order supplied.
pub fn degree_texts(graph: &CodeGraph, degrees: &[DegreeCentrality]) -> Vec<String> {
    degrees
        .iter()
        .map(|record| {
            format!(
                "{}|{}|{}",
                name(graph, record.node()),
                record.incoming(),
                record.outgoing()
            )
        })
        .collect()
}

/// One score as its exact bit pattern.
///
/// A determinism case compares repeated runs bit for bit, and a rounded
/// rendering would hide the one difference it exists to catch.
pub fn bits(score: f64) -> String {
    format!("{:016x}", score.to_bits())
}

/// One optional score as its exact bit pattern, or as the absence of one.
pub fn optional_bits(score: Option<f64>) -> String {
    match score {
        Some(value) => bits(value),
        None => "none".to_owned(),
    }
}

/// Every betweenness record as `name|raw|normalized`, with both scores written
/// as their exact bit patterns.
pub fn betweenness_texts(graph: &CodeGraph, scores: &[BetweennessCentrality]) -> Vec<String> {
    scores
        .iter()
        .map(|record| {
            format!(
                "{}|{}|{}",
                name(graph, record.node()),
                bits(record.raw()),
                bits(record.normalized())
            )
        })
        .collect()
}

/// Every cohesion record as `root|internal|boundary|score`, in the order
/// supplied.
pub fn cohesion_texts(graph: &CodeGraph, cohesion: &[ModuleCohesion]) -> Vec<String> {
    cohesion
        .iter()
        .map(|record| {
            format!(
                "{}|{}|{}|{}",
                name(graph, record.root()),
                record.internal_edges(),
                record.boundary_edges(),
                optional_bits(record.score())
            )
        })
        .collect()
}

/// Every affinity record as `symbol>candidate|declared|k|n|ratio`, in the order
/// supplied.
pub fn candidate_texts(graph: &CodeGraph, candidates: &[MisplacementCandidate]) -> Vec<String> {
    candidates
        .iter()
        .map(|record| {
            format!(
                "{}>{}|{}|{}|{}|{}",
                name(graph, record.symbol()),
                name(graph, record.candidate_partition()),
                name(graph, record.declared_partition()),
                record.foreign_edges(),
                record.total_outgoing_edges(),
                bits(record.affinity())
            )
        })
        .collect()
}

/// Every boundary-crossing component as `members|partitions`, both named and
/// sorted.
///
/// Which member a cycle lists first is decided by the identities the builder
/// minted; that a cycle holds exactly these members, declared in exactly these
/// partitions, is the fact this rendering carries. The stored orders themselves
/// are proved by the component and cohesion cases.
pub fn boundary_texts(
    graph: &CodeGraph,
    components: &GraphComponents,
    crossing: &[BoundaryCrossingComponent],
) -> Vec<String> {
    crossing
        .iter()
        .map(|record| {
            let held = components
                .component(record.component())
                .unwrap_or_else(|| panic!("no component {}", record.component().index()));
            format!(
                "{}|{}",
                sorted_names(graph, held.members()),
                sorted_names(graph, record.partitions())
            )
        })
        .collect()
}

/// Every named node, sorted and joined.
pub fn sorted_names(graph: &CodeGraph, nodes: &[GraphNodeId]) -> String {
    let mut named = names(graph, nodes);
    named.sort();
    named.join(",")
}

/// Every layout node as `name|parent|partition|incoming|outgoing|raw|weighted`,
/// in the order supplied.
pub fn layout_node_texts(graph: &CodeGraph, nodes: &[LayoutNodeMetadata]) -> Vec<String> {
    nodes
        .iter()
        .map(|record| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                name(graph, record.node()),
                optional_name(graph, record.containment_parent()),
                name(graph, record.partition()),
                record.incoming_degree(),
                record.outgoing_degree(),
                bits(record.raw_betweenness()),
                bits(record.normalized_betweenness())
            )
        })
        .collect()
}

/// Every layout edge as `source>target|kind|certainty`, in the order supplied.
pub fn layout_edge_texts(graph: &CodeGraph, edges: &[LayoutEdgeMetadata]) -> Vec<String> {
    edges
        .iter()
        .map(|record| {
            format!(
                "{}>{}|{:?}|{:?}",
                name(graph, record.source()),
                name(graph, record.target()),
                record.kind(),
                record.certainty()
            )
        })
        .collect()
}

/// One optional node's name, or the absence of one.
pub fn optional_name(graph: &CodeGraph, node: Option<GraphNodeId>) -> String {
    match node {
        Some(found) => name(graph, found),
        None => "none".to_owned(),
    }
}

/// Every component as `id|cyclic|member,member`, in the order supplied.
pub fn component_texts(graph: &CodeGraph, components: &[GraphComponent]) -> Vec<String> {
    components
        .iter()
        .map(|component| {
            format!(
                "{}|{}|{}",
                component.id().index(),
                component.is_cyclic(),
                names(graph, component.members()).join(",")
            )
        })
        .collect()
}

/// Every node's component identity as `name|component`, in raw node-id order.
pub fn membership_texts(graph: &CodeGraph, components: &GraphComponents) -> Vec<String> {
    graph
        .nodes()
        .iter()
        .map(|node| {
            let component = components
                .component_of(node.id())
                .unwrap_or_else(|| panic!("{} belongs to no component", node.name()));
            format!("{}|{}", node.name(), component.index())
        })
        .collect()
}

/// Every condensation edge as `source>target|edge,edge`, in the order supplied.
pub fn condensation_texts(graph: &CodeGraph, edges: &[CondensationEdge]) -> Vec<String> {
    edges
        .iter()
        .map(|edge| {
            format!(
                "{}>{}|{}",
                edge.source().index(),
                edge.target().index(),
                edge_texts(graph, edge.edges()).join(",")
            )
        })
        .collect()
}

/// The identity of the node at one dense position.
///
/// A model computed over dense positions names its answers through this, so a
/// case never mints an identity the graph did not.
pub fn node_at(graph: &CodeGraph, at: usize) -> GraphNodeId {
    graph
        .nodes()
        .get(at)
        .map(|node| node.id())
        .unwrap_or_else(|| panic!("this graph holds no node at {at}"))
}

/// Every selection whose derived answers are compared against the same models.
///
/// One inventory, shared by the metric and the component cases, so both prove
/// the same selections and neither can quietly narrow its own coverage.
pub fn metric_selections() -> [(&'static str, GraphEdgeSelection); 5] {
    [
        ("empty", GraphEdgeSelection::new(&[], &[])),
        ("all", GraphEdgeSelection::all()),
        ("code relations", GraphEdgeSelection::code_relations()),
        ("calls", calls_only()),
        (
            "resolved dependencies",
            GraphEdgeSelection::new(&[GraphEdgeKind::DependsOn], &[GraphCertainty::Resolved]),
        ),
    ]
}
