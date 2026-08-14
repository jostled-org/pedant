//! What something drawing or ranking a graph would otherwise derive itself.
//!
//! One typed projection of facts this crate already owns: the raw identities and
//! their containment, the partition that declares each node, the selected
//! degrees, and the same bounded betweenness result the public metric answers
//! with. It decides nothing about how a graph looks — there is no coordinate,
//! no route, no ordering, and no drawing state here, and the version-1 graph
//! object stays exactly as it was.
//!
//! The bounded pass runs first, so a graph beyond the caller's stated budget
//! refuses with that pass's own refusal, unchanged, before any metadata exists.

use crate::edge::{GraphCertainty, GraphEdgeKind};
use crate::graph::CodeGraph;
use crate::id::{GraphEdgeId, GraphNodeId, index_of, position};

use super::betweenness::{self, BetweennessCentrality};
use super::degree::{self, DegreeCentrality};
use super::error::GraphAnalysisError;
use super::index::{GraphAnalysis, SelectedAdjacency, SelectedIndexes};

/// What one node is, is inside, and measures as.
#[derive(Clone, Copy, Debug)]
pub struct LayoutNodeMetadata {
    node: GraphNodeId,
    parent: Option<GraphNodeId>,
    partition: GraphNodeId,
    incoming: u32,
    outgoing: u32,
    raw: f64,
    normalized: f64,
}

impl LayoutNodeMetadata {
    /// The node this metadata describes.
    pub fn node(self) -> GraphNodeId {
        self.node
    }

    /// The node containing it, if anything does.
    pub fn containment_parent(self) -> Option<GraphNodeId> {
        self.parent
    }

    /// The partition root that declares it.
    pub fn partition(self) -> GraphNodeId {
        self.partition
    }

    /// How many selected edges arrive at it.
    pub fn incoming_degree(self) -> u32 {
        self.incoming
    }

    /// How many selected edges leave it.
    pub fn outgoing_degree(self) -> u32 {
        self.outgoing
    }

    /// The summed share of shortest routes passing through it.
    pub fn raw_betweenness(self) -> f64 {
        self.raw
    }

    /// That share against every ordered pair a graph this size can state.
    pub fn normalized_betweenness(self) -> f64 {
        self.normalized
    }
}

/// One selected edge, restated with both of its ends and its own evidence.
#[derive(Clone, Copy, Debug)]
pub struct LayoutEdgeMetadata {
    edge: GraphEdgeId,
    source: GraphNodeId,
    target: GraphNodeId,
    kind: GraphEdgeKind,
    certainty: GraphCertainty,
}

impl LayoutEdgeMetadata {
    /// The raw edge this metadata describes.
    pub fn edge(self) -> GraphEdgeId {
        self.edge
    }

    /// The node it leaves.
    pub fn source(self) -> GraphNodeId {
        self.source
    }

    /// The node it reaches.
    pub fn target(self) -> GraphNodeId {
        self.target
    }

    /// What relation it states.
    pub fn kind(self) -> GraphEdgeKind {
        self.kind
    }

    /// How certain that relation is.
    pub fn certainty(self) -> GraphCertainty {
        self.certainty
    }
}

/// Every admitted node and every selected edge, described once.
#[derive(Debug)]
pub struct LayoutAssistMetadata {
    nodes: Box<[LayoutNodeMetadata]>,
    edges: Box<[LayoutEdgeMetadata]>,
}

impl LayoutAssistMetadata {
    /// Every admitted node, in raw node-id order.
    pub fn nodes(&self) -> &[LayoutNodeMetadata] {
        &self.nodes
    }

    /// Every selected edge, in raw edge-id order.
    pub fn edges(&self) -> &[LayoutEdgeMetadata] {
        &self.edges
    }
}

/// Describe every admitted node and selected edge, once the bounded pass admits
/// the work.
pub(crate) fn layout_assist(
    analysis: &GraphAnalysis<'_>,
) -> Result<LayoutAssistMetadata, GraphAnalysisError> {
    let weights = betweenness::betweenness(analysis)?;
    let degrees = degree::degree(analysis);
    Ok(LayoutAssistMetadata {
        nodes: described(analysis, (&degrees, &weights)),
        edges: connections(analysis),
    })
}

/// Every node's metadata, in raw node-id order.
fn described(
    analysis: &GraphAnalysis<'_>,
    measured: (&[DegreeCentrality], &[BetweennessCentrality]),
) -> Box<[LayoutNodeMetadata]> {
    let (degrees, weights) = measured;
    let indexes = analysis.indexes();
    degrees
        .iter()
        .zip(weights)
        .zip(analysis.declared_partition().owners())
        .map(|((degree, weight), partition)| node_metadata(indexes, (*degree, *weight), *partition))
        .collect()
}

/// One node beside what contains it, what declares it, and what measures it.
fn node_metadata(
    indexes: &SelectedIndexes,
    measured: (DegreeCentrality, BetweennessCentrality),
    partition: GraphNodeId,
) -> LayoutNodeMetadata {
    let (degree, weight) = measured;
    LayoutNodeMetadata {
        node: degree.node(),
        parent: indexes.parent(degree.node()),
        partition,
        incoming: degree.incoming(),
        outgoing: degree.outgoing(),
        raw: weight.raw(),
        normalized: weight.normalized(),
    }
}

/// Every selected edge's metadata, in raw edge-id order.
///
/// The shared adjacency lists hold the selection, so the walk is over what was
/// indexed; each entry's raw record is read back for the evidence it carries.
fn connections(analysis: &GraphAnalysis<'_>) -> Box<[LayoutEdgeMetadata]> {
    let indexes = analysis.indexes();
    let graph = analysis.graph();
    let mut found: Vec<LayoutEdgeMetadata> = Vec::with_capacity(index_of(indexes.selected_edges()));
    found.extend(
        (0..indexes.node_count())
            .map(|at| GraphNodeId::new(position(at)))
            .flat_map(|node| leaving(graph, indexes, node)),
    );
    found.sort_unstable_by_key(|stated| stated.edge);
    found.into_boxed_slice()
}

/// The metadata of every selected edge leaving one node.
fn leaving<'graph>(
    graph: &'graph CodeGraph,
    indexes: &'graph SelectedIndexes,
    node: GraphNodeId,
) -> impl Iterator<Item = LayoutEdgeMetadata> + 'graph {
    indexes
        .outgoing(node)
        .iter()
        .filter_map(move |entry| edge_metadata(graph, node, *entry))
}

/// One selected edge, restated from the raw record its identity names.
///
/// The identity came from the adjacency list the graph's own edges were indexed
/// into, so the lookup answers for every entry; asking through the graph rather
/// than storing a second copy of the evidence is what keeps the raw record the
/// one place it is stated.
fn edge_metadata(
    graph: &CodeGraph,
    source: GraphNodeId,
    entry: SelectedAdjacency,
) -> Option<LayoutEdgeMetadata> {
    let found = graph.edge(entry.edge())?;
    Some(LayoutEdgeMetadata {
        edge: entry.edge(),
        source,
        target: entry.node(),
        kind: found.kind(),
        certainty: found.certainty(),
    })
}
