//! The borrowed analysis view and the indexes every query reads.
//!
//! One selection is applied here and nowhere else: this module is the only
//! reader of the raw edge slice, so a neighborhood, a path, a subgraph, and
//! every later metric answer over the same admitted topology. Construction
//! proves both ceilings before it allocates anything indexed by them, and
//! answers with no analysis at all when either refuses.
//!
//! The public query methods sit beside the view they read rather than beside
//! the algorithms that answer them: a type's inherent API belongs in one file,
//! and each entry point here is one delegation to the module that owns the
//! work.

use crate::edge::GraphEdge;
use crate::graph::CodeGraph;
use crate::id::{GraphEdgeId, GraphNodeId, index_of, position};

use super::betweenness::{self, BetweennessCentrality};
use super::components::{self, CondensationGraph, GraphComponents};
use super::degree::{self, DegreeCentrality};
use super::divergence::{self, GraphDivergence};
use super::error::GraphAnalysisError;
use super::layout::{self, LayoutAssistMetadata};
use super::limits::GraphAnalysisLimits;
use super::partition::{self, DeclaredModulePartition};
use super::selection::GraphEdgeSelection;
use super::traversal::{self, GraphDirection, GraphNeighbor, GraphPath, GraphSubgraph};

/// One selected edge, from the node whose adjacency list holds it.
///
/// The other endpoint travels with the identity, so a walk never reads the raw
/// edge slice back to ask where an edge goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedAdjacency {
    edge: GraphEdgeId,
    node: GraphNodeId,
}

impl SelectedAdjacency {
    /// The selected edge's own identity.
    pub(crate) fn edge(self) -> GraphEdgeId {
        self.edge
    }

    /// The endpoint this entry reaches.
    pub(crate) fn node(self) -> GraphNodeId {
        self.node
    }
}

/// The immutable indexes one admitted selection produces.
pub(crate) struct SelectedIndexes {
    outgoing: Box<[Box<[SelectedAdjacency]>]>,
    incoming: Box<[Box<[SelectedAdjacency]>]>,
    parents: Box<[Option<GraphNodeId>]>,
    edges: u32,
}

impl SelectedIndexes {
    /// Index `graph` under `selection`, for the node and selected-edge counts
    /// both ceilings already admitted.
    ///
    /// Each adjacency list is filled in raw edge-id order, so every answer read
    /// from it is in that order before any output sorting. The admitted edge
    /// count travels with the indexes, so a later metric bounds its own work
    /// against what was indexed rather than counting the graph again.
    fn build(graph: &CodeGraph, selection: GraphEdgeSelection, admitted: (u32, u32)) -> Self {
        let (nodes, edges) = admitted;
        let width = index_of(nodes);
        let mut outgoing: Vec<Vec<SelectedAdjacency>> = vec![Vec::new(); width];
        let mut incoming: Vec<Vec<SelectedAdjacency>> = vec![Vec::new(); width];
        let mut parents: Vec<Option<GraphNodeId>> = vec![None; width];
        for edge in selected(graph, selection) {
            append(
                &mut outgoing,
                edge.source(),
                entry(edge.id(), edge.target()),
            );
            append(
                &mut incoming,
                edge.target(),
                entry(edge.id(), edge.source()),
            );
        }
        for edge in graph.containment() {
            claim(&mut parents, edge.child(), edge.parent());
        }
        Self {
            outgoing: sealed(outgoing),
            incoming: sealed(incoming),
            parents: parents.into_boxed_slice(),
            edges,
        }
    }

    /// The selected edges leaving one node, in raw edge-id order.
    pub(crate) fn outgoing(&self, node: GraphNodeId) -> &[SelectedAdjacency] {
        borrowed(&self.outgoing, node)
    }

    /// The selected edges entering one node, in raw edge-id order.
    pub(crate) fn incoming(&self, node: GraphNodeId) -> &[SelectedAdjacency] {
        borrowed(&self.incoming, node)
    }

    /// The containment parent one node is owned by, if it has one.
    pub(crate) fn parent(&self, node: GraphNodeId) -> Option<GraphNodeId> {
        self.parents.get(index_of(node.index())).copied().flatten()
    }

    /// How many nodes these indexes address.
    pub(crate) fn node_count(&self) -> usize {
        self.parents.len()
    }

    /// How many edges the selection admitted into them.
    pub(crate) fn selected_edges(&self) -> u32 {
        self.edges
    }

    /// Whether these indexes address one node at all.
    pub(crate) fn holds(&self, node: GraphNodeId) -> bool {
        index_of(node.index()) < self.parents.len()
    }
}

/// One borrowed graph, the selection applied to it, and the indexes that
/// selection produced.
pub struct GraphAnalysis<'graph> {
    graph: &'graph CodeGraph,
    selection: GraphEdgeSelection,
    limits: GraphAnalysisLimits,
    indexes: SelectedIndexes,
    partition: DeclaredModulePartition,
}

impl<'graph> GraphAnalysis<'graph> {
    /// Index one graph under one stated selection and one stated set of
    /// ceilings.
    ///
    /// The node count is proved before any node-indexed table exists and the
    /// selected-edge count is proved before any adjacency storage does, so a
    /// refusal costs the counts alone.
    pub fn new(
        graph: &'graph CodeGraph,
        selection: GraphEdgeSelection,
        limits: GraphAnalysisLimits,
    ) -> Result<GraphAnalysis<'graph>, GraphAnalysisError> {
        let nodes = admitted_nodes(graph, limits)?;
        let edges = admitted_edges(graph, selection, limits)?;
        let indexes = SelectedIndexes::build(graph, selection, (nodes, edges));
        let partition = partition::derive(graph, &indexes)?;
        Ok(Self {
            graph,
            selection,
            limits,
            indexes,
            partition,
        })
    }

    /// The graph this analysis reads. Every identity it answers with indexes
    /// back into this value.
    pub fn graph(&self) -> &'graph CodeGraph {
        self.graph
    }

    /// The selection every index was built from.
    pub fn selection(&self) -> GraphEdgeSelection {
        self.selection
    }

    /// The ceilings this analysis was admitted under.
    pub fn limits(&self) -> GraphAnalysisLimits {
        self.limits
    }

    /// The declared module partition, derived once from logical containment.
    pub fn declared_partition(&self) -> &DeclaredModulePartition {
        &self.partition
    }

    /// Every node connected to `node` within `depth` selected steps in
    /// `direction`, at its minimum distance, in distance then node order.
    pub fn neighbors(
        &self,
        node: GraphNodeId,
        depth: u32,
        direction: GraphDirection,
    ) -> Result<Box<[GraphNeighbor]>, GraphAnalysisError> {
        traversal::neighbors(self, node, depth, direction)
    }

    /// The shortest route from `source` to `target` over selected outgoing
    /// edges, or `None` when no route exists.
    pub fn path(
        &self,
        source: GraphNodeId,
        target: GraphNodeId,
    ) -> Result<Option<GraphPath>, GraphAnalysisError> {
        traversal::path(self, (source, target))
    }

    /// The selection into this graph induced by the nodes `seed` reaches
    /// within `depth` selected steps.
    pub fn subgraph(
        &self,
        seed: GraphNodeId,
        depth: u32,
        direction: GraphDirection,
    ) -> Result<GraphSubgraph, GraphAnalysisError> {
        traversal::subgraph(self, seed, depth, direction)
    }

    /// How many selected edges arrive at and leave each node, in raw node-id
    /// order.
    pub fn degree_centrality(&self) -> Box<[DegreeCentrality]> {
        degree::degree(self)
    }

    /// How much of the selected topology's shortest routing passes through each
    /// node, in raw node-id order.
    pub fn betweenness_centrality(
        &self,
    ) -> Result<Box<[BetweennessCentrality]>, GraphAnalysisError> {
        betweenness::betweenness(self)
    }

    /// Which nodes reach each other over selected edges.
    pub fn strongly_connected_components(&self) -> GraphComponents {
        components::discover(self)
    }

    /// The same selected topology with every component contracted, ordered, and
    /// still carrying every raw edge it coalesced.
    pub fn condensation(&self) -> CondensationGraph {
        components::condense(self)
    }

    /// What the selected topology says about the module partition this graph
    /// declares.
    pub fn divergence(&self) -> GraphDivergence {
        divergence::divergence(self)
    }

    /// Every admitted node and selected edge, described for a consumer that
    /// ranks or draws them.
    pub fn layout_assist(&self) -> Result<LayoutAssistMetadata, GraphAnalysisError> {
        layout::layout_assist(self)
    }

    /// The shared indexes every query reads.
    pub(crate) fn indexes(&self) -> &SelectedIndexes {
        &self.indexes
    }
}

/// Every edge one selection admits, in raw edge-id order.
///
/// The one place the raw edge slice is read and the one place the selection is
/// applied, so the counted set and the indexed set cannot differ.
fn selected(graph: &CodeGraph, selection: GraphEdgeSelection) -> impl Iterator<Item = &GraphEdge> {
    graph
        .edges()
        .iter()
        .filter(move |edge| selection.allows(edge))
}

/// The graph's node count, proved against the stated ceiling.
fn admitted_nodes(
    graph: &CodeGraph,
    limits: GraphAnalysisLimits,
) -> Result<u32, GraphAnalysisError> {
    let count = position(graph.nodes().len());
    match count <= limits.max_nodes() {
        true => Ok(count),
        false => Err(GraphAnalysisError::NodeLimitExceeded {
            count,
            limit: limits.max_nodes(),
        }),
    }
}

/// The selected edge count, proved against the stated ceiling.
fn admitted_edges(
    graph: &CodeGraph,
    selection: GraphEdgeSelection,
    limits: GraphAnalysisLimits,
) -> Result<u32, GraphAnalysisError> {
    let count = position(selected(graph, selection).count());
    match count <= limits.max_selected_edges() {
        true => Ok(count),
        false => Err(GraphAnalysisError::SelectedEdgeLimitExceeded {
            count,
            limit: limits.max_selected_edges(),
        }),
    }
}

/// One adjacency entry: the edge, and the endpoint it reaches.
fn entry(edge: GraphEdgeId, node: GraphNodeId) -> SelectedAdjacency {
    SelectedAdjacency { edge, node }
}

/// Record one selected edge in the list its endpoint owns.
fn append(lists: &mut [Vec<SelectedAdjacency>], node: GraphNodeId, entry: SelectedAdjacency) {
    if let Some(list) = lists.get_mut(index_of(node.index())) {
        list.push(entry);
    }
}

/// Record the containment parent one child is owned by.
fn claim(parents: &mut [Option<GraphNodeId>], child: GraphNodeId, parent: GraphNodeId) {
    if let Some(slot) = parents.get_mut(index_of(child.index())) {
        *slot = Some(parent);
    }
}

/// One filled adjacency table, sealed against further growth.
fn sealed(lists: Vec<Vec<SelectedAdjacency>>) -> Box<[Box<[SelectedAdjacency]>]> {
    lists
        .into_iter()
        .map(Vec::into_boxed_slice)
        .collect::<Vec<Box<[SelectedAdjacency]>>>()
        .into_boxed_slice()
}

/// One node's adjacency list, or nothing at all for a node this graph does not
/// hold.
fn borrowed(lists: &[Box<[SelectedAdjacency]>], node: GraphNodeId) -> &[SelectedAdjacency] {
    match lists.get(index_of(node.index())) {
        Some(list) => list,
        None => &[],
    }
}
