//! Bounded neighborhoods, shortest paths, and induced subgraph selections.
//!
//! Every walk is iterative and indexed by dense node identity, so no query
//! recurses on a depth the repository controls. All three read the shared
//! selected adjacency and containment-parent indexes; none reads the raw edge
//! slice or restates the selection.
//!
//! [`GraphDirection`] lives beside the walks that consume it rather than beside
//! the edge selection: it states how a walk follows an edge, not which edges an
//! analysis admits, and every operation that reads it is here.

use std::collections::VecDeque;

use crate::containment::ContainmentEdge;
use crate::id::{GraphEdgeId, GraphNodeId, index_of, position};

use super::error::GraphAnalysisError;
use super::index::{GraphAnalysis, SelectedAdjacency, SelectedIndexes};
use super::limits::GraphAnalysisLimits;

/// The adjacency list a one-sided walk does not read.
const NEITHER: &[SelectedAdjacency] = &[];

/// Which way a neighborhood or subgraph walk follows a selected edge.
///
/// Every other directed operation follows outgoing edges. A reversed question
/// is asked by swapping the endpoints rather than by changing what an operation
/// means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphDirection {
    /// Follow edges away from their source.
    Outgoing,
    /// Follow edges back towards their source.
    Incoming,
    /// Follow edges either way. A self-loop reaches the node it starts at,
    /// which the walk has already reached.
    Both,
}

/// One reached node and how many selected steps away it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphNeighbor {
    node: GraphNodeId,
    distance: u32,
}

impl GraphNeighbor {
    /// The node this walk reached.
    pub fn node(self) -> GraphNodeId {
        self.node
    }

    /// The minimum number of selected steps that reach it.
    pub fn distance(self) -> u32 {
        self.distance
    }
}

/// One directed route over selected outgoing edges.
///
/// A route always states one more node than it states edges: the nodes are the
/// stops, and the edges are the steps between them.
#[derive(Debug)]
pub struct GraphPath {
    nodes: Box<[GraphNodeId]>,
    edges: Box<[GraphEdgeId]>,
}

impl GraphPath {
    /// The nodes this route visits, from source to target.
    pub fn nodes(&self) -> &[GraphNodeId] {
        &self.nodes
    }

    /// The raw edges this route takes, in the order it takes them.
    pub fn edges(&self) -> &[GraphEdgeId] {
        &self.edges
    }
}

/// One selection into the raw graph, never a second graph.
///
/// Every identity indexes back into the graph the analysis borrows, which is
/// where a caller resolves it. The selection owns no record, no evidence, and
/// no serialized form of its own.
#[derive(Debug)]
pub struct GraphSubgraph {
    nodes: Box<[GraphNodeId]>,
    edges: Box<[GraphEdgeId]>,
    containment: Box<[ContainmentEdge]>,
}

impl GraphSubgraph {
    /// The selected nodes, in node-id order. The seed is always one of them.
    pub fn nodes(&self) -> &[GraphNodeId] {
        &self.nodes
    }

    /// Every selected edge whose source and target are both selected, in raw
    /// edge-id order.
    pub fn edges(&self) -> &[GraphEdgeId] {
        &self.edges
    }

    /// Every containment edge whose parent and child are both selected, in
    /// child order.
    pub fn containment(&self) -> &[ContainmentEdge] {
        &self.containment
    }
}

/// The minimum distance from one seed to every node one walk reached.
struct Distances {
    measured: Box<[Option<u32>]>,
}

impl Distances {
    /// How many selected steps reach one node, if the walk reached it.
    fn of(&self, node: GraphNodeId) -> Option<u32> {
        self.measured.get(index_of(node.index())).copied().flatten()
    }

    /// Every node the walk reached, in node-id order, including the seed.
    fn reached(&self) -> Box<[GraphNodeId]> {
        self.measured
            .iter()
            .enumerate()
            .filter(|(_, distance)| distance.is_some())
            .map(|(at, _)| GraphNodeId::new(position(at)))
            .collect()
    }

    /// Every node the walk reached beyond the seed, in distance then node
    /// order.
    fn ordered(&self) -> Box<[GraphNeighbor]> {
        let mut found: Vec<GraphNeighbor> = self
            .measured
            .iter()
            .enumerate()
            .filter_map(|(at, distance)| beyond_seed(at, *distance))
            .collect();
        found.sort_unstable_by_key(|neighbor| (neighbor.distance, neighbor.node));
        found.into_boxed_slice()
    }
}

/// One measured node, unless it is the seed the walk started at.
fn beyond_seed(at: usize, distance: Option<u32>) -> Option<GraphNeighbor> {
    distance
        .filter(|steps| *steps > 0)
        .map(|steps| GraphNeighbor {
            node: GraphNodeId::new(position(at)),
            distance: steps,
        })
}

/// Every node connected to `node` within `depth` selected steps in `direction`,
/// at its minimum distance.
pub(crate) fn neighbors(
    analysis: &GraphAnalysis<'_>,
    node: GraphNodeId,
    depth: u32,
    direction: GraphDirection,
) -> Result<Box<[GraphNeighbor]>, GraphAnalysisError> {
    let indexes = analysis.indexes();
    known_node(indexes, node)?;
    admitted_depth(analysis.limits(), depth)?;
    Ok(walk(indexes, node, depth, direction).ordered())
}

/// The shortest route from one node to another over selected outgoing edges.
///
/// Among equally short routes the answer is the one whose raw edge identities
/// are lexicographically least, because each step takes the least edge that
/// still reaches the target in the steps that remain.
///
/// No depth is requested and none is proved: a route is as long as the topology
/// makes it, so this walk is bounded by the admitted node and selected-edge
/// counts rather than by the depth ceiling a neighborhood or subgraph states.
pub(crate) fn path(
    analysis: &GraphAnalysis<'_>,
    route: (GraphNodeId, GraphNodeId),
) -> Result<Option<GraphPath>, GraphAnalysisError> {
    let (source, target) = route;
    let indexes = analysis.indexes();
    known_node(indexes, source)?;
    known_node(indexes, target)?;
    let remaining = walk(indexes, target, u32::MAX, GraphDirection::Incoming);
    Ok(least_route(indexes, &remaining, route))
}

/// The selection induced by the nodes `seed` reaches within `depth` selected
/// steps.
pub(crate) fn subgraph(
    analysis: &GraphAnalysis<'_>,
    seed: GraphNodeId,
    depth: u32,
    direction: GraphDirection,
) -> Result<GraphSubgraph, GraphAnalysisError> {
    let indexes = analysis.indexes();
    known_node(indexes, seed)?;
    admitted_depth(analysis.limits(), depth)?;
    Ok(induced(indexes, &walk(indexes, seed, depth, direction)))
}

/// One node this analysis holds a record for.
fn known_node(indexes: &SelectedIndexes, node: GraphNodeId) -> Result<(), GraphAnalysisError> {
    match indexes.holds(node) {
        true => Ok(()),
        false => Err(GraphAnalysisError::UnknownNode { node }),
    }
}

/// One requested depth, proved against the stated ceiling before any walk
/// state exists.
fn admitted_depth(limits: GraphAnalysisLimits, depth: u32) -> Result<(), GraphAnalysisError> {
    match depth <= limits.max_depth() {
        true => Ok(()),
        false => Err(GraphAnalysisError::DepthLimitExceeded {
            requested: depth,
            limit: limits.max_depth(),
        }),
    }
}

/// Measure every node one seed reaches within `depth` selected steps.
///
/// A breadth-first queue over dense node identities, so the walk is iterative
/// and each node is measured once, at its minimum distance.
fn walk(
    indexes: &SelectedIndexes,
    seed: GraphNodeId,
    depth: u32,
    direction: GraphDirection,
) -> Distances {
    let mut measured: Vec<Option<u32>> = vec![None; indexes.node_count()];
    let mut queue: VecDeque<GraphNeighbor> = VecDeque::new();
    admit(
        &mut measured,
        &mut queue,
        GraphNeighbor {
            node: seed,
            distance: 0,
        },
    );
    while let Some(reached) = queue.pop_front() {
        if reached.distance < depth {
            extend(indexes, (&mut measured, &mut queue), reached, direction);
        }
    }
    Distances {
        measured: measured.into_boxed_slice(),
    }
}

/// Measure every unmeasured node one reached node leads to.
fn extend(
    indexes: &SelectedIndexes,
    state: (&mut [Option<u32>], &mut VecDeque<GraphNeighbor>),
    from: GraphNeighbor,
    direction: GraphDirection,
) {
    let (measured, queue) = state;
    let distance = from.distance + 1;
    for entry in adjacent(indexes, from.node, direction) {
        admit(
            measured,
            queue,
            GraphNeighbor {
                node: entry.node(),
                distance,
            },
        );
    }
}

/// Record one node's distance, unless the walk already measured it.
fn admit(
    measured: &mut [Option<u32>],
    queue: &mut VecDeque<GraphNeighbor>,
    reached: GraphNeighbor,
) {
    match measured.get_mut(index_of(reached.node.index())) {
        Some(slot) if slot.is_none() => {
            *slot = Some(reached.distance);
            queue.push_back(reached);
        }
        _ => (),
    }
}

/// The adjacency one direction reads from one node, in raw edge-id order.
fn adjacent(
    indexes: &SelectedIndexes,
    node: GraphNodeId,
    direction: GraphDirection,
) -> impl Iterator<Item = SelectedAdjacency> + '_ {
    let (first, second) = match direction {
        GraphDirection::Outgoing => (indexes.outgoing(node), NEITHER),
        GraphDirection::Incoming => (indexes.incoming(node), NEITHER),
        GraphDirection::Both => (indexes.outgoing(node), indexes.incoming(node)),
    };
    first.iter().chain(second).copied()
}

/// Walk the least route to the target the measured distances describe.
fn least_route(
    indexes: &SelectedIndexes,
    remaining: &Distances,
    route: (GraphNodeId, GraphNodeId),
) -> Option<GraphPath> {
    let (source, _) = route;
    let mut steps = remaining.of(source)?;
    let mut nodes: Vec<GraphNodeId> = vec![source];
    let mut edges: Vec<GraphEdgeId> = Vec::new();
    let mut current = source;
    while steps > 0 {
        let step = least_step(indexes, remaining, current, steps)?;
        nodes.push(step.node());
        edges.push(step.edge());
        current = step.node();
        steps -= 1;
    }
    Some(GraphPath {
        nodes: nodes.into_boxed_slice(),
        edges: edges.into_boxed_slice(),
    })
}

/// The least selected edge leaving one node that still reaches the target in
/// the steps that remain.
fn least_step(
    indexes: &SelectedIndexes,
    remaining: &Distances,
    from: GraphNodeId,
    steps: u32,
) -> Option<SelectedAdjacency> {
    indexes
        .outgoing(from)
        .iter()
        .filter(|entry| remaining.of(entry.node()) == Some(steps - 1))
        .min_by_key(|entry| entry.edge())
        .copied()
}

/// The induced selection over every node one walk reached.
fn induced(indexes: &SelectedIndexes, distances: &Distances) -> GraphSubgraph {
    let held = distances.reached();
    GraphSubgraph {
        edges: internal_edges(indexes, &held),
        containment: internal_containment(indexes, &held),
        nodes: held,
    }
}

/// Every selected edge whose source and target are both held, in raw edge-id
/// order.
fn internal_edges(indexes: &SelectedIndexes, held: &[GraphNodeId]) -> Box<[GraphEdgeId]> {
    let mut found: Vec<GraphEdgeId> = held
        .iter()
        .flat_map(|node| leaving(indexes, *node, held))
        .collect();
    found.sort_unstable();
    found.into_boxed_slice()
}

/// The selected edges leaving one held node for another held node.
fn leaving<'index>(
    indexes: &'index SelectedIndexes,
    node: GraphNodeId,
    held: &'index [GraphNodeId],
) -> impl Iterator<Item = GraphEdgeId> + 'index {
    indexes
        .outgoing(node)
        .iter()
        .filter(move |entry| held.binary_search(&entry.node()).is_ok())
        .map(|entry| entry.edge())
}

/// Every containment edge whose parent and child are both held, in child
/// order.
fn internal_containment(indexes: &SelectedIndexes, held: &[GraphNodeId]) -> Box<[ContainmentEdge]> {
    held.iter()
        .filter_map(|child| owned_pair(indexes, *child, held))
        .collect()
}

/// One held child beside the parent that owns it, unless that parent is
/// outside the held set.
fn owned_pair(
    indexes: &SelectedIndexes,
    child: GraphNodeId,
    held: &[GraphNodeId],
) -> Option<ContainmentEdge> {
    indexes
        .parent(child)
        .filter(|parent| held.binary_search(parent).is_ok())
        .map(|parent| ContainmentEdge::new(parent, child))
}
