//! Which nodes reach each other, and the acyclic view that fact produces.
//!
//! Two nodes share a component when each reaches the other over selected edges.
//! Contracting every component leaves a graph with no cycle at all, which is
//! what a ranker or a renderer needs before it can order anything — so the
//! condensation is built here, beside the components it contracts, and keeps
//! every raw edge identity it coalesced.
//!
//! Both walks are iterative and indexed by dense identity. Neither reads the raw
//! edge slice: the selection was applied once, and these read what it produced.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{GraphEdgeId, GraphId, GraphNodeId, index_of, position};

use super::index::{AnalysisContext, SelectedAdjacency, SelectedIndexes};

/// Marker distinguishing component identities from the graph's own identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentIdKind;

/// A component's dense identity within one [`GraphComponents`].
///
/// Derived rather than graph-owned: it addresses a result the caller's selection
/// produced, so it never enters [`crate::CodeGraph`] or its serialized form.
pub type GraphComponentId = GraphId<ComponentIdKind>;

/// One set of nodes that all reach each other.
pub struct GraphComponent {
    id: GraphComponentId,
    members: Box<[GraphNodeId]>,
    cyclic: bool,
}

impl GraphComponent {
    /// This component's dense identity.
    pub fn id(&self) -> GraphComponentId {
        self.id
    }

    /// Every node it holds, in node-id order.
    pub fn members(&self) -> &[GraphNodeId] {
        &self.members
    }

    /// Whether its members can return to themselves: more than one member, or
    /// one member that selects an edge to itself.
    pub fn is_cyclic(&self) -> bool {
        self.cyclic
    }
}

/// Every component of one selected topology, and which one each node belongs
/// to.
///
/// Both views come from one walk, so a component's members and a node's
/// component can never disagree.
pub struct GraphComponents {
    components: Box<[GraphComponent]>,
    membership: Box<[Option<GraphComponentId>]>,
}

impl GraphComponents {
    /// Every component, in smallest-member order, which is also identity order.
    pub fn components(&self) -> &[GraphComponent] {
        &self.components
    }

    /// The component one identity names, if this result holds it.
    pub fn component(&self, id: GraphComponentId) -> Option<&GraphComponent> {
        self.components.get(index_of(id.index()))
    }

    /// The component one node belongs to, if this result holds that node.
    pub fn component_of(&self, node: GraphNodeId) -> Option<GraphComponentId> {
        self.membership
            .get(index_of(node.index()))
            .copied()
            .flatten()
    }
}

/// Every selected edge between one ordered pair of components.
///
/// The raw identities travel with the pair, so contracting a cycle hides no
/// evidence: a caller resolves each of them through the graph the analysis
/// borrows.
pub struct CondensationEdge {
    source: GraphComponentId,
    target: GraphComponentId,
    edges: Box<[GraphEdgeId]>,
}

impl CondensationEdge {
    /// The component these edges leave.
    pub fn source(&self) -> GraphComponentId {
        self.source
    }

    /// The component they reach.
    pub fn target(&self) -> GraphComponentId {
        self.target
    }

    /// Every raw edge between that ordered pair, in raw edge-id order.
    pub fn edges(&self) -> &[GraphEdgeId] {
        &self.edges
    }
}

/// One selected topology with every component contracted to a single node.
pub struct CondensationGraph {
    components: GraphComponents,
    edges: Box<[CondensationEdge]>,
    order: Box<[GraphComponentId]>,
}

impl CondensationGraph {
    /// The components this view contracted.
    pub fn components(&self) -> &GraphComponents {
        &self.components
    }

    /// Every coalesced pair, in source then target order.
    pub fn edges(&self) -> &[CondensationEdge] {
        &self.edges
    }

    /// Every component once, each after the components that reach it.
    pub fn topological_order(&self) -> &[GraphComponentId] {
        &self.order
    }
}

/// Every strongly connected component of one selected topology.
///
/// One forward pass records the order nodes finish in; one backward pass over
/// that order in reverse collects each component. Both are iterative, so a chain
/// as long as the admitted node ceiling costs no stack.
pub(crate) fn discover(analysis: &AnalysisContext<'_>) -> GraphComponents {
    let indexes = analysis.indexes();
    let finished = finish_order(indexes);
    assembled(grouped_backwards(indexes, &finished), indexes)
}

/// One selected topology with its components contracted and ordered.
pub(crate) fn condense(analysis: &AnalysisContext<'_>) -> CondensationGraph {
    let indexes = analysis.indexes();
    let components = discover(analysis);
    let edges = coalesced(indexes, &components);
    let order = ordered(&edges, components.components.len());
    CondensationGraph {
        components,
        edges,
        order,
    }
}

/// Every node in the order a depth-first walk of selected edges finishes it.
fn finish_order(indexes: &SelectedIndexes) -> Box<[GraphNodeId]> {
    let width = indexes.node_count();
    let mut seen: Vec<bool> = vec![false; width];
    let mut finished: Vec<GraphNodeId> = Vec::with_capacity(width);
    let mut stack: Vec<(GraphNodeId, usize)> = Vec::new();
    for at in 0..width {
        begin(&mut seen, &mut stack, GraphNodeId::new(position(at)));
        drain(indexes, (&mut seen, &mut stack, &mut finished));
    }
    finished.into_boxed_slice()
}

/// Start one walk at a node, unless an earlier walk already reached it.
fn begin(seen: &mut [bool], stack: &mut Vec<(GraphNodeId, usize)>, node: GraphNodeId) {
    if unclaimed(seen, node) {
        stack.push((node, 0));
    }
}

/// Claim one node against a flag table, answering whether this call took it.
///
/// The one place a walk's flag is tested and set, so the forward walk and the
/// backward gathering cannot disagree about what claiming a node means.
fn unclaimed(flags: &mut [bool], node: GraphNodeId) -> bool {
    match flags.get_mut(index_of(node.index())) {
        Some(slot) if !*slot => {
            *slot = true;
            true
        }
        _ => false,
    }
}

/// Run the current walk to completion, recording each node as it finishes.
fn drain(
    indexes: &SelectedIndexes,
    state: (
        &mut [bool],
        &mut Vec<(GraphNodeId, usize)>,
        &mut Vec<GraphNodeId>,
    ),
) {
    let (seen, stack, finished) = state;
    while let Some(step) = stack.pop() {
        advance(indexes, (seen, stack, finished), step);
    }
}

/// Take one more edge from the node on top of the walk, or finish it.
fn advance(
    indexes: &SelectedIndexes,
    state: (
        &mut [bool],
        &mut Vec<(GraphNodeId, usize)>,
        &mut Vec<GraphNodeId>,
    ),
    step: (GraphNodeId, usize),
) {
    let (seen, stack, finished) = state;
    let (node, at) = step;
    match indexes.outgoing(node).get(at) {
        Some(entry) => resume(seen, stack, (node, at + 1), entry.node()),
        None => finished.push(node),
    }
}

/// Put one node back on the walk and follow the edge it just took.
fn resume(
    seen: &mut [bool],
    stack: &mut Vec<(GraphNodeId, usize)>,
    step: (GraphNodeId, usize),
    reached: GraphNodeId,
) {
    stack.push(step);
    begin(seen, stack, reached);
}

/// Every component's members, gathered by walking selected edges backwards in
/// reverse finishing order.
///
/// Members arrive in the order the walk claimed them and the groups in the order
/// the walk found them. The assembly that follows sorts both, so both are still
/// mutating buffers when they are handed over.
fn grouped_backwards(indexes: &SelectedIndexes, finished: &[GraphNodeId]) -> Vec<Vec<GraphNodeId>> {
    let mut taken: Vec<bool> = vec![false; indexes.node_count()];
    let mut found: Vec<Vec<GraphNodeId>> = Vec::new();
    for node in finished.iter().rev() {
        let members = gathered(indexes, &mut taken, *node);
        match members.is_empty() {
            true => (),
            false => found.push(members),
        }
    }
    found
}

/// Every still-unclaimed node that reaches one root over selected edges.
fn gathered(indexes: &SelectedIndexes, taken: &mut [bool], root: GraphNodeId) -> Vec<GraphNodeId> {
    let mut members: Vec<GraphNodeId> = Vec::new();
    let mut stack: Vec<GraphNodeId> = Vec::new();
    claim(taken, &mut stack, root);
    while let Some(node) = stack.pop() {
        members.push(node);
        for entry in indexes.incoming(node) {
            claim(taken, &mut stack, entry.node());
        }
    }
    members
}

/// Claim one node for the component being gathered, unless it is already
/// claimed.
fn claim(taken: &mut [bool], stack: &mut Vec<GraphNodeId>, node: GraphNodeId) {
    if unclaimed(taken, node) {
        stack.push(node);
    }
}

/// One dense component table, ordered by smallest member.
fn assembled(grouped: Vec<Vec<GraphNodeId>>, indexes: &SelectedIndexes) -> GraphComponents {
    let mut ordered = grouped;
    for members in &mut ordered {
        members.sort_unstable();
    }
    ordered.sort_unstable_by_key(|members| members.first().copied());
    let components: Box<[GraphComponent]> = ordered
        .into_iter()
        .enumerate()
        .map(|(at, members)| built(at, members, indexes))
        .collect();
    let membership = placed(&components, indexes.node_count());
    GraphComponents {
        components,
        membership,
    }
}

/// One component record, identified by its position in that order.
///
/// The gathered list is taken by value and sealed in place, so no two member
/// lists of one result are ever live at once.
fn built(at: usize, members: Vec<GraphNodeId>, indexes: &SelectedIndexes) -> GraphComponent {
    GraphComponent {
        id: GraphComponentId::new(position(at)),
        cyclic: cyclic(&members, indexes),
        members: members.into_boxed_slice(),
    }
}

/// Whether one component's members can return to themselves.
///
/// More than one member is already a cycle, because each reaches the others. A
/// lone member is cyclic only when it selects an edge back to itself.
fn cyclic(members: &[GraphNodeId], indexes: &SelectedIndexes) -> bool {
    match members {
        [only] => indexes
            .outgoing(*only)
            .iter()
            .any(|entry| entry.node() == *only),
        _ => members.len() > 1,
    }
}

/// Each node's component, indexed by node.
///
/// Filled from nothing rather than from a component identity, so a node no walk
/// claimed answers with no component instead of silently answering with the
/// first one.
fn placed(components: &[GraphComponent], width: usize) -> Box<[Option<GraphComponentId>]> {
    let mut table: Vec<Option<GraphComponentId>> = vec![None; width];
    for component in components {
        for member in component.members.iter() {
            record(&mut table, *member, component.id);
        }
    }
    table.into_boxed_slice()
}

/// Record which component one node belongs to.
fn record(table: &mut [Option<GraphComponentId>], node: GraphNodeId, component: GraphComponentId) {
    if let Some(slot) = table.get_mut(index_of(node.index())) {
        *slot = Some(component);
    }
}

/// Every selected edge that crosses a component boundary, coalesced by ordered
/// component pair.
fn coalesced(indexes: &SelectedIndexes, components: &GraphComponents) -> Box<[CondensationEdge]> {
    let mut crossing: Crossings = BTreeMap::new();
    for at in 0..indexes.node_count() {
        cross(
            indexes,
            components,
            &mut crossing,
            GraphNodeId::new(position(at)),
        );
    }
    crossing.into_iter().map(joined).collect()
}

/// Every raw edge found between one ordered pair of components.
type Crossings = BTreeMap<(GraphComponentId, GraphComponentId), Vec<GraphEdgeId>>;

/// Record every selected edge leaving one node for another component.
fn cross(
    indexes: &SelectedIndexes,
    components: &GraphComponents,
    crossing: &mut Crossings,
    node: GraphNodeId,
) {
    let source = match components.component_of(node) {
        Some(found) => found,
        None => return,
    };
    for entry in indexes.outgoing(node) {
        leaving(components, crossing, (source, *entry));
    }
}

/// Record one selected edge, unless both of its ends sit in one component.
fn leaving(
    components: &GraphComponents,
    crossing: &mut Crossings,
    step: (GraphComponentId, SelectedAdjacency),
) {
    let (source, entry) = step;
    let target = match components.component_of(entry.node()) {
        Some(found) => found,
        None => return,
    };
    match source == target {
        true => (),
        false => crossing
            .entry((source, target))
            .or_default()
            .push(entry.edge()),
    }
}

/// One coalesced pair, with its raw edges in raw edge-id order.
fn joined(crossing: ((GraphComponentId, GraphComponentId), Vec<GraphEdgeId>)) -> CondensationEdge {
    let ((source, target), mut edges) = crossing;
    edges.sort_unstable();
    CondensationEdge {
        source,
        target,
        edges: edges.into_boxed_slice(),
    }
}

/// The deterministic topological order of one condensation.
///
/// Contracting whole components leaves no cycle, so every component eventually
/// becomes ready and the order states each of them once. Components that become
/// ready together are consumed by identity.
fn ordered(edges: &[CondensationEdge], count: usize) -> Box<[GraphComponentId]> {
    let mut waiting: Vec<usize> = vec![0; count];
    for edge in edges {
        bump(&mut waiting, edge.target);
    }
    let mut ready: BTreeSet<GraphComponentId> = (0..count)
        .map(|at| GraphComponentId::new(position(at)))
        .filter(|component| waiting.get(index_of(component.index())) == Some(&0))
        .collect();
    let mut consumed: Vec<GraphComponentId> = Vec::with_capacity(count);
    while let Some(least) = ready.pop_first() {
        consumed.push(least);
        release(edges, least, (&mut waiting, &mut ready));
    }
    consumed.into_boxed_slice()
}

/// Count one more coalesced edge arriving at a component.
fn bump(waiting: &mut [usize], component: GraphComponentId) {
    if let Some(slot) = waiting.get_mut(index_of(component.index())) {
        *slot += 1;
    }
}

/// Consume every edge leaving one ordered component, admitting whatever that
/// leaves ready.
fn release(
    edges: &[CondensationEdge],
    consumed: GraphComponentId,
    state: (&mut [usize], &mut BTreeSet<GraphComponentId>),
) {
    let (waiting, ready) = state;
    ready.extend(
        leaving_pairs(edges, consumed)
            .iter()
            .filter_map(|edge| arrived(waiting, edge.target)),
    );
}

/// The coalesced pairs leaving one component.
///
/// `coalesced` states each pair once, keyed by an ordered component pair, so the
/// slice is sorted by source and one component's pairs are a contiguous run.
/// Bounding that run costs two binary searches rather than a scan of every pair
/// per ordered component, which is what keeps the whole ordering linear in the
/// pairs it consumes.
fn leaving_pairs(edges: &[CondensationEdge], source: GraphComponentId) -> &[CondensationEdge] {
    let start = edges.partition_point(|edge| edge.source < source);
    let end = edges.partition_point(|edge| edge.source <= source);
    &edges[start..end]
}

/// Record one arriving edge as consumed, answering with its component when the
/// last one is.
///
/// A component already released states no further arrival to consume, so the
/// decrement is checked: a saturating one would answer with a component a second
/// time and state it twice in the order.
fn arrived(waiting: &mut [usize], component: GraphComponentId) -> Option<GraphComponentId> {
    let slot = waiting.get_mut(index_of(component.index()))?;
    *slot = slot.checked_sub(1)?;
    match *slot {
        0 => Some(component),
        _ => None,
    }
}
