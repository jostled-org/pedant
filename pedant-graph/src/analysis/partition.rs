//! The declared module partition, derived from logical containment alone.
//!
//! Every container is a partition root, every node belongs to the nearest
//! container above it, and a container belongs to itself. Where a node's bytes
//! sit never enters the answer: a file node follows containment into the unit
//! that instantiates it, exactly as a definition follows containment into the
//! module that declares it.

use crate::graph::CodeGraph;
use crate::id::{GraphNodeId, index_of, position};
use crate::node::GraphNodeKind;

use super::error::GraphAnalysisError;
use super::index::SelectedIndexes;

/// Which container owns each node, and which nodes each container owns.
///
/// Derived once per analysis. Both views come from one walk, so an owner and a
/// membership list can never disagree.
pub struct DeclaredModulePartition {
    owners: Box<[GraphNodeId]>,
    roots: Box<[GraphNodeId]>,
    members: Box<[Box<[GraphNodeId]>]>,
}

impl DeclaredModulePartition {
    /// The nearest container above one node, which is the node itself when it
    /// is a container.
    pub fn owner(&self, node: GraphNodeId) -> Option<GraphNodeId> {
        self.owners.get(index_of(node.index())).copied()
    }

    /// Every partition root, in node-id order.
    pub fn roots(&self) -> &[GraphNodeId] {
        &self.roots
    }

    /// Which container owns each node, in node-id order.
    ///
    /// The dense table the derivation settled, for a consumer that walks every
    /// node rather than asking about one. A public caller asks through
    /// [`DeclaredModulePartition::owner`], which answers for an identity this
    /// graph may not hold.
    pub(crate) fn owners(&self) -> &[GraphNodeId] {
        &self.owners
    }

    /// Every node one root owns, in node-id order, including the root itself.
    pub fn members(&self, root: GraphNodeId) -> Option<&[GraphNodeId]> {
        self.roots
            .binary_search(&root)
            .ok()
            .and_then(|at| self.members.get(at))
            .map(|held| &**held)
    }
}

/// The partial answer one derivation carries while it walks.
struct Ownership {
    containers: Box<[bool]>,
    owners: Box<[Option<GraphNodeId>]>,
    chain: Vec<GraphNodeId>,
}

impl Ownership {
    /// One unsettled ownership table for `graph`.
    fn new(graph: &CodeGraph) -> Self {
        let containers: Box<[bool]> = graph
            .nodes()
            .iter()
            .map(|node| matches!(node.kind(), GraphNodeKind::Container { .. }))
            .collect();
        let owners = vec![None; containers.len()].into_boxed_slice();
        Self {
            containers,
            owners,
            chain: Vec::new(),
        }
    }

    /// The owner one node already settled on, if a previous walk reached it.
    fn settled(&self, node: GraphNodeId) -> Option<GraphNodeId> {
        self.owners.get(index_of(node.index())).copied().flatten()
    }

    /// Whether one node is a container, and therefore its own owner.
    fn is_container(&self, node: GraphNodeId) -> bool {
        self.containers
            .get(index_of(node.index()))
            .copied()
            .unwrap_or(false)
    }

    /// Record one node on the chain currently being walked.
    fn push(&mut self, node: GraphNodeId) {
        self.chain.push(node);
    }

    /// Settle every node of the current chain on one owner.
    fn settle(&mut self, owner: GraphNodeId) {
        for node in self.chain.drain(..) {
            if let Some(slot) = self.owners.get_mut(index_of(node.index())) {
                *slot = Some(owner);
            }
        }
    }

    /// Abandon the current chain, leaving its nodes unsettled.
    fn abandon(&mut self) {
        self.chain.clear();
    }

    /// How many nodes this table addresses.
    fn width(&self) -> usize {
        self.owners.len()
    }

    /// The settled partition, or the first node no container owns.
    fn finish(self) -> Result<DeclaredModulePartition, GraphAnalysisError> {
        let unsettled = self.owners.iter().position(Option::is_none);
        match unsettled {
            Some(at) => Err(GraphAnalysisError::ConsumedGraphInvariant {
                node: GraphNodeId::new(position(at)),
            }),
            None => Ok(assembled(
                self.owners.iter().flatten().copied().collect(),
                &self.containers,
            )),
        }
    }
}

/// Derive the declared module partition of one graph.
///
/// Graph construction proves every node is reachable from a container root, so
/// the refusal below is the exhaustiveness branch of that guarantee rather than
/// a refusal an ordinary repository can reach.
pub(crate) fn derive(
    graph: &CodeGraph,
    indexes: &SelectedIndexes,
) -> Result<DeclaredModulePartition, GraphAnalysisError> {
    let mut ownership = Ownership::new(graph);
    for node in graph.nodes() {
        let owner = nearest_container(&mut ownership, indexes, node.id());
        match owner {
            Some(found) => ownership.settle(found),
            None => ownership.abandon(),
        }
    }
    ownership.finish()
}

/// Walk up the containment chain from one node to the nearest container.
///
/// Iterative, and bounded by the node count, so neither a deep hierarchy nor a
/// containment cycle no validator saw can run without end.
fn nearest_container(
    ownership: &mut Ownership,
    indexes: &SelectedIndexes,
    start: GraphNodeId,
) -> Option<GraphNodeId> {
    let mut current = Some(start);
    for _ in 0..ownership.width() {
        let node = current?;
        let settled = ownership.settled(node);
        match settled {
            Some(owner) => return Some(owner),
            None => ownership.push(node),
        }
        match ownership.is_container(node) {
            true => return Some(node),
            false => current = indexes.parent(node),
        }
    }
    None
}

/// One settled owner table, grouped into the members each root owns.
fn assembled(owners: Box<[GraphNodeId]>, containers: &[bool]) -> DeclaredModulePartition {
    let roots: Box<[GraphNodeId]> = containers
        .iter()
        .enumerate()
        .filter(|(_, container)| **container)
        .map(|(at, _)| GraphNodeId::new(position(at)))
        .collect();
    let members = grouped(&owners, &roots);
    DeclaredModulePartition {
        owners,
        roots,
        members,
    }
}

/// Every root's members, in node-id order, parallel to `roots`.
fn grouped(owners: &[GraphNodeId], roots: &[GraphNodeId]) -> Box<[Box<[GraphNodeId]>]> {
    let mut buckets: Vec<Vec<GraphNodeId>> = vec![Vec::new(); roots.len()];
    for (at, owner) in owners.iter().enumerate() {
        record(&mut buckets, roots, *owner, GraphNodeId::new(position(at)));
    }
    buckets
        .into_iter()
        .map(Vec::into_boxed_slice)
        .collect::<Vec<Box<[GraphNodeId]>>>()
        .into_boxed_slice()
}

/// Record one node among the members of the root that owns it.
fn record(
    buckets: &mut [Vec<GraphNodeId>],
    roots: &[GraphNodeId],
    owner: GraphNodeId,
    node: GraphNodeId,
) {
    let bucket = roots
        .binary_search(&owner)
        .ok()
        .and_then(|at| buckets.get_mut(at));
    if let Some(held) = bucket {
        held.push(node);
    }
}
