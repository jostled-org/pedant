//! The immutable graph value and the one checked store every build inserts
//! through.

use pedant_types::ResolutionTier;
use serde::Serialize;

use crate::containment::ContainmentEdge;
use crate::edge::{EdgeDraft, GraphEdge, GraphEdgeOrigin};
use crate::error::GraphBuildError;
use crate::id::{GraphEdgeId, GraphNodeId, GraphReferenceId, index_of, position};
use crate::limits::{GraphCollection, GraphLimits};
use crate::node::{GraphNode, NodeDraft};
use crate::reference::{GraphReference, ReferenceDraft};

/// One deterministic, language-tagged code topology.
///
/// Immutable after construction: fields are private, every accessor borrows,
/// and the value implements neither `Clone` nor `Deserialize`. A consumer that
/// wants a graph builds one from the facts it holds rather than hydrating one
/// whose records nothing validated.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct CodeGraph {
    schema_version: u32,
    tier: ResolutionTier,
    nodes: Box<[GraphNode]>,
    containment: Box<[ContainmentEdge]>,
    references: Box<[GraphReference]>,
    edges: Box<[GraphEdge]>,
}

impl CodeGraph {
    /// The version of the serialized topology contract this crate emits.
    pub const SCHEMA_VERSION: u32 = 1;

    /// The version of the serialized topology contract this value carries.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Which resolution mechanism produced the facts behind this graph.
    pub fn tier(&self) -> ResolutionTier {
        self.tier
    }

    /// Every node, indexed by its own dense identity.
    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }

    /// The node one identity selects.
    pub fn node(&self, id: GraphNodeId) -> Option<&GraphNode> {
        self.nodes.get(index_of(id.index()))
    }

    /// Every containment edge, sorted by child.
    pub fn containment(&self) -> &[ContainmentEdge] {
        &self.containment
    }

    /// Every reference record, indexed by its own dense identity.
    pub fn references(&self) -> &[GraphReference] {
        &self.references
    }

    /// The reference record one identity selects.
    pub fn reference(&self, id: GraphReferenceId) -> Option<&GraphReference> {
        self.references.get(index_of(id.index()))
    }

    /// Every edge, indexed by its own dense identity.
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    /// The edge one identity selects.
    pub fn edge(&self, id: GraphEdgeId) -> Option<&GraphEdge> {
        self.edges.get(index_of(id.index()))
    }

    /// Whether this graph is still admissible under one set of ceilings.
    ///
    /// A graph is reused rather than rebuilt only when the caller's current
    /// ceilings would have admitted it. The collections are compared in the
    /// order a build fills them — nodes, then reference records, then edges —
    /// so the refusal a lowered ceiling produces names the collection direct
    /// construction would have reached first.
    pub(crate) fn admissible(&self, limits: GraphLimits) -> Result<(), GraphBuildError> {
        [
            (GraphCollection::Node, self.nodes.len()),
            (GraphCollection::Reference, self.references.len()),
            (GraphCollection::Edge, self.edges.len()),
        ]
        .into_iter()
        .find(|(collection, held)| position(*held) > limits.ceiling(*collection))
        .map_or(Ok(()), |(collection, _)| {
            Err(GraphBuildError::CapacityExceeded {
                collection,
                limit: limits.ceiling(collection),
            })
        })
    }
}

/// How many records one build states before its first pass.
///
/// Every count is a stated size, never a ceiling: the store reserves the
/// smaller of the count and the limit that collection refuses at.
pub(crate) struct RecordCapacity {
    /// The unit containers and definition nodes the report states.
    pub(crate) nodes: usize,
    /// The reference records the report states.
    pub(crate) references: usize,
    /// The dependency and candidate edges the inputs state.
    pub(crate) edges: usize,
}

/// The growing record store one build inserts through.
///
/// Every identity is minted by [`GraphRecords::admit`], so the configured
/// ceiling and the fixed-width identity ceiling are one check and a refusal
/// never leaves a partially inserted record behind. [`GraphRecords::contain`]
/// mints nothing: it states a relation between identities this store has
/// already issued.
pub(crate) struct GraphRecords {
    limits: GraphLimits,
    nodes: Vec<GraphNode>,
    containment: Vec<ContainmentEdge>,
    references: Vec<(GraphReferenceId, ReferenceDraft)>,
    reference_edges: Vec<Vec<GraphEdgeId>>,
    edges: Vec<GraphEdge>,
}

impl GraphRecords {
    /// An empty store bounded by `limits`, sized for `capacity`.
    pub(crate) fn new(limits: GraphLimits, capacity: RecordCapacity) -> Self {
        let nodes = reserved(capacity.nodes, limits.ceiling(GraphCollection::Node));
        let references = reserved(
            capacity.references,
            limits.ceiling(GraphCollection::Reference),
        );
        Self {
            limits,
            nodes: Vec::with_capacity(nodes),
            containment: Vec::with_capacity(nodes),
            references: Vec::with_capacity(references),
            reference_edges: Vec::with_capacity(references),
            edges: Vec::with_capacity(reserved(
                capacity.edges,
                limits.ceiling(GraphCollection::Edge),
            )),
        }
    }

    /// Append one node, or refuse before the store is touched.
    pub(crate) fn insert_node(&mut self, draft: NodeDraft) -> Result<GraphNodeId, GraphBuildError> {
        let index = self.admit(GraphCollection::Node)?;
        let id = GraphNodeId::new(index);
        self.nodes.push(GraphNode::new(id, draft));
        Ok(id)
    }

    /// Append one reference record, or refuse before the store is touched.
    pub(crate) fn insert_reference(
        &mut self,
        draft: ReferenceDraft,
    ) -> Result<GraphReferenceId, GraphBuildError> {
        let index = self.admit(GraphCollection::Reference)?;
        let id = GraphReferenceId::new(index);
        self.references.push((id, draft));
        self.reference_edges.push(Vec::new());
        Ok(id)
    }

    /// Append one edge and link it to the record that produced it, or refuse
    /// before the store is touched.
    ///
    /// An edge whose origin names a reference is attached to that record here,
    /// so minting and linking are one step and no identity can reach
    /// [`GraphReference::edges`] without an edge behind it. A reference that
    /// answers for no record refuses before the edge exists: dropping the link
    /// would leave the edge in the graph and its record claiming it produced
    /// nothing.
    pub(crate) fn insert_edge(&mut self, draft: EdgeDraft) -> Result<GraphEdgeId, GraphBuildError> {
        let index = self.admit(GraphCollection::Edge)?;
        let id = GraphEdgeId::new(index);
        self.link_origin(&draft.origin, id)?;
        self.edges.push(GraphEdge::new(id, draft));
        Ok(id)
    }

    /// Record that the reference an edge names produced it.
    ///
    /// A dependency edge links nothing: the declaration it carries is its own
    /// evidence, and no record claims it.
    fn link_origin(
        &mut self,
        origin: &GraphEdgeOrigin,
        edge: GraphEdgeId,
    ) -> Result<(), GraphBuildError> {
        let reference = match origin {
            GraphEdgeOrigin::Reference { reference } => *reference,
            GraphEdgeOrigin::Dependency { .. } => return Ok(()),
        };
        match self.reference_edges.get_mut(index_of(reference.index())) {
            Some(produced) => {
                produced.push(edge);
                Ok(())
            }
            None => Err(GraphBuildError::MissingReferenceRecord {
                reference: reference.index(),
            }),
        }
    }

    /// Record that `parent` logically owns `child`.
    pub(crate) fn contain(&mut self, parent: GraphNodeId, child: GraphNodeId) {
        self.containment.push(ContainmentEdge::new(parent, child));
    }

    /// Every containment edge stated so far.
    pub(crate) fn containment(&self) -> &[ContainmentEdge] {
        &self.containment
    }

    /// How many nodes the store holds.
    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Seal the store into one immutable graph.
    ///
    /// Containment sorts by child then parent, which is a total order over the
    /// stated edges rather than one that holds only while a separate validator
    /// rejects a twice-claimed child. Each reference record keeps the identity
    /// its insertion minted, so a record can never be renumbered away from the
    /// edges that name it.
    pub(crate) fn finish(mut self, tier: ResolutionTier) -> CodeGraph {
        self.containment
            .sort_unstable_by_key(|edge| (edge.child(), edge.parent()));
        let references = self
            .references
            .into_iter()
            .zip(self.reference_edges)
            .map(|((id, draft), edges)| GraphReference::new(id, draft, edges.into_boxed_slice()))
            .collect();
        CodeGraph {
            schema_version: CodeGraph::SCHEMA_VERSION,
            tier,
            nodes: self.nodes.into_boxed_slice(),
            containment: self.containment.into_boxed_slice(),
            references,
            edges: self.edges.into_boxed_slice(),
        }
    }

    /// The identity the next entry of `collection` would take.
    ///
    /// The one place a graph identity is minted: it proves the configured
    /// ceiling and the fixed-width ceiling together, before any mutation. The
    /// count is read from the named collection rather than supplied, so an
    /// identity can never be minted from the length of another slice.
    fn admit(&self, collection: GraphCollection) -> Result<u32, GraphBuildError> {
        let count = match collection {
            GraphCollection::Node => self.nodes.len(),
            GraphCollection::Reference => self.references.len(),
            GraphCollection::Edge => self.edges.len(),
        };
        let limit = self.limits.ceiling(collection);
        u32::try_from(count)
            .ok()
            .filter(|next| *next < limit)
            .ok_or(GraphBuildError::CapacityExceeded { collection, limit })
    }
}

/// How much one collection reserves for a stated count.
///
/// Never more than the ceiling that collection refuses at, so a build the
/// limits are going to refuse allocates no more than the graph it would have
/// admitted. Every table sized from a stated count reserves through here, so
/// one rule bounds them all.
pub(crate) fn reserved(stated: usize, ceiling: u32) -> usize {
    stated.min(index_of(ceiling))
}
