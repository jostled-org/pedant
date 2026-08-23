//! The tables one assembly resolves its symbolic joins through.
//!
//! Containers are per planned unit; file nodes are qualified by the unit that
//! instantiates them, because a source's graph identity is the pair of the path
//! and the unit reading it. Definition nodes are keyed by the stable identity
//! the plan states, so a join made before any identity was minted still names
//! exactly one node. Nothing here reads a repository: every table is filled
//! from one plan.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, DefaultHasher};
use std::sync::Arc;

use pedant_types::ResolutionTier;

use crate::containment::ContainmentEdge;
use crate::edge::EdgeDraft;
use crate::error::GraphBuildError;
use crate::graph::{CodeGraph, GraphRecords, RecordCapacity, reserved};
use crate::id::{GraphEdgeId, GraphNodeId, GraphReferenceId, index_of};
use crate::limits::{GraphCollection, GraphLimits};
use crate::node::NodeDraft;
use crate::reference::ReferenceDraft;

use super::placement::DefinitionIdentity;
use super::validation;

/// Every file node one planned unit reads, by normalized path.
///
/// Ordered, because a unit's sources are minted in the snapshot's own order and
/// the scope is what proves a path was minted at all.
pub(crate) type SourceScope = BTreeMap<Arc<str>, GraphNodeId>;

/// Every node one stable definition identity produced, by that identity.
///
/// Hashed rather than ordered: a probe reads the key once instead of walking
/// levels of comparison over four strings and a span. The hasher is named
/// because this crate states no dependency of its own, so the standard
/// fixed-key one is what it has, and because the seeded default would vary a
/// table two equal plans must fill identically. Order reaches nothing either
/// way — the table is inserted into and probed, never iterated.
type DefinitionScope =
    HashMap<Arc<DefinitionIdentity>, GraphNodeId, BuildHasherDefault<DefaultHasher>>;

/// How many records the supplied inputs state before the first pass runs.
///
/// File nodes are not counted: which sources a bound unit instantiates is known
/// only once the planner has read them, so the node reservation covers the
/// containers and the definitions alone.
#[derive(Clone, Copy)]
pub(crate) struct ProjectionCapacity {
    /// The report units, one container node each.
    pub(crate) units: usize,
    /// The report definitions, one node each.
    pub(crate) definitions: usize,
    /// The report references, one record each.
    pub(crate) references: usize,
    /// The snapshot dependency edges beside the stated candidates.
    pub(crate) edges: usize,
}

impl ProjectionCapacity {
    /// The store sizes these counts imply.
    fn records(&self) -> RecordCapacity {
        RecordCapacity {
            nodes: self.units.saturating_add(self.definitions),
            references: self.references,
            edges: self.edges,
        }
    }
}

/// Every table one assembly fills, beside the record store it fills them from.
pub(crate) struct ProjectionState {
    records: GraphRecords,
    containers: Vec<GraphNodeId>,
    files: Vec<SourceScope>,
    definitions: DefinitionScope,
}

impl ProjectionState {
    /// An empty assembly bounded by `limits` and sized for `capacity`.
    ///
    /// The sole constructor, reached only after the plan proved every join, so
    /// no record is allocated for a pairing this crate is going to refuse.
    pub(crate) fn new(limits: GraphLimits, capacity: ProjectionCapacity) -> Self {
        let ceiling = limits.ceiling(GraphCollection::Node);
        let units = reserved(capacity.units, ceiling);
        let definitions = reserved(capacity.definitions, ceiling);
        Self {
            records: GraphRecords::new(limits, capacity.records()),
            containers: Vec::with_capacity(units),
            files: Vec::with_capacity(units),
            definitions: DefinitionScope::with_capacity_and_hasher(
                definitions,
                BuildHasherDefault::default(),
            ),
        }
    }

    /// Insert one node through the single checked insertion owner.
    pub(crate) fn insert_node(&mut self, draft: NodeDraft) -> Result<GraphNodeId, GraphBuildError> {
        self.records.insert_node(draft)
    }

    /// Insert one reference record through the single checked insertion owner.
    pub(crate) fn insert_reference(
        &mut self,
        draft: ReferenceDraft,
    ) -> Result<GraphReferenceId, GraphBuildError> {
        self.records.insert_reference(draft)
    }

    /// Insert one edge through the single checked insertion owner.
    pub(crate) fn insert_edge(&mut self, draft: EdgeDraft) -> Result<GraphEdgeId, GraphBuildError> {
        self.records.insert_edge(draft)
    }

    /// Record that `parent` logically owns `child`.
    pub(crate) fn contain(&mut self, parent: GraphNodeId, child: GraphNodeId) {
        self.records.contain(parent, child);
    }

    /// Record the container node one planned unit took.
    ///
    /// Units are bound in plan order, so a container's position in this table
    /// is the unit's own position and no separate key is needed.
    pub(crate) fn bind_container(&mut self, container: GraphNodeId) {
        self.containers.push(container);
        self.files.push(SourceScope::new());
    }

    /// The container node one planned unit owns.
    pub(crate) fn container(&self, unit: u32) -> Option<GraphNodeId> {
        self.containers.get(index_of(unit)).copied()
    }

    /// Record the file node one unit reads one normalized path through.
    ///
    /// The scope the binding belongs in is proved rather than assumed, so a
    /// unit position this assembly bound no container for is refused where the
    /// binding is made instead of leaving the file node unreachable.
    pub(crate) fn bind_file(
        &mut self,
        unit: u32,
        path: &Arc<str>,
        node: GraphNodeId,
    ) -> Result<(), GraphBuildError> {
        let scope = validation::unit_scope(self.files.get_mut(index_of(unit)), unit)?;
        scope.insert(Arc::clone(path), node);
        Ok(())
    }

    /// The file node one unit reads `path` through.
    pub(crate) fn file(&self, unit: u32, path: &str) -> Option<GraphNodeId> {
        self.files
            .get(index_of(unit))
            .and_then(|scope| scope.get(path))
            .copied()
    }

    /// Record the node one stable definition identity produced.
    ///
    /// The handle the plan already holds is shared into the table rather than
    /// copied, so one identity is retained per definition however many joins
    /// name it.
    pub(crate) fn bind_definition(
        &mut self,
        identity: &Arc<DefinitionIdentity>,
        node: GraphNodeId,
    ) {
        self.definitions.insert(Arc::clone(identity), node);
    }

    /// The node one stable definition identity produced.
    pub(crate) fn definition(&self, identity: &DefinitionIdentity) -> Option<GraphNodeId> {
        self.definitions.get(identity).copied()
    }

    /// Every containment edge stated so far.
    pub(crate) fn containment(&self) -> &[ContainmentEdge] {
        self.records.containment()
    }

    /// How many nodes this assembly has produced.
    pub(crate) fn node_count(&self) -> usize {
        self.records.node_count()
    }

    /// Seal this assembly into one immutable graph.
    pub(crate) fn finish(self, tier: ResolutionTier) -> CodeGraph {
        self.records.finish(tier)
    }
}
