//! The tables one Rust projection resolves its joins through.
//!
//! Containers are per report unit; file nodes are qualified by the snapshot
//! unit that instantiates them, because a source's graph identity is the pair
//! of the path and the unit reading it. Definition nodes are dense in report
//! order. Nothing here reads a repository: every table is built from the two
//! supplied values.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::resolution::rust::RustSnapshotUnitId;
use pedant_types::ResolutionTier;

use crate::containment::ContainmentEdge;
use crate::edge::EdgeDraft;
use crate::error::GraphBuildError;
use crate::graph::{CodeGraph, GraphRecords, RecordCapacity, reserved};
use crate::id::{GraphEdgeId, GraphNodeId, GraphReferenceId, index_of};
use crate::limits::{GraphCollection, GraphLimits};
use crate::node::NodeDraft;
use crate::reference::ReferenceDraft;

/// One snapshot unit's container, the report unit that bound it, and the file
/// nodes it instantiates.
struct UnitScope {
    owner: u32,
    container: GraphNodeId,
    files: BTreeMap<Arc<str>, GraphNodeId>,
}

/// What one report unit resolved to.
struct BoundUnit {
    container: GraphNodeId,
    snapshot_unit: RustSnapshotUnitId,
}

/// How many records the supplied inputs state before the first pass runs.
///
/// File nodes are not counted: which sources a bound unit instantiates is known
/// only once the sources pass has read them, so the node reservation covers the
/// containers and the definitions alone.
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

/// Every table one projection fills, beside the record store it fills them from.
pub(crate) struct ProjectionState {
    records: GraphRecords,
    scopes: BTreeMap<RustSnapshotUnitId, UnitScope>,
    units: Vec<BoundUnit>,
    definitions: Vec<GraphNodeId>,
}

impl ProjectionState {
    /// An empty projection bounded by `limits` and sized for `capacity`.
    ///
    /// The sole constructor, reached only after both identity checks pass, so
    /// no record is allocated for a pairing this crate is going to refuse.
    pub(crate) fn new(limits: GraphLimits, capacity: ProjectionCapacity) -> Self {
        let ceiling = limits.ceiling(GraphCollection::Node);
        Self {
            records: GraphRecords::new(limits, capacity.records()),
            scopes: BTreeMap::new(),
            units: Vec::with_capacity(reserved(capacity.units, ceiling)),
            definitions: Vec::with_capacity(reserved(capacity.definitions, ceiling)),
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

    /// Bind one report unit to its container and its snapshot unit.
    ///
    /// A snapshot unit is bound by one report unit. The report unit already
    /// holding the scope is answered rather than merged, because two report
    /// units sharing one build unit would give every source of that unit two
    /// owners, and the collision must be named where it happens.
    pub(crate) fn bind_unit(
        &mut self,
        container: GraphNodeId,
        unit: (RustSnapshotUnitId, u32),
    ) -> Option<u32> {
        let (snapshot_unit, reported) = unit;
        match self.scopes.get(&snapshot_unit) {
            Some(held) => Some(held.owner),
            None => {
                self.scopes.insert(
                    snapshot_unit,
                    UnitScope {
                        owner: reported,
                        container,
                        files: BTreeMap::new(),
                    },
                );
                self.units.push(BoundUnit {
                    container,
                    snapshot_unit,
                });
                None
            }
        }
    }

    /// The container node one report unit owns.
    pub(crate) fn container(&self, unit: u32) -> Option<GraphNodeId> {
        self.units.get(index_of(unit)).map(|bound| bound.container)
    }

    /// The container node one snapshot unit owns.
    pub(crate) fn snapshot_container(&self, unit: RustSnapshotUnitId) -> Option<GraphNodeId> {
        self.scopes.get(&unit).map(|scope| scope.container)
    }

    /// The snapshot unit one report unit is bound to.
    pub(crate) fn snapshot_unit(&self, unit: u32) -> Option<RustSnapshotUnitId> {
        self.units
            .get(index_of(unit))
            .map(|bound| bound.snapshot_unit)
    }

    /// Qualify one normalized path with the snapshot unit reading it, inserting
    /// the file node the first time that pair is seen.
    ///
    /// `None` names a snapshot unit this projection bound no scope for. The
    /// refusal belongs to the validation owner that states it, so no table here
    /// builds a [`GraphBuildError`] of its own.
    pub(crate) fn qualify_source(
        &mut self,
        snapshot_unit: RustSnapshotUnitId,
        path: &Arc<str>,
        draft: NodeDraft,
    ) -> Result<Option<GraphNodeId>, GraphBuildError> {
        match self.file_node(snapshot_unit, path) {
            Some(found) => Ok(Some(found)),
            None => self.instantiate_source(snapshot_unit, path, draft),
        }
    }

    /// Mint the file node one unit-and-path pair takes the first time it is
    /// seen.
    ///
    /// The scope is proved before the node exists, because a node whose pair
    /// nothing recorded would be looked up again, reported as a missing source,
    /// and minted a second time for every further site at that path.
    fn instantiate_source(
        &mut self,
        snapshot_unit: RustSnapshotUnitId,
        path: &Arc<str>,
        draft: NodeDraft,
    ) -> Result<Option<GraphNodeId>, GraphBuildError> {
        match self.scopes.get_mut(&snapshot_unit) {
            Some(scope) => {
                let node = self.records.insert_node(draft)?;
                scope.files.insert(Arc::clone(path), node);
                Ok(Some(node))
            }
            None => Ok(None),
        }
    }

    /// The file node one snapshot unit reads `path` through.
    pub(crate) fn file_node(&self, unit: RustSnapshotUnitId, path: &str) -> Option<GraphNodeId> {
        self.scopes
            .get(&unit)
            .and_then(|scope| scope.files.get(path))
            .copied()
    }

    /// Record the node one report definition produced.
    pub(crate) fn bind_definition(&mut self, node: GraphNodeId) {
        self.definitions.push(node);
    }

    /// The node one report definition produced.
    pub(crate) fn definition_node(&self, definition: u32) -> Option<GraphNodeId> {
        self.definitions.get(index_of(definition)).copied()
    }

    /// Every containment edge stated so far.
    pub(crate) fn containment(&self) -> &[ContainmentEdge] {
        self.records.containment()
    }

    /// How many nodes this projection has produced.
    pub(crate) fn node_count(&self) -> usize {
        self.records.node_count()
    }

    /// Seal this projection into one immutable graph.
    pub(crate) fn finish(self, tier: ResolutionTier) -> CodeGraph {
        self.records.finish(tier)
    }
}
