//! What one relation answer says about one seed instance.
//!
//! The records are the graph's own, projected and not summarized. Parallel
//! edges stay parallel, a possible edge stays possible, a distance is the
//! minimum the walk measured, and an unresolved reference stays visible with
//! its gaps even where no edge answered it. Nothing here merges two pieces of
//! evidence into one, because two pieces of evidence are what a caller asked
//! about.

use pedant_graph::{ContainmentEdge, GraphEdge, GraphNodeId, GraphReference};
use serde::Serialize;

use crate::index::{ProjectHandle, StructureCoverage};

use super::entity::NavigationEntity;

/// Everything the induced selection of one walk retained.
///
/// Named rather than spelled inline because the three collections are one
/// answer: they are selected together, by one walk, and a constructor that took
/// them apart would let a caller state edges and containment rows from two
/// different selections.
pub(super) type InducedSelection = (
    Box<[GraphEdge]>,
    Box<[ContainmentEdge]>,
    Box<[GraphReference]>,
);

/// One node one walk reached, and how far away it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RelationNeighbor {
    node: GraphNodeId,
    distance: u32,
}

impl RelationNeighbor {
    /// One reached node at its minimum distance.
    pub(super) fn stated(node: GraphNodeId, distance: u32) -> Self {
        Self { node, distance }
    }

    /// The node the walk reached, inside the neighborhood's own project graph.
    pub fn node(self) -> GraphNodeId {
        self.node
    }

    /// The minimum number of selected steps that reach it.
    pub fn distance(self) -> u32 {
        self.distance
    }
}

/// One seed instance's neighborhood in one project graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelationNeighborhood {
    project: ProjectHandle,
    seed: GraphNodeId,
    coverage: StructureCoverage,
    neighbors: Box<[RelationNeighbor]>,
    nodes: Box<[NavigationEntity]>,
    edges: Box<[GraphEdge]>,
    containment: Box<[ContainmentEdge]>,
    unresolved: Box<[GraphReference]>,
}

impl RelationNeighborhood {
    /// Everything one walk of one seed instance retained.
    pub(super) fn stated(
        selected: (ProjectHandle, GraphNodeId, StructureCoverage),
        reached: (Box<[RelationNeighbor]>, Box<[NavigationEntity]>),
        induced: InducedSelection,
    ) -> Self {
        let (project, seed, coverage) = selected;
        let (neighbors, nodes) = reached;
        let (edges, containment, unresolved) = induced;
        Self {
            project,
            seed,
            coverage,
            neighbors,
            nodes,
            edges,
            containment,
            unresolved,
        }
    }

    /// The project graph this neighborhood was walked in.
    pub fn project(&self) -> ProjectHandle {
        self.project
    }

    /// The seed instance the walk started at.
    pub fn seed(&self) -> GraphNodeId {
        self.seed
    }

    /// What evidence stands behind it.
    pub fn coverage(&self) -> StructureCoverage {
        self.coverage
    }

    /// Every node the walk reached beyond the seed, in distance then node
    /// order.
    pub fn neighbors(&self) -> &[RelationNeighbor] {
        &self.neighbors
    }

    /// Every node of the induced selection, in node-id order, the seed
    /// included.
    pub fn nodes(&self) -> &[NavigationEntity] {
        &self.nodes
    }

    /// Every selected edge whose ends are both selected, in edge-id order.
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    /// Every containment edge whose ends are both selected, in child order.
    pub fn containment(&self) -> &[ContainmentEdge] {
        &self.containment
    }

    /// Every reference a selected node states that no edge answered.
    pub fn unresolved(&self) -> &[GraphReference] {
        &self.unresolved
    }
}
