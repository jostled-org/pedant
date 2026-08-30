//! One graph node's membership, read from the node's side.
//!
//! A relation answer walks a graph and has to say what each node it reached is,
//! which is the question a `StructureInstance` answers backwards. The index
//! seals both directions of one fact rather than scanning every retained
//! structure per query: the map is minted where the join is, so the two cannot
//! disagree about what a node declares.

use pedant_graph::GraphNodeId;

use super::project::ProjectId;
use super::structure::StructureId;

/// What one project graph's node declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct NodeMembership {
    project: ProjectId,
    node: GraphNodeId,
    structure: StructureId,
}

impl NodeMembership {
    /// The structure one project's node declares.
    pub(super) fn stated(project: ProjectId, node: GraphNodeId, structure: StructureId) -> Self {
        Self {
            project,
            node,
            structure,
        }
    }

    /// What this membership is keyed by.
    pub(super) fn key(self) -> (ProjectId, GraphNodeId) {
        (self.project, self.node)
    }

    /// The structure it names.
    pub(super) fn structure(self) -> StructureId {
        self.structure
    }
}
