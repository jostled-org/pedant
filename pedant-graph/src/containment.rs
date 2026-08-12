//! The logical hierarchy relation, separate from every other edge.

use serde::Serialize;

use crate::id::GraphNodeId;

/// One logical-ownership edge between a parent node and the node it owns.
///
/// Containment is the sole hierarchy relation and never appears in
/// [`crate::CodeGraph::edges`]: a reference graph may be cyclic and
/// hub-dominated while the hierarchy stays a clean forest.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainmentEdge {
    parent: GraphNodeId,
    child: GraphNodeId,
}

impl ContainmentEdge {
    pub(crate) fn new(parent: GraphNodeId, child: GraphNodeId) -> Self {
        Self { parent, child }
    }

    /// The node that logically owns the child.
    pub fn parent(&self) -> GraphNodeId {
        self.parent
    }

    /// The owned node.
    pub fn child(&self) -> GraphNodeId {
        self.child
    }
}
