//! How many selected edges each node states at each of its ends.
//!
//! The answer is the length of the adjacency lists one selection produced, so it
//! costs one read of the shared indexes and reaches the raw graph not at all.

use crate::id::{GraphNodeId, position};

use super::index::{AnalysisContext, SelectedIndexes};

/// How many selected edges arrive at and leave one node.
///
/// Parallel edges count separately and a self-loop counts once at each end,
/// because each is distinct evidence rather than one relation restated.
#[derive(Clone, Copy, Debug)]
pub struct DegreeCentrality {
    node: GraphNodeId,
    incoming: u32,
    outgoing: u32,
}

impl DegreeCentrality {
    /// The node these counts describe.
    pub fn node(self) -> GraphNodeId {
        self.node
    }

    /// How many selected edges arrive at it.
    pub fn incoming(self) -> u32 {
        self.incoming
    }

    /// How many selected edges leave it.
    pub fn outgoing(self) -> u32 {
        self.outgoing
    }
}

/// Every node's selected degrees, in raw node-id order.
pub(crate) fn degree(analysis: &AnalysisContext<'_>) -> Box<[DegreeCentrality]> {
    let indexes = analysis.indexes();
    (0..indexes.node_count())
        .map(|at| counted(indexes, GraphNodeId::new(position(at))))
        .collect()
}

/// One node's adjacency lengths, which are its selected degrees.
///
/// Both counts fit their width because analysis construction already refused a
/// selection above the stated selected-edge ceiling.
fn counted(indexes: &SelectedIndexes, node: GraphNodeId) -> DegreeCentrality {
    DegreeCentrality {
        node,
        incoming: position(indexes.incoming(node).len()),
        outgoing: position(indexes.outgoing(node).len()),
    }
}
