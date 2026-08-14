//! Why an analysis or one of its queries refused.
//!
//! Every variant names the exact identity, count, or ceiling that failed. No
//! refusal answers with a partial result, and none panics.

use crate::id::GraphNodeId;

/// A refusal taken while building or querying one analysis.
#[derive(Debug, thiserror::Error)]
pub enum GraphAnalysisError {
    /// A query named a node this graph holds no record for.
    #[error("node {} is not in this graph", node.index())]
    UnknownNode {
        /// The identity that named nothing.
        node: GraphNodeId,
    },
    /// The graph states more nodes than the stated ceiling admits.
    #[error("the graph states {count} nodes, above the ceiling of {limit}")]
    NodeLimitExceeded {
        /// How many nodes the graph states.
        count: u32,
        /// The ceiling the caller stated.
        limit: u32,
    },
    /// The selection admits more edges than the stated ceiling allows.
    #[error("the selection admits {count} edges, above the ceiling of {limit}")]
    SelectedEdgeLimitExceeded {
        /// How many edges the selection admits.
        count: u32,
        /// The ceiling the caller stated.
        limit: u32,
    },
    /// A query asked to walk further than the stated ceiling allows.
    #[error("a depth of {requested} is above the ceiling of {limit}")]
    DepthLimitExceeded {
        /// The depth the query asked for.
        requested: u32,
        /// The ceiling the caller stated.
        limit: u32,
    },
    /// Betweenness over this selection costs more than the stated ceiling.
    #[error("betweenness needs {required} steps, above the ceiling of {limit}")]
    BetweennessWorkLimitExceeded {
        /// The upper bound on the work the selection would cost.
        required: u64,
        /// The ceiling the caller stated.
        limit: u64,
    },
    /// The betweenness work bound does not fit the width it is counted in.
    #[error("the betweenness work bound overflows its own counter")]
    BetweennessWorkOverflow,
    /// Partition derivation observed a node no container owns.
    ///
    /// Graph construction proves every node is reachable from one container
    /// root, and no public constructor can state a graph that is not, so this
    /// is the exhaustiveness branch of a guarantee rather than a reachable
    /// refusal.
    #[error("node {} is owned by no container", node.index())]
    ConsumedGraphInvariant {
        /// The node no container ancestor answers for.
        node: GraphNodeId,
    },
}
