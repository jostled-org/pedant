//! What one derived answer is retained under, and what is retained.
//!
//! A product's identity is the graph state holding it, the edge selection it
//! was answered over, the operation asked, and the complete arguments that
//! operation took. Ceilings are deliberately absent: a lower ceiling changes
//! whether an answer may be returned, never what the answer is, and the store
//! that holds these values proves the applicable ceiling again before it hands
//! one back.
//!
//! The claim carries the operation, so key equality already fixes which shape
//! the value filed under it has. The reading that unwraps a retained value and
//! the constructor that states a fresh one are therefore stated once per shape
//! here, beside the claim that decides them.

use std::sync::Arc;

use crate::analysis::{
    BetweennessCentrality, CondensationGraph, DegreeCentrality, GraphComponents, GraphDirection,
    GraphDivergence, GraphEdgeSelection, GraphNeighbor, GraphPath, GraphSubgraph,
    LayoutAssistMetadata,
};
use crate::id::GraphNodeId;

use super::storage::BoundedStore;

/// Which operation, over which complete arguments, one product answers.
///
/// One variant per published derived operation. An argument a caller can vary
/// is a field here, so changing a node, a depth, a direction, a source, or a
/// target states a different product rather than reusing the last one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProductOperation {
    /// A bounded neighborhood around one node.
    Neighbors {
        /// The node the walk started at.
        node: GraphNodeId,
        /// How many selected steps it was allowed to take.
        depth: u32,
        /// Which way it followed a selected edge.
        direction: GraphDirection,
    },
    /// The shortest route between one ordered node pair, reachable or not.
    Path {
        /// The node the route leaves.
        source: GraphNodeId,
        /// The node the route reaches.
        target: GraphNodeId,
    },
    /// The selection induced by one bounded walk.
    Subgraph {
        /// The node the walk started at.
        seed: GraphNodeId,
        /// How many selected steps it was allowed to take.
        depth: u32,
        /// Which way it followed a selected edge.
        direction: GraphDirection,
    },
    /// Every node's selected degrees.
    Degree,
    /// Every node's directed betweenness.
    Betweenness,
    /// The strongly connected components of the selected topology.
    Components,
    /// The same topology with every component contracted.
    Condensation,
    /// What the selected topology says about the declared partition.
    Divergence,
    /// Every admitted node and selected edge, described for a consumer.
    Layout,
}

/// The complete identity one retained product answers for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProductClaim {
    selection: GraphEdgeSelection,
    operation: ProductOperation,
}

impl ProductClaim {
    /// One operation, over one selection of one graph's edges.
    pub(crate) fn new(selection: GraphEdgeSelection, operation: ProductOperation) -> Self {
        Self {
            selection,
            operation,
        }
    }
}

/// One retained answer, held exactly as the caller is handed it.
///
/// Shared rather than copied: a repeated equal operation answers with the same
/// allocation, and a value a caller still holds outlives the entry it came
/// from.
#[derive(Clone)]
pub(crate) enum ProductValue {
    /// A bounded neighborhood.
    Neighbors(Arc<[GraphNeighbor]>),
    /// A shortest route, or the proven absence of one.
    Path(Option<Arc<GraphPath>>),
    /// An induced selection.
    Subgraph(Arc<GraphSubgraph>),
    /// Every node's selected degrees.
    Degree(Arc<[DegreeCentrality]>),
    /// Every node's directed betweenness.
    Betweenness(Arc<[BetweennessCentrality]>),
    /// The strongly connected components.
    Components(Arc<GraphComponents>),
    /// The contracted acyclic view.
    Condensation(Arc<CondensationGraph>),
    /// The declared-partition evidence.
    Divergence(Arc<GraphDivergence>),
    /// The coordinate-free layout metadata.
    Layout(Arc<LayoutAssistMetadata>),
}

/// One answer shape, beside the retained state that holds it.
///
/// The one place the rule "a claim decides its variant" is written down. A
/// claim carries the operation, so key equality already fixes which variant the
/// value filed under it has; what is left is the reading that unwraps it and
/// the constructor that states a fresh one, and both belong to the shape rather
/// than to each operation that asks for it.
pub(crate) trait Product: Clone {
    /// This shape, when the retained value holds it.
    ///
    /// A value of another variant is not this shape: the caller derives one
    /// rather than reinterpreting the answer to a different question.
    fn read(value: ProductValue) -> Option<Self>;

    /// The retained state one answer of this shape is held as.
    fn state(self) -> ProductValue;
}

/// State one shape's pairing with the variant that retains it.
///
/// One row per shape, read in both directions. The reading and the constructor
/// are generated from that row, so they name one variant and cannot drift
/// apart, and a shape added without a variant to hold it does not compile.
macro_rules! stated_products {
    ($($variant:ident => $shape:ty,)+) => {
        $(
            impl Product for $shape {
                fn read(value: ProductValue) -> Option<Self> {
                    match value {
                        ProductValue::$variant(held) => Some(held),
                        _ => None,
                    }
                }

                fn state(self) -> ProductValue {
                    ProductValue::$variant(self)
                }
            }
        )+
    };
}

stated_products! {
    Neighbors => Arc<[GraphNeighbor]>,
    Path => Option<Arc<GraphPath>>,
    Subgraph => Arc<GraphSubgraph>,
    Degree => Arc<[DegreeCentrality]>,
    Betweenness => Arc<[BetweennessCentrality]>,
    Components => Arc<GraphComponents>,
    Condensation => Arc<CondensationGraph>,
    Divergence => Arc<GraphDivergence>,
    Layout => Arc<LayoutAssistMetadata>,
}

/// The bounded products one cached graph retains.
///
/// The pairing is stated once, here: a complete claim selects an entry, and the
/// entry holds the value that claim's operation answers with.
pub(crate) type ProductStore = BoundedStore<ProductClaim, ProductValue>;
