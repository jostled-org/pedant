//! Derived analysis over one borrowed graph.
//!
//! The family borrows a valid [`crate::CodeGraph`]. It never builds, clones,
//! deserializes, mutates, or revalidates one, and it adds no field to the
//! version-1 wire contract.

/// Directed betweenness over the selected topology.
pub(crate) mod betweenness;
/// Strongly connected components and the acyclic view they produce.
pub(crate) mod components;
/// How many selected edges each node states at each of its ends.
pub(crate) mod degree;
/// Where the declared module tree and the selected topology disagree.
pub(crate) mod divergence;
/// Why an analysis or one of its queries refused.
mod error;
/// The borrowed analysis view and the indexes every query reads.
pub(crate) mod index;
/// What something drawing or ranking a graph would otherwise derive itself.
pub(crate) mod layout;
/// The ceilings one caller states before an analysis is built.
mod limits;
/// The declared module partition, derived from logical containment alone.
mod partition;
/// Which edges one analysis admits.
mod selection;
/// Bounded neighborhoods, shortest paths, and induced subgraph selections.
pub(crate) mod traversal;

pub use betweenness::BetweennessCentrality;
pub use components::{
    ComponentIdKind, CondensationEdge, CondensationGraph, GraphComponent, GraphComponentId,
    GraphComponents,
};
pub use degree::DegreeCentrality;
pub use divergence::{
    BoundaryCrossingComponent, GraphDivergence, MisplacementCandidate, ModuleCohesion,
};
pub use error::GraphAnalysisError;
pub use index::GraphAnalysis;
pub use layout::{LayoutAssistMetadata, LayoutEdgeMetadata, LayoutNodeMetadata};
pub use limits::GraphAnalysisLimits;
pub use partition::DeclaredModulePartition;
pub use selection::GraphEdgeSelection;
pub use traversal::{GraphDirection, GraphNeighbor, GraphPath, GraphSubgraph};
