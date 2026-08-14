//! Deterministic, language-tagged code topology built from one snapshot-bound
//! symbol-resolution result.
//!
//! The graph separates three relations a consumer would otherwise have to
//! reconstruct itself: logical containment, source association, and
//! certainty-carrying reference and dependency edges. It consumes already
//! validated in-memory facts and widens nothing: it loads no project, reads no
//! file, parses no source, invokes no build tool, and evaluates no policy.
//!
//! The snapshot must be the one the resolution was validated against, and a
//! successful build serializes to the compact version-1 JSON described below
//! through `serde_json::to_string`.
//!
//! ```no_run
//! # use pedant_core::resolution::rust::{RustResolutionSnapshot, RustTargetResolution};
//! # use pedant_graph::{CodeGraph, GraphBuildError};
//! # fn topology(
//! #     snapshot: &RustResolutionSnapshot,
//! #     resolution: &RustTargetResolution,
//! # ) -> Result<CodeGraph, GraphBuildError> {
//! pedant_graph::build_rust_graph(snapshot, resolution)
//! # }
//! ```
//!
//! # The version-1 shape
//!
//! One object with six keys, in this order:
//!
//! - `schema_version`: the integer [`CodeGraph::SCHEMA_VERSION`].
//! - `tier`: `"syntactic"` or `"semantic"`, taken from the supplied report.
//! - `nodes`: `id`, `language`, `name`, `kind`, `location`. `kind` is tagged by
//!   `category`; `location` is `null` or tagged by `kind` as `file` or `span`.
//! - `containment`: `parent` and `child`, sorted by child then parent.
//! - `references`: `id`, `source`, `language`, `kind`, `text`, `span`, `gaps`,
//!   `edges`, in mint order.
//! - `edges`: `id`, `source`, `target`, `kind`, `certainty`, `origin`, in mint
//!   order. `origin` is tagged by `kind` as `reference` or `dependency`.
//!
//! Every identity is an integer equal to the record's position in its own
//! slice, and every graph-owned enum is one lower-snake-case string. No key
//! states a coordinate, a size, a color, or any other layout choice.

//! # Bounded queries over a built graph
//!
//! A caller states which edges to admit and what the answer may cost, then
//! asks. Nothing about the graph changes.
//!
//! ```no_run
//! # use pedant_graph::{
//! #     CodeGraph, GraphAnalysis, GraphAnalysisError, GraphAnalysisLimits, GraphDirection,
//! #     GraphEdgeSelection, GraphNeighbor, GraphNodeId,
//! # };
//! # fn callers_of(
//! #     graph: &CodeGraph,
//! #     node: GraphNodeId,
//! # ) -> Result<Box<[GraphNeighbor]>, GraphAnalysisError> {
//! let analysis = GraphAnalysis::new(
//!     graph,
//!     GraphEdgeSelection::code_relations(),
//!     GraphAnalysisLimits::new(100_000, 400_000, 8, 50_000_000),
//! )?;
//! analysis.neighbors(node, 2, GraphDirection::Incoming)
//! # }
//! ```
//!
//! The same view answers the derived questions. Cohesion, modularity, affinity,
//! and boundary-crossing cycles are evidence about the partition the graph
//! declares; layout metadata is that evidence beside the degrees and weights a
//! ranker or a renderer would otherwise measure itself.
//!
//! ```no_run
//! # use pedant_graph::{
//! #     CodeGraph, GraphAnalysis, GraphAnalysisError, GraphAnalysisLimits, GraphEdgeSelection,
//! #     LayoutAssistMetadata,
//! # };
//! # fn described(graph: &CodeGraph) -> Result<LayoutAssistMetadata, GraphAnalysisError> {
//! let analysis = GraphAnalysis::new(
//!     graph,
//!     GraphEdgeSelection::code_relations(),
//!     GraphAnalysisLimits::new(100_000, 400_000, 8, 50_000_000),
//! )?;
//! let evidence = analysis.divergence();
//! for module in evidence.cohesion() {
//!     let _ = (module.root(), module.internal_edges(), module.score());
//! }
//! analysis.layout_assist()
//! # }
//! ```

#![deny(missing_docs)]

/// Derived analysis over one borrowed graph.
mod analysis;
/// The logical hierarchy relation.
mod containment;
/// Graph edges, their certainty, and their evidence.
mod edge;
/// Why a graph build refused.
mod error;
/// The immutable graph value and its checked record store.
mod graph;
/// Dense typed identities into one graph's collections.
mod id;
/// The configured ceilings a build refuses at.
mod limits;
/// Graph nodes, their categories, and their source locations.
mod node;
/// Reference records and what they denote.
mod reference;
/// The Rust projection adapter.
mod rust;

pub use analysis::{
    BetweennessCentrality, BoundaryCrossingComponent, ComponentIdKind, CondensationEdge,
    CondensationGraph, DeclaredModulePartition, DegreeCentrality, GraphAnalysis,
    GraphAnalysisError, GraphAnalysisLimits, GraphComponent, GraphComponentId, GraphComponents,
    GraphDirection, GraphDivergence, GraphEdgeSelection, GraphNeighbor, GraphPath, GraphSubgraph,
    LayoutAssistMetadata, LayoutEdgeMetadata, LayoutNodeMetadata, MisplacementCandidate,
    ModuleCohesion,
};
pub use containment::ContainmentEdge;
pub use edge::{
    DependencyEvidence, GraphCertainty, GraphDependencyKind, GraphEdge, GraphEdgeKind,
    GraphEdgeOrigin,
};
pub use error::GraphBuildError;
pub use graph::CodeGraph;
pub use id::{
    EdgeIdKind, GraphEdgeId, GraphId, GraphNodeId, GraphReferenceId, NodeIdKind, ReferenceIdKind,
};
pub use limits::{GraphCollection, GraphLimits};
pub use node::{GraphNode, GraphNodeKind, GraphNodeLocation};
pub use reference::{GraphReference, GraphReferenceKind};
pub use rust::{build_rust_graph, build_rust_graph_with_limits};
