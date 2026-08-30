//! The one handle every graph answer in this crate is taken through.
//!
//! A slice holds its graph the way its producer handed it over: the Rust store
//! keeps the cache's own handle, the Go builder hands over the graph itself. An
//! analysis follows the same split, and for the same reason the retention does.
//!
//! A cached graph owns two bounded stores — the indexes one edge selection
//! produces, and the answers derived over them — and both are bounded by
//! ceilings this crate already states in its revision claim. Reaching the
//! borrowed analysis instead would leave those two ceilings configured and
//! inert: they would move the revision without bounding a retention, which is
//! exactly what Invariant 14 forbids. So every Rust answer is taken through the
//! handle whose stores they bound.
//!
//! The two variants answer identically. `CachedGraphAnalysis` states the same
//! results, in the same order, with the same refusals in the same order as the
//! borrowed `GraphAnalysis` for the same graph, selection, and ceilings, so
//! which one answered is a cost and never an answer.

use std::sync::Arc;

use pedant_graph::{
    BetweennessCentrality, CodeGraph, CondensationGraph, DegreeCentrality, GraphAnalysisError,
    GraphAnalysisLimits, GraphComponents, GraphDirection, GraphDivergence, GraphEdgeSelection,
    GraphNeighbor, GraphNodeId, GraphPath, GraphSubgraph,
};

use super::retained::RetainedGraph;

/// One project slice's graph, ready to be asked.
pub(crate) enum SliceAnalysis<'graph> {
    /// A Rust graph the bounded reuse store produced, analyzed through the
    /// handle that owns its selected indexes and derived products.
    ///
    /// The graph is carried beside the handle because the handle borrows its
    /// own state: a caller that needs the graph for as long as the slice lives
    /// reads it here rather than from a temporary.
    #[cfg(feature = "graph-rust")]
    Reused {
        /// The graph this analysis reads.
        graph: &'graph CodeGraph,
        /// The handle that retains everything derived from it.
        held: pedant_graph::CachedGraphAnalysis,
    },
    /// A Go graph the direct builder produced, analyzed in place.
    #[cfg(feature = "graph-go")]
    Direct(pedant_graph::GraphAnalysis<'graph>),
}

impl<'graph> SliceAnalysis<'graph> {
    /// Analyze one retained graph under `selection` and `limits`.
    ///
    /// # Errors
    ///
    /// Every refusal `GraphAnalysis::new` states, in the same order. A cached
    /// graph proves its node and selected-edge counts against these ceilings
    /// before it examines anything it retained, so a lowered ceiling refuses
    /// exactly as it would refuse a graph nothing had been derived from.
    ///
    /// Narrower than the type it constructs, which is `pub(crate)`. It takes a
    /// `RetainedGraph`, and what a project retained is this module's own
    /// business: the one caller is the slice that holds it, and a crate-wide
    /// constructor would publish that type to readers who have no graph to hand
    /// it.
    pub(super) fn opened(
        retained: &'graph RetainedGraph,
        selection: GraphEdgeSelection,
        limits: GraphAnalysisLimits,
    ) -> Result<Self, GraphAnalysisError> {
        match retained {
            #[cfg(feature = "graph-rust")]
            RetainedGraph::Reused(cached) => Ok(Self::Reused {
                graph: cached.graph(),
                held: cached.analyze(selection, limits)?,
            }),
            #[cfg(feature = "graph-go")]
            RetainedGraph::Direct(graph) => {
                pedant_graph::GraphAnalysis::new(graph, selection, limits).map(Self::Direct)
            }
        }
    }

    /// The graph this analysis reads.
    pub(crate) fn graph(&self) -> &'graph CodeGraph {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { graph, .. } => graph,
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held.graph(),
        }
    }

    /// The ceilings this analysis was admitted under.
    pub(crate) fn limits(&self) -> GraphAnalysisLimits {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.limits(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held.limits(),
        }
    }

    /// The selection induced by the nodes `seed` reaches within `depth`
    /// selected steps, and the distance the same walk measured to each of them.
    ///
    /// The one bounded walk this crate asks for. A neighborhood answer states
    /// both readings, and asking the analysis for each separately would traverse
    /// the reachable set twice and retain two derived products stating one
    /// answer.
    ///
    /// # Errors
    ///
    /// The graph crate's own seed and depth refusals, in its own order.
    pub(crate) fn subgraph(
        &self,
        seed: GraphNodeId,
        depth: u32,
        direction: GraphDirection,
    ) -> Result<Arc<GraphSubgraph>, GraphAnalysisError> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.subgraph(seed, depth, direction),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held.subgraph(seed, depth, direction).map(Arc::new),
        }
    }

    /// Every reached node beyond `seed`, ordered by distance then identity.
    pub(crate) fn neighbors(
        &self,
        seed: GraphNodeId,
        depth: u32,
        direction: GraphDirection,
    ) -> Result<Arc<[GraphNeighbor]>, GraphAnalysisError> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.neighbors(seed, depth, direction),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held.neighbors(seed, depth, direction).map(Arc::from),
        }
    }

    /// The shortest route from `source` to `target`, or `None` when the graph
    /// states none.
    ///
    /// # Errors
    ///
    /// The graph crate's own endpoint refusals, in its own order.
    pub(crate) fn path(
        &self,
        source: GraphNodeId,
        target: GraphNodeId,
    ) -> Result<Option<Arc<GraphPath>>, GraphAnalysisError> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.path(source, target),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held.path(source, target).map(|found| found.map(Arc::new)),
        }
    }

    /// How many selected edges arrive at and leave each node.
    pub(crate) fn degree_centrality(&self) -> Arc<[DegreeCentrality]> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.degree_centrality(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => Arc::from(held.degree_centrality()),
        }
    }

    /// How much shortest routing passes through each node.
    ///
    /// # Errors
    ///
    /// The graph crate's own work-bound refusal.
    pub(crate) fn betweenness_centrality(
        &self,
    ) -> Result<Arc<[BetweennessCentrality]>, GraphAnalysisError> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.betweenness_centrality(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held.betweenness_centrality().map(Arc::from),
        }
    }

    /// Which nodes reach each other over selected edges.
    pub(crate) fn strongly_connected_components(&self) -> Arc<GraphComponents> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.strongly_connected_components(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => Arc::new(held.strongly_connected_components()),
        }
    }

    /// The acyclic view over those components.
    pub(crate) fn condensation(&self) -> Arc<CondensationGraph> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.condensation(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => Arc::new(held.condensation()),
        }
    }

    /// What the selected topology says about the declared module partition.
    pub(crate) fn divergence(&self) -> Arc<GraphDivergence> {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused { held, .. } => held.divergence(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => Arc::new(held.divergence()),
        }
    }
}
