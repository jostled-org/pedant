//! The handle a caller holds on one cached graph.

use std::sync::Arc;

use crate::analysis::index::admitted_counts;
use crate::analysis::{GraphAnalysisError, GraphAnalysisLimits, GraphEdgeSelection};
use crate::graph::CodeGraph;

use super::analysis::{CachedGraphAnalysis, DerivedState};
use super::limits::GraphCacheLimits;
use super::state::CacheCounters;
use super::stats::GraphCacheStats;

/// One admitted graph beside everything derived from it.
///
/// The derived state belongs to the graph rather than to the cache entry that
/// retained it, so two handles on one graph share the indexes and the products
/// either of them produced, and both keep answering after the entry is gone.
pub(crate) struct CachedGraphState {
    graph: Arc<CodeGraph>,
    derived: DerivedState,
}

impl CachedGraphState {
    /// One immutable graph, with nothing derived from it yet.
    pub(crate) fn new(
        graph: CodeGraph,
        limits: GraphCacheLimits,
        counters: Arc<CacheCounters>,
    ) -> Self {
        Self {
            graph: Arc::new(graph),
            derived: DerivedState::new(limits, counters),
        }
    }

    /// The graph this state was built from.
    pub(crate) fn graph(&self) -> &CodeGraph {
        &self.graph
    }

    /// The bounded indexes and products derived from it.
    pub(crate) fn derived(&self) -> &DerivedState {
        &self.derived
    }

    /// What the cache that produced this graph has done so far.
    ///
    /// Read through the derived state, which already shares the one set of
    /// counters this graph records against. A second handle on them here would
    /// be a second place to keep in step with the first.
    pub(crate) fn stats(&self) -> GraphCacheStats {
        self.derived.counters().snapshot()
    }
}

/// One immutable graph, shared with the cache that produced it.
///
/// Cloning a handle shares the graph rather than copying its records, and a
/// handle stays valid after its cache entry is evicted, after the cache is
/// cleared, and after the cache itself is dropped: the memory is the caller's
/// for as long as the caller holds it.
#[derive(Clone)]
pub struct CachedCodeGraph {
    state: Arc<CachedGraphState>,
}

impl CachedCodeGraph {
    /// One handle on an admitted graph, sharing the cache's own state.
    pub(crate) fn new(state: Arc<CachedGraphState>) -> Self {
        Self { state }
    }

    /// The graph this handle holds.
    pub fn graph(&self) -> &CodeGraph {
        self.state.graph()
    }

    /// What the cache that produced this handle has done so far.
    pub fn stats(&self) -> GraphCacheStats {
        self.state.stats()
    }

    /// One shared analysis of this graph under `selection`, reusing the indexes
    /// this graph already produced for it.
    ///
    /// The returned handle answers exactly as [`crate::GraphAnalysis`] answers
    /// for the same graph, selection, and ceilings, whatever this graph
    /// retained first.
    ///
    /// # Errors
    ///
    /// The same refusals [`crate::GraphAnalysis::new`] returns. The node and
    /// selected-edge counts are proved against the caller's current ceilings
    /// before any retained index set is examined, so a lowered ceiling refuses
    /// exactly as it would have refused a fresh analysis.
    pub fn analyze(
        &self,
        selection: GraphEdgeSelection,
        limits: GraphAnalysisLimits,
    ) -> Result<CachedGraphAnalysis, GraphAnalysisError> {
        let admitted = admitted_counts(self.graph(), selection, limits)?;
        let shared = self
            .state
            .derived()
            .indexed(self.graph(), selection, admitted)?;
        Ok(CachedGraphAnalysis::new(
            Arc::clone(&self.state),
            selection,
            limits,
            shared,
        ))
    }

    /// Drop the selected indexes and derived products retained for this graph.
    ///
    /// Cumulative statistics are not reset, no analysis or product a caller
    /// holds is invalidated, and the graph itself is untouched: the cache drops
    /// its own strong references and nothing else.
    pub fn clear_analysis_cache(&self) {
        self.state.derived().clear();
    }
}
