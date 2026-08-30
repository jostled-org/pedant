//! The graph work one indexer carries from one revision to the next.
//!
//! An index is immutable, so every revision builds its graphs again. Most of
//! that work is the same work: a repository where one Python file changed
//! states exactly the Rust graphs the previous revision stated, from exactly
//! the same snapshot and the same validated resolution. The cache is what turns
//! the second build of an unchanged target into a lookup.
//!
//! It changes cost and nothing else. The handle it returns holds the graph
//! `build_rust_graph_with_limits` returns for the same arguments, whatever the
//! cache retained first, so a hit and a miss are the same answer under the same
//! revision. Its counters are cost too: no claim reads them, so no identity
//! moves when an entry is evicted.
//!
//! Go has no cache here. `pedant-graph` publishes one for Rust alone, and
//! writing a second one in this crate would be a reuse policy the graph owner
//! never proved.

use super::limits::CodeIntelligenceLimits;

/// What one indexer may reuse across the revisions it publishes.
pub(super) struct GraphReuse {
    #[cfg(feature = "graph-rust")]
    cache: pedant_graph::GraphCache,
}

impl GraphReuse {
    /// An empty reuse store, bounded by the host's own cache ceilings.
    #[cfg(feature = "graph-rust")]
    pub(super) fn new(limits: &CodeIntelligenceLimits) -> Self {
        Self {
            cache: pedant_graph::GraphCache::new(limits.graph_cache),
        }
    }

    /// No Rust graph producer is linked, so there is no graph work to reuse.
    #[cfg(not(feature = "graph-rust"))]
    pub(super) fn new(_: &CodeIntelligenceLimits) -> Self {
        Self {}
    }

    /// One Rust target's graph, reusing an exact earlier answer where the
    /// snapshot and the resolution state exactly the earlier claim.
    #[cfg(feature = "graph-rust")]
    pub(super) fn rust_graph(
        &mut self,
        snapshot: &pedant_core::resolution::rust::RustResolutionSnapshot,
        resolution: &pedant_core::resolution::rust::RustTargetResolution,
        limits: pedant_graph::GraphLimits,
    ) -> Result<pedant_graph::CachedCodeGraph, pedant_graph::GraphBuildError> {
        self.cache.build_rust_graph(snapshot, resolution, limits)
    }

    /// What this store has reused and what it has had to build.
    #[cfg(feature = "graph-rust")]
    pub(super) fn stats(&self) -> pedant_graph::GraphCacheStats {
        self.cache.stats()
    }
}
