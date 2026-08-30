//! The graph one project slice holds, and which producer handed it over.
//!
//! Both variants answer the same borrowed [`CodeGraph`], so nothing downstream
//! of a slice can tell a reused Rust graph from a freshly built one. That is the
//! contract the reuse store states: a cache hit and a cache miss are the same
//! graph, so which one happened is a cost, never an answer.
//!
//! The Rust variant keeps the cache's own handle rather than a copy of the
//! graph. The handle stays valid after eviction, after `clear`, and after the
//! cache itself is dropped, which is what lets one indexer publish a state that
//! outlives the store that built it.

use std::fmt;

use pedant_graph::CodeGraph;

/// One project slice's graph.
#[derive(Clone)]
pub(super) enum RetainedGraph {
    /// A Rust graph the bounded reuse store produced.
    #[cfg(feature = "graph-rust")]
    Reused(pedant_graph::CachedCodeGraph),
    /// A Go graph the direct builder produced.
    #[cfg(feature = "graph-go")]
    Direct(std::sync::Arc<CodeGraph>),
}

impl RetainedGraph {
    /// The graph this slice resolved.
    pub(super) fn graph(&self) -> &CodeGraph {
        match self {
            #[cfg(feature = "graph-rust")]
            Self::Reused(held) => held.graph(),
            #[cfg(feature = "graph-go")]
            Self::Direct(held) => held,
        }
    }
}

impl fmt::Debug for RetainedGraph {
    /// The graph's own shape, not the handle's provenance.
    ///
    /// A slice that reused its graph and one that built it are the same slice,
    /// so a rendering that named the variant would print a difference no answer
    /// carries.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let graph = self.graph();
        formatter
            .debug_struct("RetainedGraph")
            .field("nodes", &graph.nodes().len())
            .field("references", &graph.references().len())
            .field("edges", &graph.edges().len())
            .finish()
    }
}
