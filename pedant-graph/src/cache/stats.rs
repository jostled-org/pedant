//! What one cache did, counted once per examined or dropped entry.
//!
//! Statistics describe cache work alone. Nothing here enters graph identity,
//! record order, serialization, or a query answer: a counter is read by a host
//! deciding whether its retention budget is worth the memory, and by the proofs
//! that hold this crate to reusing only what it claims to reuse.
//!
//! The reading is a copied value. The live counts it is taken from belong to
//! [`super::state`], so a host reads a number that cannot move under it.

/// One category's three cumulative counts, as a copied reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CategoryCounts {
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl CategoryCounts {
    /// One category's three counts, read together.
    pub(crate) fn new(hits: u64, misses: u64, evictions: u64) -> Self {
        Self {
            hits,
            misses,
            evictions,
        }
    }
}

/// A copied reading of one cache's cumulative activity.
///
/// Counters saturate rather than wrap, so a long-lived host reads a ceiling
/// instead of a count that silently restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphCacheStats {
    source_projections: CategoryCounts,
    exact_graphs: CategoryCounts,
    selected_indexes: CategoryCounts,
    derived_products: CategoryCounts,
}

impl GraphCacheStats {
    /// One reading, taken across all four categories at once.
    pub(crate) fn new(
        source_projections: CategoryCounts,
        exact_graphs: CategoryCounts,
        selected_indexes: CategoryCounts,
        derived_products: CategoryCounts,
    ) -> Self {
        Self {
            source_projections,
            exact_graphs,
            selected_indexes,
            derived_products,
        }
    }

    /// Source-unit projections reused from retained state.
    pub fn source_projection_hits(self) -> u64 {
        self.source_projections.hits
    }

    /// Source-unit projections that had to be rebuilt.
    pub fn source_projection_misses(self) -> u64 {
        self.source_projections.misses
    }

    /// Source-unit projections dropped to stay within their ceiling.
    pub fn source_projection_evictions(self) -> u64 {
        self.source_projections.evictions
    }

    /// Exact graphs answered from retained state.
    pub fn exact_graph_hits(self) -> u64 {
        self.exact_graphs.hits
    }

    /// Exact graphs that had to be built.
    pub fn exact_graph_misses(self) -> u64 {
        self.exact_graphs.misses
    }

    /// Exact graphs dropped to stay within their ceiling.
    pub fn exact_graph_evictions(self) -> u64 {
        self.exact_graphs.evictions
    }

    /// Edge-selection index sets answered from retained state.
    pub fn selected_index_hits(self) -> u64 {
        self.selected_indexes.hits
    }

    /// Edge-selection index sets that had to be built.
    pub fn selected_index_misses(self) -> u64 {
        self.selected_indexes.misses
    }

    /// Edge-selection index sets dropped to stay within their ceiling.
    pub fn selected_index_evictions(self) -> u64 {
        self.selected_indexes.evictions
    }

    /// Derived products answered from retained state.
    pub fn derived_product_hits(self) -> u64 {
        self.derived_products.hits
    }

    /// Derived products that had to be computed.
    pub fn derived_product_misses(self) -> u64 {
        self.derived_products.misses
    }

    /// Derived products dropped to stay within their ceiling.
    pub fn derived_product_evictions(self) -> u64 {
        self.derived_products.evictions
    }
}
