//! The live state one cache shares with every handle it produced.
//!
//! A handle outlives the cache entry it came from and may be read from another
//! thread, so the counts a cache accumulates live here behind shared ownership
//! rather than inside the cache value. Nothing here decides what a cache
//! retains: it records what the cache already did.

use std::sync::atomic::{AtomicU64, Ordering};

use super::stats::{CategoryCounts, GraphCacheStats};

/// Which retention category one counter or ceiling addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheCategory {
    /// Retained source-unit projections.
    SourceProjection,
    /// Retained exact graphs.
    ExactGraph,
    /// Retained edge-selection index sets.
    SelectedIndex,
    /// Retained derived analysis products.
    DerivedProduct,
}

/// How one examined or dropped entry is classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheEvent {
    /// The entry was found and reused.
    Hit,
    /// The entry was absent and had to be computed.
    Miss,
    /// The entry was dropped to stay within its ceiling.
    Eviction,
}

/// One category's three live counts.
///
/// Atomic because a cached graph handle is shared across threads and reports
/// the same cumulative activity from any of them.
#[derive(Default)]
struct CategoryCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl CategoryCounters {
    /// The counter one classification addresses.
    fn counter(&self, event: CacheEvent) -> &AtomicU64 {
        match event {
            CacheEvent::Hit => &self.hits,
            CacheEvent::Miss => &self.misses,
            CacheEvent::Eviction => &self.evictions,
        }
    }

    /// This category's counts, copied.
    fn counts(&self) -> CategoryCounts {
        CategoryCounts::new(
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.evictions.load(Ordering::Relaxed),
        )
    }
}

/// Every cumulative count one cache and the handles it produced share.
#[derive(Default)]
pub(crate) struct CacheCounters {
    source_projections: CategoryCounters,
    exact_graphs: CategoryCounters,
    selected_indexes: CategoryCounters,
    derived_products: CategoryCounters,
}

impl CacheCounters {
    /// Count `amount` entries of one category under one classification.
    ///
    /// The one mutation path. Every hit, miss, and eviction anywhere in the
    /// cache reaches this, so no counter can be advanced by arithmetic that
    /// wraps or by a second owner that forgot to saturate.
    ///
    /// Nothing counted is nothing done. Most callers state a count the store
    /// computed rather than one they chose — a build classifies every source it
    /// examined, and every retention states the entries its ceiling dropped, so
    /// the ordinary answer is zero. Stopping here leaves the atomic untouched
    /// instead of running a contended read-modify-write per source to add
    /// nothing.
    pub(crate) fn record(&self, category: CacheCategory, event: CacheEvent, amount: u64) {
        match amount {
            0 => (),
            counted => saturate(self.category(category).counter(event), counted),
        }
    }

    /// A copied reading of every counter.
    pub(crate) fn snapshot(&self) -> GraphCacheStats {
        GraphCacheStats::new(
            self.category(CacheCategory::SourceProjection).counts(),
            self.category(CacheCategory::ExactGraph).counts(),
            self.category(CacheCategory::SelectedIndex).counts(),
            self.category(CacheCategory::DerivedProduct).counts(),
        )
    }

    /// The counters one category owns.
    fn category(&self, category: CacheCategory) -> &CategoryCounters {
        match category {
            CacheCategory::SourceProjection => &self.source_projections,
            CacheCategory::ExactGraph => &self.exact_graphs,
            CacheCategory::SelectedIndex => &self.selected_indexes,
            CacheCategory::DerivedProduct => &self.derived_products,
        }
    }
}

/// Add `amount` to one counter, stopping at `u64::MAX`.
///
/// The compare-and-exchange loop is the saturating add: reading, saturating,
/// and storing in one retried step keeps two threads from losing a count, and
/// the loop never discards a result it should have handled.
fn saturate(counter: &AtomicU64, amount: u64) {
    let mut held = counter.load(Ordering::Relaxed);
    while let Err(current) = counter.compare_exchange_weak(
        held,
        held.saturating_add(amount),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        held = current;
    }
}
