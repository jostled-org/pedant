//! The retained source-unit projections one build may reuse.
//!
//! The store answers one question, before the planner derives anything for a
//! source: is the projection this source states already held? An answer is
//! given only when the key selects a retained projection and the current report
//! still states the claim that projection was derived from. That one decision
//! is where reuse and its classification both happen — a source that is
//! answered costs one key and one comparison and derives nothing, and a source
//! that is not is derived and retained here.
//!
//! Classification belongs to the examination rather than to the retention that
//! may follow it. Every source this store is asked about is classified once, at
//! the moment it is asked, so a derivation that refuses leaves behind the same
//! count as one that succeeds.

use std::sync::Arc;

use crate::cache::{BoundedStore, CacheCategory, CacheCounters, CacheEvent};

use crate::projection::draft::SourceFragment;

use super::claim::SourceKey;

/// The bounded source-unit projections one cache retains.
pub(crate) struct ProjectionStore {
    counters: Arc<CacheCounters>,
    entries: BoundedStore<SourceKey, Arc<SourceFragment>>,
}

impl ProjectionStore {
    /// A store bounded by `ceiling`, counting into shared cache state.
    pub(crate) fn new(ceiling: u32, counters: Arc<CacheCounters>) -> Self {
        Self {
            counters,
            entries: BoundedStore::new(ceiling),
        }
    }

    /// A store for a build with no cache behind it.
    ///
    /// It retains nothing and its counts reach no caller, so a direct build
    /// derives every source through the one path a cached miss derives it by
    /// rather than through a second builder that skips the seam.
    pub(crate) fn unretained() -> Self {
        Self::new(0, Arc::new(CacheCounters::default()))
    }

    /// The retained projection `key` selects, when `states` proves it is still
    /// what the current report states for that source.
    ///
    /// The one classification site. Examining a source is what decides it, so
    /// both answers are counted here: a selected projection the current report
    /// still states is the hit, and anything else is the miss the caller's
    /// derivation answers. A source whose derivation then refuses is still a
    /// source this store examined, and it is classified exactly once whether or
    /// not a projection ever comes back to be retained.
    pub(crate) fn reused(
        &mut self,
        key: &SourceKey,
        states: impl Fn(&SourceFragment) -> bool,
    ) -> Option<Arc<SourceFragment>> {
        match self.entries.selected(key, |held| states(held)) {
            Some(retained) => {
                self.counters
                    .record(CacheCategory::SourceProjection, CacheEvent::Hit, 1);
                Some(retained)
            }
            None => {
                self.counters
                    .record(CacheCategory::SourceProjection, CacheEvent::Miss, 1);
                None
            }
        }
    }

    /// Retain one derived projection, answering with the handle this build uses.
    ///
    /// The examination that reached here was already classified, so this counts
    /// retention pressure alone.
    pub(crate) fn retain(
        &mut self,
        key: SourceKey,
        derived: SourceFragment,
    ) -> Arc<SourceFragment> {
        let shared = Arc::new(derived);
        let evicted = self.entries.retain(key, Arc::clone(&shared));
        self.counters.record(
            CacheCategory::SourceProjection,
            CacheEvent::Eviction,
            evicted,
        );
        shared
    }

    /// Drop every retained projection.
    ///
    /// The store owns strong references, never the only ones: a projection the
    /// current plan holds stays valid and immutable after its entry is gone.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}
