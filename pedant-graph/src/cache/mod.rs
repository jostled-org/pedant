//! Optional caller-owned reuse of already admitted graph work.
//!
//! The family holds ceilings, cumulative counts, bounded retention, and the
//! handle a caller keeps. It names no language: the claims that decide whether
//! a retained value may answer for a new input belong to the adapter that
//! produced it.

/// Bounded reuse of the indexes and the products one graph produces.
mod analysis;
/// The handle a caller holds on one cached graph.
mod graph;
/// How many admitted values a cache may retain.
mod limits;
/// What one derived answer is retained under, and what is retained.
mod product;
/// The live counts a cache shares with the handles it produced.
mod state;
/// What a cache did, counted once per examined entry.
mod stats;
/// Bounded least-recently-used retention.
mod storage;

pub use analysis::CachedGraphAnalysis;
pub use graph::CachedCodeGraph;
pub use limits::GraphCacheLimits;
pub use stats::GraphCacheStats;

pub(crate) use graph::CachedGraphState;
pub(crate) use state::{CacheCategory, CacheCounters, CacheEvent};
pub(crate) use storage::BoundedStore;
