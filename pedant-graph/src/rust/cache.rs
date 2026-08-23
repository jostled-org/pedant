//! The caller-created cache of already built Rust graphs.
//!
//! It accepts exactly what the direct builders accept and loads nothing of its
//! own: no project, no source, no path, no parser, no semantic context, no
//! resolver, no process, and no filesystem event. The caller stays responsible
//! for supplying a current snapshot beside the resolution validated against it.
//!
//! Reuse is decided by the complete claim rather than by the snapshot
//! fingerprint alone. The fingerprint identifies repository content and the
//! selected units; a graph also depends on the validated unit bindings and the
//! complete report supplied beside that snapshot, and two valid reports over
//! one snapshot describe two different graphs.

use std::sync::Arc;

use pedant_core::resolution::rust::{
    RustResolutionSnapshot, RustSnapshotFingerprint, RustTargetResolution, RustUnitBinding,
    TargetId,
};
use pedant_types::ResolutionReport;

use crate::cache::{
    BoundedStore, CacheCategory, CacheCounters, CacheEvent, CachedCodeGraph, CachedGraphState,
    GraphCacheLimits, GraphCacheStats,
};
use crate::error::GraphBuildError;
use crate::limits::GraphLimits;

use crate::projection::assembly;

use super::projection;
use super::reuse::ProjectionStore;

/// The complete claim one retained graph was built from.
///
/// The fingerprint narrows the comparison and exact typed equality decides it,
/// so a custom valid report over an unchanged snapshot can never be answered
/// with a graph built from another report.
struct ExactGraphClaim {
    fingerprint: RustSnapshotFingerprint,
    root_target: TargetId,
    bindings: Box<[RustUnitBinding]>,
    report: Arc<ResolutionReport>,
}

impl ExactGraphClaim {
    /// The claim one validated pairing states.
    fn new(snapshot: &RustResolutionSnapshot, resolution: &RustTargetResolution) -> Self {
        Self {
            fingerprint: snapshot.fingerprint(),
            root_target: resolution.root_target(),
            bindings: resolution.units().into(),
            report: resolution.shared_report(),
        }
    }

    /// Whether two claims describe the same report.
    ///
    /// One handle on a report proves equality without reading it. Two handles
    /// on equal reports are equal too, so a caller that rebuilt its report from
    /// the same facts still reuses the graph those facts describe.
    fn states_one_report(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.report, &other.report) || self.report == other.report
    }
}

/// Cheapest fields first: a differing fingerprint decides the comparison before
/// a binding slice or a whole report is read.
impl PartialEq for ExactGraphClaim {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
            && self.root_target == other.root_target
            && self.bindings == other.bindings
            && self.states_one_report(other)
    }
}

/// A caller-owned cache of graphs built from complete resolution claims.
///
/// The cache is mutated through `&mut self`, so a host chooses its own
/// synchronization policy for construction. Every handle it returns may outlive
/// it and may be shared across threads.
pub struct GraphCache {
    counters: Arc<CacheCounters>,
    limits: GraphCacheLimits,
    graphs: BoundedStore<ExactGraphClaim, Arc<CachedGraphState>>,
    projections: ProjectionStore,
}

impl GraphCache {
    /// An empty cache bounded by one host-chosen retention budget.
    pub fn new(limits: GraphCacheLimits) -> Self {
        let counters = Arc::new(CacheCounters::default());
        Self {
            graphs: BoundedStore::new(limits.max_exact_graphs()),
            projections: ProjectionStore::new(
                limits.max_source_projections(),
                Arc::clone(&counters),
            ),
            limits,
            counters,
        }
    }

    /// Project one snapshot-bound Rust resolution, reusing an exact earlier
    /// answer when the caller states exactly the same claim.
    ///
    /// The returned graph is the one [`crate::build_rust_graph_with_limits`]
    /// returns for the same arguments, whatever this cache retained first.
    ///
    /// # Errors
    ///
    /// The same refusals as the direct builders. Both identity refusals are
    /// taken before any retained state is examined, so a mismatched pairing
    /// cannot be answered from, or recorded against, this cache.
    pub fn build_rust_graph(
        &mut self,
        snapshot: &RustResolutionSnapshot,
        resolution: &RustTargetResolution,
        limits: GraphLimits,
    ) -> Result<CachedCodeGraph, GraphBuildError> {
        projection::validate(snapshot, resolution)?;
        let claim = ExactGraphClaim::new(snapshot, resolution);
        match self.graphs.get(&claim) {
            Some(retained) => self.reuse(retained, limits),
            None => self.build_missing(claim, (snapshot, resolution), limits),
        }
    }

    /// What this cache has done so far.
    pub fn stats(&self) -> GraphCacheStats {
        self.counters.snapshot()
    }

    /// Drop every retained graph and every retained source projection.
    ///
    /// Cumulative statistics are not reset, and no handle a caller holds is
    /// invalidated: the cache drops its own strong references and nothing else.
    pub fn clear(&mut self) {
        self.graphs.clear();
        self.projections.clear();
    }

    /// Return one retained graph, under the caller's current ceilings.
    ///
    /// The ceilings are not part of a graph's identity, because admitted output
    /// is independent of the ceiling that admitted it. They are reapplied here
    /// in construction order, so a caller that lowered one is refused exactly as
    /// a direct build would refuse it.
    fn reuse(
        &self,
        retained: Arc<CachedGraphState>,
        limits: GraphLimits,
    ) -> Result<CachedCodeGraph, GraphBuildError> {
        self.counters
            .record(CacheCategory::ExactGraph, CacheEvent::Hit, 1);
        retained.graph().admissible(limits)?;
        Ok(CachedCodeGraph::new(retained))
    }

    /// Build one graph this cache holds no answer for, and retain it.
    ///
    /// The planner examines every source this pairing states exactly once,
    /// against the projections this cache retained. A source whose claim still
    /// holds is answered from that store and derived again by nothing; every
    /// other source is derived and retained. Removed and superseded projections
    /// never reach the assembly, because the walk is over the sources the
    /// current plan states, in the order it states them, and a selected entry
    /// answers only when the current report still states its claim.
    fn build_missing(
        &mut self,
        claim: ExactGraphClaim,
        stated: (&RustResolutionSnapshot, &RustTargetResolution),
        limits: GraphLimits,
    ) -> Result<CachedCodeGraph, GraphBuildError> {
        let (snapshot, resolution) = stated;
        self.counters
            .record(CacheCategory::ExactGraph, CacheEvent::Miss, 1);
        let planned = projection::plan(snapshot, resolution, &mut self.projections)?;
        let state = Arc::new(CachedGraphState::new(
            assembly::assemble(&planned, limits)?,
            self.limits,
            Arc::clone(&self.counters),
        ));
        let evicted = self.graphs.retain(claim, Arc::clone(&state));
        self.counters
            .record(CacheCategory::ExactGraph, CacheEvent::Eviction, evicted);
        Ok(CachedCodeGraph::new(state))
    }
}
