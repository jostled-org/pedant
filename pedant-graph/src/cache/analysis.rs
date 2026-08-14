//! Bounded reuse of the indexes and the products one immutable graph produces.
//!
//! The retained state belongs to the graph rather than to the cache that built
//! it: a handle a caller kept answers from it after the top-level cache is
//! cleared or dropped. Every entry is admitted work — an index set one
//! selection produced, or one derived answer over it — so evicting one costs a
//! recomputation and never turns an answer into a failure.
//!
//! Every ceiling that still applies is proved before a retained value is
//! returned. A product computed under a generous budget is not evidence that a
//! stricter budget admits it, so the node, selected-edge, depth, and
//! betweenness-work checks run again on the way in.

use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::analysis::index::{AnalysisContext, SharedAnalysis};
use crate::analysis::{
    BetweennessCentrality, CondensationGraph, DeclaredModulePartition, DegreeCentrality,
    GraphAnalysisError, GraphAnalysisLimits, GraphComponents, GraphDirection, GraphDivergence,
    GraphEdgeSelection, GraphNeighbor, GraphPath, GraphSubgraph, LayoutAssistMetadata, betweenness,
    components, degree, divergence, layout, traversal,
};
use crate::graph::CodeGraph;
use crate::id::GraphNodeId;

use super::graph::CachedGraphState;
use super::limits::GraphCacheLimits;
use super::product::{Product, ProductClaim, ProductOperation, ProductStore};
use super::state::{CacheCategory, CacheCounters, CacheEvent};
use super::storage::BoundedStore;

/// The two bounded categories one cached graph retains.
struct Derived {
    indexes: BoundedStore<GraphEdgeSelection, SharedAnalysis>,
    products: ProductStore,
}

impl Derived {
    /// Two empty stores, bounded by the per-graph ceilings a host chose.
    fn new(limits: GraphCacheLimits) -> Self {
        Self {
            indexes: BoundedStore::new(limits.max_selected_indexes_per_graph()),
            products: ProductStore::new(limits.max_derived_products_per_graph()),
        }
    }

    /// Drop every retained index set and every retained product.
    ///
    /// The cache owns strong references, never the only ones: an analysis or a
    /// product a caller still holds stays valid and immutable afterwards.
    fn clear(&mut self) {
        self.indexes.clear();
        self.products.clear();
    }
}

/// The synchronized derived state one cached graph owns.
///
/// Standard-library synchronization, because cloned handles are queried from
/// several threads. The counts live outside the lock, so reading what the cache
/// did never waits on a computation.
pub(crate) struct DerivedState {
    retained: Mutex<Derived>,
    counters: Arc<CacheCounters>,
}

impl DerivedState {
    /// Empty derived state for one graph, sharing its cache's counters.
    pub(crate) fn new(limits: GraphCacheLimits, counters: Arc<CacheCounters>) -> Self {
        Self {
            retained: Mutex::new(Derived::new(limits)),
            counters,
        }
    }

    /// Drop every retained index set and product.
    pub(crate) fn clear(&self) {
        self.locked().clear();
    }

    /// The shared indexes and partition one selection produces, reused when
    /// this graph already holds them.
    ///
    /// The counts arrive already proved against the caller's current ceilings,
    /// so an index set admitted under a looser budget cannot answer a stricter
    /// one, and a miss indexes exactly what those ceilings admitted.
    pub(crate) fn indexed(
        &self,
        graph: &CodeGraph,
        selection: GraphEdgeSelection,
        admitted: (u32, u32),
    ) -> Result<SharedAnalysis, GraphAnalysisError> {
        let mut retained = self.locked();
        match retained.indexes.get(&selection) {
            Some(held) => {
                self.count(CacheCategory::SelectedIndex, CacheEvent::Hit, 1);
                Ok(held)
            }
            None => {
                self.count(CacheCategory::SelectedIndex, CacheEvent::Miss, 1);
                let built = SharedAnalysis::from_admitted(graph, selection, admitted)?;
                let evicted = retained.indexes.retain(selection, built.clone());
                self.count(CacheCategory::SelectedIndex, CacheEvent::Eviction, evicted);
                Ok(built)
            }
        }
    }

    /// One derived answer, computed only when this graph holds none for the
    /// exact claim.
    ///
    /// The one hit, miss, retention, and eviction owner for every published
    /// operation: the claim selects the entry, the shape states how it is read
    /// and held, and `derive` runs the algorithm that owns the answer. The claim
    /// carries the operation, so the entry the key selects already has the shape
    /// this call expects. Derivation happens under the same guard that missed,
    /// so two threads asking one question converge on one allocation rather
    /// than racing to retain two.
    ///
    /// The refusal type is the derivation's own, so an operation that cannot
    /// refuse states that in its type instead of carrying an error arm nothing
    /// reaches.
    pub(crate) fn product<T: Product, E>(
        &self,
        claim: ProductClaim,
        derive: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let mut retained = self.locked();
        let found = retained.products.get(&claim).and_then(T::read);
        match found {
            Some(answer) => {
                self.count(CacheCategory::DerivedProduct, CacheEvent::Hit, 1);
                Ok(answer)
            }
            None => {
                self.count(CacheCategory::DerivedProduct, CacheEvent::Miss, 1);
                let answer = derive()?;
                let evicted = retained.products.retain(claim, answer.clone().state());
                self.count(CacheCategory::DerivedProduct, CacheEvent::Eviction, evicted);
                Ok(answer)
            }
        }
    }

    /// The counters every classification this graph makes is recorded against.
    ///
    /// One set of counters per cache, shared with the graphs it produced, so a
    /// handle reads what the cache did rather than a second tally kept beside
    /// it.
    pub(crate) fn counters(&self) -> &CacheCounters {
        &self.counters
    }

    /// Count one classification against this graph's cache.
    fn count(&self, category: CacheCategory, event: CacheEvent, amount: u64) {
        self.counters.record(category, event, amount);
    }

    /// The one acquisition of this graph's derived store.
    ///
    /// A guard poisoned by a panic says nothing about the graph, which is
    /// immutable, and everything about state a partial computation may have
    /// left behind. Ownership is recovered and every retained entry is dropped
    /// before the store is read, so the next operation recomputes from the
    /// graph and answers exactly as a cache with nothing retained would. No
    /// arm here aborts, and no cache-specific refusal is added to the analysis
    /// error vocabulary.
    ///
    /// The flag is reset in the same arm, so exactly one operation pays the
    /// discard. Recovering ownership alone leaves the mutex poisoned for the
    /// life of the graph, which would drop every later retention too and turn
    /// one panic into a cache that never retains again.
    fn locked(&self) -> MutexGuard<'_, Derived> {
        match self.retained.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                let mut discarded = poisoned.into_inner();
                discarded.clear();
                self.retained.clear_poison();
                discarded
            }
        }
    }
}

/// One shared analysis over one cached graph.
///
/// Distinct from the borrowed [`crate::GraphAnalysis`]: this handle owns shared
/// state, so it can be cloned, sent between threads, and outlive the cache that
/// produced it. Cloning shares the admitted indexes rather than rebuilding
/// them.
#[derive(Clone)]
pub struct CachedGraphAnalysis {
    state: Arc<CachedGraphState>,
    selection: GraphEdgeSelection,
    limits: GraphAnalysisLimits,
    shared: SharedAnalysis,
}

impl CachedGraphAnalysis {
    /// One handle on indexes this graph already admitted.
    pub(crate) fn new(
        state: Arc<CachedGraphState>,
        selection: GraphEdgeSelection,
        limits: GraphAnalysisLimits,
        shared: SharedAnalysis,
    ) -> Self {
        Self {
            state,
            selection,
            limits,
            shared,
        }
    }

    /// The graph this analysis reads. Every identity it answers with indexes
    /// back into this value.
    pub fn graph(&self) -> &CodeGraph {
        self.state.graph()
    }

    /// The selection every index was built from.
    pub fn selection(&self) -> GraphEdgeSelection {
        self.selection
    }

    /// The ceilings this analysis was admitted under.
    pub fn limits(&self) -> GraphAnalysisLimits {
        self.limits
    }

    /// The declared module partition, derived once with the indexes.
    pub fn declared_partition(&self) -> &DeclaredModulePartition {
        self.shared.partition()
    }

    /// Every node connected to `node` within `depth` selected steps in
    /// `direction`, at its minimum distance, in distance then node order.
    ///
    /// # Errors
    ///
    /// The same refusals [`crate::GraphAnalysis::neighbors`] returns, in the
    /// same order. The seed and the depth ceiling are proved before any
    /// retained neighborhood is examined.
    pub fn neighbors(
        &self,
        node: GraphNodeId,
        depth: u32,
        direction: GraphDirection,
    ) -> Result<Arc<[GraphNeighbor]>, GraphAnalysisError> {
        self.admits_walk(node, depth)?;
        self.product(
            ProductOperation::Neighbors {
                node,
                depth,
                direction,
            },
            |context| traversal::neighbors(context, node, depth, direction).map(Arc::from),
        )
    }

    /// The shortest route from `source` to `target` over selected outgoing
    /// edges, or `None` when no route exists.
    ///
    /// The proven absence of a route is retained too, so a repeated
    /// unreachable pair is answered rather than walked again.
    ///
    /// # Errors
    ///
    /// The same refusals [`crate::GraphAnalysis::path`] returns, in the same
    /// order. Both endpoints are proved before any retained route is examined,
    /// so a pair this graph holds no record for costs no store lookup and is
    /// never counted as a product nothing derived and nothing retained.
    pub fn path(
        &self,
        source: GraphNodeId,
        target: GraphNodeId,
    ) -> Result<Option<Arc<GraphPath>>, GraphAnalysisError> {
        traversal::admitted_route(self.shared.indexes(), (source, target))?;
        self.product(ProductOperation::Path { source, target }, |context| {
            traversal::path(context, (source, target)).map(|found| found.map(Arc::new))
        })
    }

    /// The selection into this graph induced by the nodes `seed` reaches
    /// within `depth` selected steps.
    ///
    /// # Errors
    ///
    /// The same refusals [`crate::GraphAnalysis::subgraph`] returns, in the
    /// same order. The seed and the depth ceiling are proved before any
    /// retained selection is examined.
    pub fn subgraph(
        &self,
        seed: GraphNodeId,
        depth: u32,
        direction: GraphDirection,
    ) -> Result<Arc<GraphSubgraph>, GraphAnalysisError> {
        self.admits_walk(seed, depth)?;
        self.product(
            ProductOperation::Subgraph {
                seed,
                depth,
                direction,
            },
            |context| traversal::subgraph(context, seed, depth, direction).map(Arc::new),
        )
    }

    /// How many selected edges arrive at and leave each node, in raw node-id
    /// order.
    pub fn degree_centrality(&self) -> Arc<[DegreeCentrality]> {
        settled(self.product(ProductOperation::Degree, |context| {
            Ok(Arc::from(degree::degree(context)))
        }))
    }

    /// How much of the selected topology's shortest routing passes through each
    /// node, in raw node-id order.
    ///
    /// # Errors
    ///
    /// The same refusals [`crate::GraphAnalysis::betweenness_centrality`]
    /// returns. The work bound is proved before any retained score is examined.
    pub fn betweenness_centrality(
        &self,
    ) -> Result<Arc<[BetweennessCentrality]>, GraphAnalysisError> {
        self.admits_centrality_work()?;
        self.product(ProductOperation::Betweenness, |context| {
            betweenness::betweenness(context).map(Arc::from)
        })
    }

    /// Which nodes reach each other over selected edges.
    pub fn strongly_connected_components(&self) -> Arc<GraphComponents> {
        settled(self.product(ProductOperation::Components, |context| {
            Ok(Arc::new(components::discover(context)))
        }))
    }

    /// The same selected topology with every component contracted, ordered, and
    /// still carrying every raw edge it coalesced.
    pub fn condensation(&self) -> Arc<CondensationGraph> {
        settled(self.product(ProductOperation::Condensation, |context| {
            Ok(Arc::new(components::condense(context)))
        }))
    }

    /// What the selected topology says about the module partition this graph
    /// declares.
    pub fn divergence(&self) -> Arc<GraphDivergence> {
        settled(self.product(ProductOperation::Divergence, |context| {
            Ok(Arc::new(divergence::divergence(context)))
        }))
    }

    /// Every admitted node and selected edge, described for a consumer that
    /// ranks or draws them.
    ///
    /// # Errors
    ///
    /// The same refusals [`crate::GraphAnalysis::layout_assist`] returns. The
    /// bounded pass behind it is admitted before any retained metadata is
    /// examined.
    pub fn layout_assist(&self) -> Result<Arc<LayoutAssistMetadata>, GraphAnalysisError> {
        self.admits_centrality_work()?;
        self.product(ProductOperation::Layout, |context| {
            layout::layout_assist(context).map(Arc::new)
        })
    }

    /// One derived answer, keyed by this handle's selection and the operation's
    /// complete arguments.
    fn product<T: Product, E>(
        &self,
        operation: ProductOperation,
        derive: impl FnOnce(&AnalysisContext<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let claim = ProductClaim::new(self.selection, operation);
        self.derived().product(claim, || derive(&self.context()))
    }

    /// The bounded derived state this handle's graph owns.
    fn derived(&self) -> &DerivedState {
        self.state.derived()
    }

    /// The seed and the depth a bounded walk states, proved against this
    /// handle's ceilings.
    ///
    /// Proved through the owner the borrowed walks reach, so a cached handle
    /// cannot state a refusal the direct analysis would not state, or state the
    /// same two refusals in the other order.
    fn admits_walk(&self, node: GraphNodeId, depth: u32) -> Result<(), GraphAnalysisError> {
        traversal::admitted_walk(self.shared.indexes(), self.limits, node, depth)
    }

    /// The betweenness work bound, proved against this handle's ceilings.
    fn admits_centrality_work(&self) -> Result<(), GraphAnalysisError> {
        betweenness::admitted_work(self.shared.indexes(), self.limits)
    }

    /// What every algorithm this handle delegates to reads.
    fn context(&self) -> AnalysisContext<'_> {
        self.shared.context(self.state.graph(), self.limits)
    }
}

/// The answer of an operation whose derivation states no refusal.
///
/// Three metrics always answer, and their derivations say so by refusing with
/// [`Infallible`]. The error arm is discharged by matching a type with no
/// values rather than by inventing one: nothing is recovered, defaulted, or
/// aborted, because nothing can reach it.
fn settled<T>(answer: Result<T, Infallible>) -> T {
    answer.unwrap_or_else(|never| match never {})
}
