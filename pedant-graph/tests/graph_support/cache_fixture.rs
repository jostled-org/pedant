//! Real workspaces and the cached and direct builders every cache case enters
//! through.
//!
//! Every cache case enters through the published API over a real temporary
//! Cargo repository resolved by [`super::fixture`]. Nothing here mocks a
//! project, a snapshot, a report, or a graph, and the cache owns no resource
//! beyond the memory its own handles hold. What a build did to the counters is
//! [`super::cache_counting`]'s to state.

use pedant_core::resolution::rust::{
    CargoTargetKind, RustResolutionSnapshot, RustTargetResolution,
};
use pedant_graph::{
    CachedCodeGraph, CodeGraph, GraphBuildError, GraphCache, GraphCacheLimits, GraphLimits,
    build_rust_graph, build_rust_graph_with_limits,
};

use super::cache_counting::{Classification, assert_build_classifies, assert_delta, fragments_of};
use super::corpus::TARGET_KIND_CORPUS;
use super::fixture::{self, Fixture, Resolved};
use super::promotion::{self, Restatement};

/// Ceilings large enough that no cache case evicts by accident.
pub fn generous() -> GraphCacheLimits {
    GraphCacheLimits::new(64, 64, 64, 64)
}

/// Ceilings that retain every exact graph a case states and no projection.
pub fn exact_only(max_exact_graphs: u32) -> GraphCacheLimits {
    GraphCacheLimits::new(0, max_exact_graphs, 0, 0)
}

/// Ceilings that retain one exact graph and the derived state a case states.
///
/// Derived cases hold the graph still — one build, one retained graph — so
/// every counter delta they read belongs to the selection or the product under
/// test rather than to a rebuild.
pub fn derived_only(max_selected_indexes: u32, max_products: u32) -> GraphCacheLimits {
    GraphCacheLimits::new(0, 1, max_selected_indexes, max_products)
}

/// Ceilings that retain every projection a case states and no exact graph.
///
/// Every projection row holds the exact-graph ceiling at zero, so each build
/// misses the exact graph and enters the projection seam: a retained graph could
/// otherwise answer a row and hide the classification it claims to prove.
pub fn projection_only(max_source_projections: u32) -> GraphCacheLimits {
    GraphCacheLimits::new(max_source_projections, 0, 0, 0)
}

/// One snapshot beside a resolution validated against it.
///
/// Cases pair one snapshot with several valid reports, so the two values travel
/// as borrowed arguments rather than inside one owned fixture result.
pub type Pair<'a> = (&'a RustResolutionSnapshot, &'a RustTargetResolution);

/// The snapshot and resolution one fixture result states.
pub fn pair(resolved: &Resolved) -> Pair<'_> {
    (&resolved.snapshot, &resolved.resolution)
}

/// The graph one cached build returns, or the refusal it took.
pub fn build(
    cache: &mut GraphCache,
    stated: Pair<'_>,
    limits: GraphLimits,
) -> Result<CachedCodeGraph, GraphBuildError> {
    let (snapshot, resolution) = stated;
    cache.build_rust_graph(snapshot, resolution, limits)
}

/// The graph one cached build returns, under the default ceilings.
///
/// Ceilings are a separate dimension every other case holds still, so the
/// ordinary reading takes the defaults and the ceiling cases state their own.
pub fn admitted(cache: &mut GraphCache, stated: Pair<'_>, subject: &str) -> CachedCodeGraph {
    bounded(cache, stated, GraphLimits::default(), subject)
}

/// The graph one cached build returns under stated ceilings.
pub fn bounded(
    cache: &mut GraphCache,
    stated: Pair<'_>,
    limits: GraphLimits,
    subject: &str,
) -> CachedCodeGraph {
    build(cache, stated, limits)
        .unwrap_or_else(|error| panic!("{subject} should build through the cache: {error}"))
}

/// The graph the direct builder returns for the same inputs.
pub fn direct(stated: Pair<'_>, limits: GraphLimits, subject: &str) -> CodeGraph {
    let (snapshot, resolution) = stated;
    build_rust_graph_with_limits(snapshot, resolution, limits)
        .unwrap_or_else(|error| panic!("{subject} should build directly: {error}"))
}

/// A cached graph equals what the direct builder returns, and serializes to the
/// same bytes.
///
/// One direct graph is projected per comparison. The default-ceiling entry point
/// forwards to the bounded one, so which of the two published builders is read
/// here is a claim about the direct surface itself and is stated once, by
/// [`assert_direct_builders_agree`], rather than at every cached row.
pub fn assert_matches_direct(cached: &CodeGraph, stated: Pair<'_>, subject: &str) {
    let direct = direct(stated, GraphLimits::default(), subject);
    assert_eq!(
        cached, &direct,
        "{subject}: cached and direct graphs differ"
    );
    assert_eq!(
        json(cached),
        json(&direct),
        "{subject}: cached and direct version-1 bytes differ"
    );
    assert_eq!(
        cached.schema_version(),
        CodeGraph::SCHEMA_VERSION,
        "{subject}: the schema version is unchanged"
    );
}

/// The two published direct builders return one graph for one input.
///
/// [`build_rust_graph`] is [`build_rust_graph_with_limits`] under the default
/// ceilings, so this is one claim about the published surface: that the shorter
/// entry point still forwards the ceilings it names.
pub fn assert_direct_builders_agree(stated: Pair<'_>, subject: &str) {
    let (snapshot, resolution) = stated;
    let unbounded = build_rust_graph(snapshot, resolution).unwrap_or_else(|error| {
        panic!("{subject} should build under the default ceilings: {error}")
    });
    assert_eq!(
        &unbounded,
        &direct(stated, GraphLimits::default(), subject),
        "{subject}: the two direct builders disagree"
    );
}

/// One refused pairing returns the direct refusal and moves no counter.
///
/// Shared: a refusal the cache must take before it observes anything is read the
/// same way whichever dimension states the disagreement.
pub fn assert_refused_without_observation(
    cache: &mut GraphCache,
    stated: Pair<'_>,
    expected: GraphBuildError,
    subject: &str,
) {
    let (snapshot, resolution) = stated;
    let before = cache.stats();
    let refused = build(cache, stated, GraphLimits::default())
        .err()
        .unwrap_or_else(|| panic!("{subject}: an invalid pairing must be refused"));
    let directly = build_rust_graph_with_limits(snapshot, resolution, GraphLimits::default())
        .expect_err("the direct builder refuses the same pairing");
    assert_eq!(
        format!("{refused:?}"),
        format!("{expected:?}"),
        "{subject}: the cache returns the existing refusal"
    );
    assert_eq!(
        format!("{refused:?}"),
        format!("{directly:?}"),
        "{subject}: the cached and direct refusals agree"
    );
    assert_delta(before, cache.stats(), &[], subject);
}

/// The exact compact version-1 bytes one graph serializes to.
pub fn json(graph: &CodeGraph) -> String {
    serde_json::to_string(graph).expect("a built graph serializes")
}

/// One resolution restated over its own snapshot under one claim dimension.
pub fn restated(resolved: &Resolved, restatement: Restatement) -> RustTargetResolution {
    promotion::restate(
        &resolved.snapshot,
        resolved.resolution.report(),
        restatement,
    )
}

/// One cache holding one graph of `files`, with the repository already gone.
///
/// The derived cases read a graph rather than a repository, and a projected
/// graph owns everything it answers with, so the temporary directory is
/// released here instead of being kept alive through every assertion. The
/// resolution travels back so a case can build the same claim again.
pub fn cached_workspace(
    files: &[(&str, &str)],
    limits: GraphCacheLimits,
) -> (Resolved, GraphCache, CachedCodeGraph) {
    let (directory, resolved) = fixture::resolve_target(files, fixture::CORPUS_LIBRARY);
    let (cache, held) = cached_from(&resolved, limits);
    drop(directory);
    (resolved, cache, held)
}

/// One cache holding one graph of a corpus that is already resolved.
///
/// A row that varies only the ceilings varies only the cache, so the repository
/// behind it is materialized, loaded, snapshotted, and resolved once and every
/// row of the table is built from the pair it produced.
pub fn cached_from(resolved: &Resolved, limits: GraphCacheLimits) -> (GraphCache, CachedCodeGraph) {
    let mut cache = GraphCache::new(limits);
    let held = admitted(&mut cache, pair(resolved), "the cached workspace");
    (cache, held)
}

/// Clearing drops the cache's own entries, keeps every cumulative counter, and
/// leaves the caller's graph valid, unmoved in value, and rebuildable.
///
/// Shared: the exact owner and the projection owner both state this claim, and
/// a cleared store answers it the same way whichever entry it was retaining —
/// it retains nothing, so the rebuild derives every fragment of the graph it
/// returns. The rebuild is required to be a fresh allocation that is still
/// equal, value for value and byte for byte, to the one the caller held: that
/// is the half of "clearing does not disturb a live handle" a caller can
/// actually observe.
pub fn assert_clear_keeps_the_held_graph(
    cache: &mut GraphCache,
    base: &Resolved,
    held: &CachedCodeGraph,
    subject: &str,
) {
    let before = cache.stats();
    cache.clear();
    assert_delta(
        before,
        cache.stats(),
        &[],
        &format!("{subject}: clearing the cache"),
    );
    assert_matches_direct(held.graph(), pair(base), subject);

    let rebuilt = assert_build_classifies(
        cache,
        pair(base),
        Classification::retained(0, fragments_of(held.graph())),
        &format!("{subject}: a cleared store derives every fragment again"),
    );
    assert!(
        !std::ptr::eq(held.graph(), rebuilt.graph()),
        "{subject}: a cleared store answers from a fresh allocation"
    );
    assert_eq!(
        held.graph(),
        rebuilt.graph(),
        "{subject}: the held graph equals the one the cleared store rebuilt"
    );
    assert_eq!(
        json(held.graph()),
        json(rebuilt.graph()),
        "{subject}: the held and rebuilt graphs state the same version-1 bytes"
    );
}

/// One corpus resolved twice: the library root and a second declared target.
///
/// The two pairings are both valid and name different root targets, which is
/// the one identity dimension a report restatement cannot state.
pub fn two_root_targets() -> (Fixture, Resolved, Resolved) {
    let corpus = Fixture::build(TARGET_KIND_CORPUS);
    let library = corpus.resolve(corpus.sole_library());
    let example = corpus.resolve(corpus.target("app", CargoTargetKind::Example, "demo"));
    (corpus, library, example)
}
