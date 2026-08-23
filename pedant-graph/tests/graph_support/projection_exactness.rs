//! What the Rust answers still are once the assembler stopped being Rust's,
//! and what the cache still is once a second language can reach that assembler.
//!
//! The neutral family changed who mints a graph, not what a graph is. These
//! cases read the two claims that would fail silently if it had: every Rust
//! graph a caller can obtain — directly, at a lowered ceiling, and through a
//! cache miss — is byte-for-byte what it was, and the cache around it stays a
//! Rust-only surface that names no other language.

use std::collections::BTreeSet;

use pedant_graph::{
    CodeGraph, GraphBuildError, GraphCache, GraphCollection, GraphLimits,
    build_rust_graph_with_limits,
};

use super::analysis_perturbation::created_in_reverse;
use super::cache_counting::{
    Classification, EXACT_GRAPH_HITS, assert_build_classifies, assert_delta,
};
use super::cache_fixture::{
    admitted, assert_clear_keeps_the_held_graph, assert_direct_builders_agree,
    assert_matches_direct, bounded, build, exact_only, generous, json, pair, projection_only,
};
use super::cache_ownership::assert_cache_public_boundary_is_exact;
use super::cache_revision::{REVISIONS, revised};
use super::corpus_revision::{REVISION_CORPUS, REVISION_FRAGMENTS};
use super::fixture::{self, CORPUS_LIBRARY, Resolved};
use super::inventory::{CACHE_SOURCES, SOURCES};
use super::render;
use super::scan::{code_only, compact, source};

/// The core vocabulary of every language the cache may never name.
///
/// The Rust spellings are the cache entry point's own and are read separately;
/// these are the ones that would arrive with a second adapter. A cache that
/// named one of them would have taken on a language it retains nothing for.
const FOREIGN_SPELLINGS: &[&str] = &[
    "GoResolutionSnapshot",
    "GoProjectResolution",
    "GoProject",
    "GoResolver",
    "GoResolutionLimits",
    "build_go_graph",
    "go_resolution",
    "resolution::go",
];

/// The one adapter cache entry point, and the whole Rust vocabulary it names.
const CACHE_ENTRY: &str = "src/rust/cache.rs";

/// Direct, bounded, and cache-miss Rust graphs are byte-identical to what the
/// Rust-owned assembler returned, over every retained corpus.
pub fn assert_rust_projection_bytes_stay_exact() {
    assert_direct_and_cached_revisions_agree();
    assert_lowered_ceilings_refuse_alike();
    assert_enumeration_order_changes_nothing();
}

/// Every revision of the retained corpus states one graph, whichever entry a
/// caller reached it through, and the projection seam classifies it exactly.
///
/// The revised build is run against a warmed store, so its fragments arrive
/// through the reuse path rather than through a fresh derivation. A retained
/// draft that no longer described the graph the assembler mints would show up
/// here as a difference from the direct build the same inputs produce.
fn assert_direct_and_cached_revisions_agree() {
    for revision in REVISIONS {
        let subject = revision.label();
        let (_repository, base, after) = revised(revision);
        let mut cache = GraphCache::new(projection_only(64));
        let warmed = assert_build_classifies(
            &mut cache,
            pair(&base),
            Classification::retained(0, REVISION_FRAGMENTS),
            &format!("{subject}: the base build"),
        );
        assert_exact_against_direct(warmed.graph(), &base, &format!("{subject}: the base build"));

        let rebuilt = assert_build_classifies(
            &mut cache,
            pair(&after),
            Classification::retained(revision.hits(), revision.misses()),
            subject,
        );
        assert_exact_against_direct(rebuilt.graph(), &after, subject);
    }
}

/// One graph equals the direct build column for column, byte for byte, and
/// through the reading surface a caller compares two graphs with.
fn assert_exact_against_direct(built: &CodeGraph, resolved: &Resolved, subject: &str) {
    assert_matches_direct(built, pair(resolved), subject);
    assert_direct_builders_agree(pair(resolved), subject);
    let direct = build_rust_graph_with_limits(
        &resolved.snapshot,
        &resolved.resolution,
        GraphLimits::default(),
    )
    .unwrap_or_else(|error| panic!("{subject} should build directly: {error}"));
    for (reading, held, minted) in [
        ("nodes", render::nodes(built), render::nodes(&direct)),
        (
            "containment",
            render::containment(built),
            render::containment(&direct),
        ),
        (
            "reference sites",
            render::reference_sites(built),
            render::reference_sites(&direct),
        ),
    ] {
        assert_eq!(held, minted, "{subject}: the rendered {reading} differ");
    }
    assert_eq!(
        (
            built.nodes().len(),
            built.references().len(),
            built.edges().len(),
            built.containment().len(),
        ),
        (
            direct.nodes().len(),
            direct.references().len(),
            direct.edges().len(),
            direct.containment().len(),
        ),
        "{subject}: the two builds state different record counts"
    );
    assert_eq!(
        json(built),
        json(&direct),
        "{subject}: the version-1 bytes differ"
    );
}

/// A lowered ceiling refuses the same collection and amount whichever entry
/// point takes it, and a hit reapplies it in construction order.
fn assert_lowered_ceilings_refuse_alike() {
    let (_repository, resolved) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(generous());
    let warm = admitted(&mut cache, pair(&resolved), "the warming build");
    let counts = [
        ("node", warm.graph().nodes().len(), GraphCollection::Node),
        (
            "reference",
            warm.graph().references().len(),
            GraphCollection::Reference,
        ),
        ("edge", warm.graph().edges().len(), GraphCollection::Edge),
    ];

    for (label, counted, collection) in counts {
        assert!(counted > 0, "the warming graph states at least one {label}");
        let ceiling = u32::try_from(counted)
            .unwrap_or_else(|error| panic!("{label}s outnumber a dense identity: {error}"))
            - 1;
        let limits = lowered(collection, ceiling);
        let before = cache.stats();
        let cached = build(&mut cache, pair(&resolved), limits)
            .err()
            .unwrap_or_else(|| panic!("{label}: the lowered ceiling was admitted"));
        let directly =
            build_rust_graph_with_limits(&resolved.snapshot, &resolved.resolution, limits)
                .err()
                .unwrap_or_else(|| panic!("{label}: the direct build admitted it"));
        match cached {
            GraphBuildError::CapacityExceeded {
                collection: refused,
                limit,
            } => assert_eq!(
                (refused, limit),
                (collection, ceiling),
                "{label}: the refusal names its own collection and ceiling"
            ),
            other => panic!("{label}: unexpected refusal {other:?}"),
        }
        assert_eq!(
            format!("{cached:?}"),
            format!("{directly:?}"),
            "{label}: the cached and direct refusals agree"
        );
        assert_delta(before, cache.stats(), &[(EXACT_GRAPH_HITS, 1)], label);
    }

    let readmitted = bounded(
        &mut cache,
        pair(&resolved),
        GraphLimits::default(),
        "the readmitted build",
    );
    assert!(
        std::ptr::eq(warm.graph(), readmitted.graph()),
        "a refused ceiling leaves the retained graph in place"
    );
}

/// The ceilings that admit every collection but one.
fn lowered(collection: GraphCollection, ceiling: u32) -> GraphLimits {
    match collection {
        GraphCollection::Node => GraphLimits::new(ceiling, u32::MAX, u32::MAX),
        GraphCollection::Reference => GraphLimits::new(u32::MAX, ceiling, u32::MAX),
        GraphCollection::Edge => GraphLimits::new(u32::MAX, u32::MAX, ceiling),
    }
}

/// One corpus written in either direction states one graph and one set of
/// bytes.
///
/// The assembler mints in fixed passes over the plan, so the order a caller's
/// filesystem happened to enumerate its sources in must not reach the output.
fn assert_enumeration_order_changes_nothing() {
    let (_forward, forward) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let (_reverse, reverse) =
        fixture::resolve_target(&created_in_reverse(REVISION_CORPUS), CORPUS_LIBRARY);
    let subject = "a reversed enumeration order";
    let first = build_rust_graph_with_limits(
        &forward.snapshot,
        &forward.resolution,
        GraphLimits::default(),
    )
    .unwrap_or_else(|error| panic!("{subject}: the forward corpus builds: {error}"));
    let second = build_rust_graph_with_limits(
        &reverse.snapshot,
        &reverse.resolution,
        GraphLimits::default(),
    )
    .unwrap_or_else(|error| panic!("{subject}: the reversed corpus builds: {error}"));
    assert_eq!(
        json(&first),
        json(&second),
        "{subject}: equal projects state equal version-1 bytes"
    );
}

/// The cache is still the Rust-only surface it was: one entry point, one
/// vocabulary, no other language, and the exact answers it published before.
pub fn assert_cache_remains_rust_only() {
    assert_cache_public_boundary_is_exact();
    assert_no_cache_source_names_another_language();
    assert_only_the_adapter_entry_names_a_resolution();
    assert_retained_answers_are_exact();
}

/// No cache module and no cache entry point names a second language.
fn assert_no_cache_source_names_another_language() {
    let offenders: Vec<String> = CACHE_SOURCES
        .iter()
        .copied()
        .chain(std::iter::once(CACHE_ENTRY))
        .flat_map(|path| {
            let code = compact(source(path));
            FOREIGN_SPELLINGS
                .iter()
                .filter(move |spelling| code.contains(**spelling))
                .map(move |spelling| format!("{path} names {spelling}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "the cache surface names a language it retains nothing for: {offenders:?}"
    );
    assert!(
        !compact(super::inventory::MANIFEST).contains("[features]"),
        "the graph manifest states no feature the cache could be gated by"
    );
}

/// The one cache entry point is the only cache source naming a resolution
/// type, and every reuse key it states is still the Rust claim.
fn assert_only_the_adapter_entry_names_a_resolution() {
    let entry = code_only(source(CACHE_ENTRY));
    for required in [
        "RustResolutionSnapshot",
        "RustTargetResolution",
        "build_rust_graph",
    ] {
        assert!(
            entry.contains(required),
            "{CACHE_ENTRY} states the Rust claim it retains: {required}"
        );
    }
    let published: BTreeSet<&str> = SOURCES
        .iter()
        .filter(|held| CACHE_SOURCES.contains(&held.path))
        .filter(|held| code_only(held.text).contains("pub fn build_"))
        .map(|held| held.path)
        .collect();
    assert!(
        published.is_empty(),
        "no language-neutral cache module publishes a builder: {published:?}"
    );
}

/// A retained graph still answers exactly what the direct build answers, and
/// every published counter still reads the amount that answer owed.
///
/// The exact-graph ceiling admits the claim and the projection ceiling admits
/// nothing, so the first build owes one graph miss and one derivation per
/// fragment, and the second owes one graph hit and no examination at all.
fn assert_retained_answers_are_exact() {
    let subject = "the retained Rust claim";
    let (_repository, base) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(exact_only(64));
    let held = assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, REVISION_FRAGMENTS),
        subject,
    );
    assert_matches_direct(held.graph(), pair(&base), subject);

    let before = cache.stats();
    let repeated = admitted(&mut cache, pair(&base), &format!("{subject}, repeated"));
    assert_delta(
        before,
        cache.stats(),
        &[(EXACT_GRAPH_HITS, 1)],
        &format!("{subject}, repeated"),
    );
    assert!(
        std::ptr::eq(held.graph(), repeated.graph()),
        "{subject}: an equal claim is answered from the retained graph"
    );
    assert_clear_keeps_the_held_graph(&mut cache, &base, &held, subject);
}
