//! What the cache still is once a second language can reach the assembler
//! beneath it.
//!
//! Assembling a graph and keeping one are separate jobs, and only the first
//! became language-neutral. These cases read the half that did not: the
//! retention surface stays the Rust adapter's, with one entry point, one
//! vocabulary, no other language, no selection, and the exact answers it
//! published before.

use std::collections::BTreeSet;

use pedant_graph::GraphCache;

use super::cache_counting::{
    Classification, EXACT_GRAPH_HITS, assert_build_classifies, assert_delta,
};
use super::cache_fixture::{
    admitted, assert_clear_keeps_the_held_graph, assert_matches_direct, exact_only, pair,
};
use super::cache_ownership::assert_cache_public_boundary_is_exact;
use super::corpus_revision::{REVISION_CORPUS, REVISION_FRAGMENTS};
use super::fixture::{self, CORPUS_LIBRARY};
use super::inventory::{CACHE_SOURCES, PROJECTION_SOURCES, SOURCES};
use super::ownership_model::GO_VOCABULARY;
use super::scan::{code_only, compact, naming, parsed, source, token_text};

/// The one adapter cache entry point, and the whole Rust vocabulary it names.
const CACHE_ENTRY: &str = "src/rust/cache.rs";

/// The retention vocabulary no neutral source may name.
///
/// Assembling a graph and keeping one are separate jobs, and only the first is
/// language-neutral. A neutral module that reached for a store, a counter, or a
/// retained handle would be a cache every later adapter inherited whether or not
/// it retains anything — which is the opposite of the Rust-only surface this
/// case exists to hold.
const RETENTION_SPELLINGS: &[&str] = &[
    "crate::cache",
    "GraphCache",
    "CachedCodeGraph",
    "CachedGraphState",
    "BoundedStore",
    "CacheCategory",
    "CacheCounters",
    "CacheEvent",
];

/// The one source that retains a projection between builds.
const RETENTION_OWNER: &str = "src/rust/reuse.rs";

/// The record that owner retains, reached from the neutral family that declares
/// it.
const NEUTRAL_RETAINED_IMPORT: &str = "use crate::projection::draft::SourceFragment;";

/// The retained entries, as the store declares them.
const RETAINED_ENTRIES: &str = "BoundedStore<SourceKey,Arc<SourceFragment>>";

/// The neutral record the retention owner hands back, which no cache module may
/// name.
const RETAINED_RECORD: &str = "SourceFragment";

/// The crate root, where a module a build selects is gated.
const MODULE_ROOT: &str = "src/lib.rs";

/// The module that root admits whatever the build selected.
const CACHE_MODULE: &str = "cache";

/// The conditional spelling a selected language would arrive under.
const SELECTION: &str = "feature";

/// The cache is still the Rust-only surface it was: one entry point, one
/// vocabulary, no other language, no selection, and the exact answers it
/// published before.
pub fn assert_cache_remains_rust_only() {
    assert_cache_public_boundary_is_exact();
    assert_no_cache_source_names_another_language();
    assert_no_selection_reaches_the_cache();
    assert_only_the_adapter_entry_names_a_resolution();
    assert_the_neutral_family_holds_no_retention();
    assert_retention_reuses_the_neutral_draft();
    assert_retained_answers_are_exact();
}

/// No module of the neutral family names anything a cache is made of.
///
/// The half of this claim the neutral family owns. Every language now reaches
/// one assembler; the surface that retains what that assembler mints stays the
/// Rust adapter's, and it stays there only while the family beneath it names no
/// store, counter, or retained handle of its own.
fn assert_the_neutral_family_holds_no_retention() {
    let offenders = naming(PROJECTION_SOURCES, RETENTION_SPELLINGS, "the retention");
    assert!(
        offenders.is_empty(),
        "the neutral projection family holds a retention of its own: {offenders:?}"
    );
}

/// The retained record is the neutral family's draft, and no cache module knows
/// what it is.
///
/// Reuse is where the two halves meet: the adapter states which claim a
/// retained projection answers, the neutral family states what that projection
/// *is*, and the bounded store beneath keeps a value it never reads. A
/// retention owner holding an adapter-shaped record instead would be the drafts
/// copied back under `rust/`, with the cache the copy no caller could see.
fn assert_retention_reuses_the_neutral_draft() {
    let owner = code_only(source(RETENTION_OWNER));
    assert!(
        owner.contains(NEUTRAL_RETAINED_IMPORT),
        "{RETENTION_OWNER} retains what the neutral family declares: {NEUTRAL_RETAINED_IMPORT}"
    );
    assert!(
        compact(source(RETENTION_OWNER)).contains(RETAINED_ENTRIES),
        "{RETENTION_OWNER} retains its entries as {RETAINED_ENTRIES}"
    );
    let offenders: Vec<&str> = SOURCES
        .iter()
        .filter(|held| CACHE_SOURCES.contains(&held.path))
        .filter(|held| code_only(held.text).contains(RETAINED_RECORD))
        .map(|held| held.path)
        .collect();
    assert!(
        offenders.is_empty(),
        "a cache module names the retained record it only holds: {offenders:?}"
    );
}

/// No cache module and no cache entry point names a second language.
///
/// The Rust spellings are the cache entry point's own and are read separately;
/// the Go vocabulary is the one that would arrive with a second adapter, and it
/// is the same written-down table the neutral family and the Rust adapter are
/// held to. A cache that named one of these would have taken on a language it
/// retains nothing for.
fn assert_no_cache_source_names_another_language() {
    let offenders = naming(&cache_surface(), GO_VOCABULARY, "the Go spelling");
    assert!(
        offenders.is_empty(),
        "the cache surface names a language it retains nothing for: {offenders:?}"
    );
}

/// Every language-neutral cache module, beside the one adapter entry point
/// built on them.
fn cache_surface() -> Vec<&'static str> {
    CACHE_SOURCES
        .iter()
        .copied()
        .chain(std::iter::once(CACHE_ENTRY))
        .collect()
}

/// No feature selection reaches the cache: not a module of it, not its entry
/// point, and not the declaration that admits them.
///
/// A second adapter arrives behind a feature of its own, and that is where a
/// selection belongs — on the language it adds. One that reached the retention
/// surface instead would make what a Rust caller retains depend on which other
/// language the build happened to select, and the exact answers this case ends
/// on would hold in one build and not the next. What features the crate
/// declares is the manifest model's claim, not this one's.
fn assert_no_selection_reaches_the_cache() {
    let selected: Vec<&str> = cache_surface()
        .into_iter()
        .filter(|path| compact(source(path)).contains(SELECTION))
        .collect();
    assert!(
        selected.is_empty(),
        "the cache surface states a selection it could be gated by: {selected:?}"
    );
    let declaration = parsed(MODULE_ROOT)
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Mod(module) if module.ident == CACHE_MODULE => Some(module),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{MODULE_ROOT} declares no mod {CACHE_MODULE}"));
    let conditions: Vec<String> = declaration
        .attrs
        .iter()
        .map(token_text)
        .filter(|attribute| attribute.contains(SELECTION))
        .collect();
    assert!(
        conditions.is_empty(),
        "{MODULE_ROOT} admits mod {CACHE_MODULE} whatever the build selects: {conditions:?}"
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
