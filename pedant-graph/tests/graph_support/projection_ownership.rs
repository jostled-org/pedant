//! The one language-neutral projection family, and who may enter it.
//!
//! A graph adapter states what one snapshot and one report claim; the drafts,
//! the placement, the tables, and the checked assembler beneath it name no
//! language at all. These cases hold that boundary to the tree: the neutral
//! family is discovered rather than assumed, it may name no language
//! vocabulary, the drafts and the assembler are declared exactly once and only
//! there, no adapter directory declares an assembler of its own, both Rust
//! entries reach the neutral one, and every dense identity is still minted by
//! the single checked insertion owner.
//!
//! Every input is a compile-time source read through [`super::scan`], beside
//! the one directory listing that rejects a module which appeared without an
//! entry.

use std::collections::BTreeSet;

use super::inventory::{CACHE_SOURCES, PROJECTION_SOURCES, RUST_SOURCES, SOURCES};
use super::scan::{
    code_only, compact, declaring_sources, discovered_sources, function_body, method_body, parsed,
    source,
};
use super::surface::{declared_items, declares_only, item_label};

/// Every predicate the neutral projection family registers at the one root.
pub const PROJECTION_PREDICATES: &[&str] = &[
    "graph_cache_remains_rust_only_after_neutral_assembly",
    "graph_projection_has_one_language_neutral_assembler",
    "rust_direct_and_cached_projection_bytes_stay_exact_after_neutral_assembly",
];

/// The neutral family root, which declares and re-exports only.
const PROJECTION_ROOT: &str = "src/projection/mod.rs";

/// The one source that declares the graph-neutral drafts.
const DRAFT_OWNER: &str = "src/projection/draft.rs";

/// The one source that declares the checked assembler.
const ASSEMBLY_OWNER: &str = "src/projection/assembly.rs";

/// The declaration the sole assembler is written with.
const ASSEMBLER_DECLARATION: &str = "pub(crate) fn assemble(";

/// The adapter modules the neutral family took over.
///
/// Named as module stems rather than as a claim about the whole directory: an
/// adapter may state its own snapshot claims, its own vocabulary, and its own
/// planner, and none of those is an assembly owner. What it may not do is hold
/// a second copy of one of these.
const NEUTRALIZED_MODULES: &[&str] = &[
    "assembly",
    "containment_check",
    "fragment",
    "identity",
    "index",
];

/// Every draft record a language adapter fills in, beside nothing else.
///
/// Written down rather than discovered: a draft that moved back under an
/// adapter would leave this list naming a record the neutral owner no longer
/// declares, and a second copy under `rust/` would be found by the same
/// comparison.
const DRAFT_RECORDS: &[&str] = &[
    "CandidateProjection",
    "DefinitionProjection",
    "DependencyProjection",
    "FragmentSlot",
    "PlacedFragment",
    "ProjectionPlan",
    "ReferenceProjection",
    "SourceFragment",
    "UnitPlan",
];

/// The language vocabulary no neutral source may name.
///
/// Each is the exact production spelling an adapter type would arrive under.
/// The neutral family holds drafts a language filled in; the moment it reads
/// one of these, the assembler has a language of its own and a second one would
/// have to be written for the next.
const LANGUAGE_SPELLINGS: &[&str] = &[
    "pedant_core",
    "RustResolutionSnapshot",
    "RustTargetResolution",
    "RustSnapshotUnitId",
    "RustSnapshotEdge",
    "RustSnapshotFingerprint",
    "RustUnitBinding",
    "RustResolutionUnit",
    "Vocabulary",
    "crate::rust",
    "super::rust",
    "GoResolutionSnapshot",
    "GoProjectResolution",
];

/// The dense identities only the record store may mint.
const MINTED_IDENTITIES: &[&str] = &[
    "GraphNodeId::new",
    "GraphReferenceId::new",
    "GraphEdgeId::new",
];

/// The sole checked insertion owner every minted identity passes through.
const INSERTION_OWNER: &str = "fn admit";

/// Both Rust entries into the neutral assembler, beside the owner declaring
/// them.
///
/// The direct path plans then assembles; the cached path does the same on a
/// miss. Both are named, because a cache miss that grew an assembler of its own
/// would answer a caller with a graph no other entry could produce.
const RUST_ENTRIES: &[(&str, &str)] = &[
    ("src/rust/projection.rs", "project"),
    ("src/rust/cache.rs", "build_missing"),
];

/// The import both Rust entries reach the neutral assembler through.
const NEUTRAL_IMPORT: &str = "use crate::projection::assembly;";

/// The call both Rust entries state, as the parsed body renders it.
const NEUTRAL_CALL: &str = "assembly :: assemble";

/// One neutral projection family owns every draft and the one checked
/// assembler, no adapter declares a second, and dense identities are still
/// minted in one place.
pub fn assert_projection_has_one_language_neutral_assembler() {
    assert_the_neutral_family_is_discovered();
    assert_the_family_root_only_declares();
    assert_the_neutral_family_names_no_language();
    assert_the_drafts_have_one_owner();
    assert_the_assembler_has_one_owner();
    assert_rust_entries_reach_the_neutral_assembler();
    assert_identities_are_minted_by_one_owner();
}

/// The neutral module inventory is exactly what the tree holds beneath
/// `src/projection`.
fn assert_the_neutral_family_is_discovered() {
    let discovered: BTreeSet<String> = discovered_sources()
        .into_iter()
        .filter(|path| path.starts_with("src/projection/"))
        .collect();
    assert_eq!(
        discovered,
        PROJECTION_SOURCES
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<BTreeSet<String>>(),
        "every neutral module is modelled and every modelled module exists"
    );
    let scanned: Vec<&str> = SOURCES
        .iter()
        .map(|entry| entry.path)
        .filter(|path| path.starts_with("src/projection/"))
        .collect();
    assert_eq!(
        scanned, PROJECTION_SOURCES,
        "every neutral module carries its compile-time text"
    );
}

/// The family root declares modules and re-exports names, and defines nothing.
fn assert_the_family_root_only_declares() {
    let root = parsed(PROJECTION_ROOT);
    let defined: Vec<String> = root
        .items
        .iter()
        .filter(|item| !declares_only(item))
        .map(item_label)
        .collect();
    assert!(
        defined.is_empty(),
        "{PROJECTION_ROOT} must declare and re-export only: {defined:?}"
    );
    let declared: BTreeSet<String> = root
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) => Some(module.ident.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        declared,
        PROJECTION_SOURCES
            .iter()
            .filter(|entry| !entry.ends_with("mod.rs"))
            .map(|entry| entry
                .trim_start_matches("src/projection/")
                .trim_end_matches(".rs")
                .to_owned())
            .collect::<BTreeSet<String>>(),
        "{PROJECTION_ROOT} declares exactly its own modules"
    );
}

/// No neutral source names a language adapter's vocabulary.
fn assert_the_neutral_family_names_no_language() {
    let offenders: Vec<String> = PROJECTION_SOURCES
        .iter()
        .flat_map(|path| {
            let code = compact(source(path));
            LANGUAGE_SPELLINGS
                .iter()
                .filter(move |spelling| code.contains(**spelling))
                .map(move |spelling| format!("{path} names {spelling}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "the neutral projection family names a language vocabulary: {offenders:?}"
    );
}

/// Every draft record is declared once, by the neutral draft owner, and the
/// owner declares no other.
fn assert_the_drafts_have_one_owner() {
    for record in DRAFT_RECORDS {
        let declaration = format!("pub(crate) struct {record}");
        assert_eq!(
            declaring_sources(&declaration),
            vec![DRAFT_OWNER],
            "{declaration} is declared by exactly the neutral draft owner"
        );
    }
    let held: BTreeSet<String> = declared_items(&parsed(DRAFT_OWNER).items)
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Struct(found) => Some(found.ident.to_string()),
            syn::Item::Enum(found) => Some(found.ident.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        held,
        DRAFT_RECORDS
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<String>>(),
        "the neutral draft owner declares exactly the modelled drafts"
    );
}

/// Exactly one source declares the assembler, and no adapter module declares
/// one at all.
fn assert_the_assembler_has_one_owner() {
    assert_eq!(
        declaring_sources(ASSEMBLER_DECLARATION),
        vec![ASSEMBLY_OWNER],
        "{ASSEMBLER_DECLARATION} is declared by exactly the neutral assembly owner"
    );
    let adapter: Vec<&str> = RUST_SOURCES
        .iter()
        .copied()
        .filter(|path| {
            NEUTRALIZED_MODULES
                .iter()
                .any(|name| *path == format!("src/rust/{name}.rs"))
        })
        .collect();
    assert!(
        adapter.is_empty(),
        "no assembly owner may live under an adapter directory: {adapter:?}"
    );
    assert_eq!(
        function_body(ASSEMBLY_OWNER, "assemble")
            .matches("state . finish")
            .count(),
        1,
        "the one assembler seals exactly one graph"
    );
}

/// Both Rust entries reach the neutral assembler, and neither states one of its
/// own.
fn assert_rust_entries_reach_the_neutral_assembler() {
    for (path, entry) in RUST_ENTRIES {
        assert!(
            code_only(source(path)).contains(NEUTRAL_IMPORT),
            "{path} must reach the assembler through {NEUTRAL_IMPORT}"
        );
        let body = match *path {
            "src/rust/cache.rs" => method_body(path, entry),
            other => function_body(other, entry),
        };
        assert!(
            body.contains(NEUTRAL_CALL),
            "{path}::{entry} must assemble through the neutral owner"
        );
    }
}

/// No neutral, adapter, or cache module mints a graph identity.
///
/// The derived answers read identities back out of a graph they were handed,
/// which is not minting. Every module on the graph-building path must take each
/// identity from the one checked insertion owner instead.
///
/// Published so the cache's own path predicate states this claim by reaching
/// the owner of it rather than by scanning the same three families again.
pub fn assert_identities_are_minted_by_one_owner() {
    let offenders: Vec<&str> = SOURCES
        .iter()
        .filter(|entry| {
            [PROJECTION_SOURCES, RUST_SOURCES, CACHE_SOURCES]
                .into_iter()
                .any(|family| family.contains(&entry.path))
        })
        .filter(|entry| {
            let code = compact(entry.text);
            MINTED_IDENTITIES
                .iter()
                .any(|spelling| code.contains(*spelling))
        })
        .map(|entry| entry.path)
        .collect();
    assert!(
        offenders.is_empty(),
        "only the record store mints graph identities: {offenders:?}"
    );
    assert_eq!(
        code_only(source("src/graph.rs"))
            .matches(INSERTION_OWNER)
            .count(),
        1,
        "there is exactly one checked insertion owner, spelled {INSERTION_OWNER}"
    );
}
