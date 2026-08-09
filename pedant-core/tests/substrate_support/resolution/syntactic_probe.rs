//! Parse-only observations only the proof feature can make.
//!
//! Tier 1 must read nothing outside the repository root and name no process
//! API. Every subject below is stated, not counted from a run: the corpus
//! inventories are read off the fixture's own manifests and module tree, and
//! [`TIER1_SOURCES`] names each file the process scan must cover. A scan whose
//! subjects come from the walker it is checking proves nothing when the walker
//! returns too little, so the walker's answer is compared with the model first.

use std::path::PathBuf;

use crate::declaration_scan::{
    PathIdents, assert_semantic_exclusion_is_not_vacuous, crate_path, crate_sources, excluded_root,
    module_files, parse_rust_file, process_evidence,
};

/// Every source the corpus reads, parses, and walks, in closure order: the root
/// library, the one module it declares, and the library of its one path
/// dependency.
pub const CORPUS_SOURCES: &[&str] = &["src/lib.rs", "src/alpha.rs", "crates/helper/src/lib.rs"];

/// Every source
/// [`SHARED_SOURCE`](super::syntactic_fixtures::SHARED_SOURCE) reads and parses,
/// in closure order.
///
/// `shared/common.rs` belongs to both closures and appears once: the root unit
/// reaches it first, and the path dependency's own `#[path]` declaration finds
/// it already stored. A store that keyed anything but the normalized path would
/// name it twice here.
pub const SHARED_SOURCES: &[&str] = &["src/lib.rs", "shared/common.rs", "crates/helper/src/lib.rs"];

/// The one source whose `use` items the extractor walks, once per item. The
/// corpus root states two `use` items; no other source states one.
pub const CORPUS_IMPORT_WALKS: &[&str] = &["src/lib.rs", "src/lib.rs"];

/// Every manifest read the corpus states, in order.
///
/// The corpus holds two manifests. Indexing reads each once, in discovery
/// order: the root first, then the path dependency it names. Snapshotting then
/// re-checks the indexed revision of each, in sorted order. Nothing else is
/// read, so a loader that reached a third manifest — or read one of these
/// twice more — changes this list.
pub const CORPUS_MANIFEST_READS: &[&str] = &[
    "Cargo.toml",
    "crates/helper/Cargo.toml",
    "Cargo.toml",
    "crates/helper/Cargo.toml",
];

/// The modules Tier 1 runs inside, whose sources may name no process API.
const TIER1_MODULES: &[&str] = &["ir", "observe", "resolution"];

/// Every source of [`TIER1_MODULES`], less the semantic adapter subtree, stated
/// as the exact set the process scan covers.
///
/// This list is the scan's subject, not its result: adding a Tier 1 source
/// without admitting it here fails the comparison, so the scan can never
/// silently cover less of the tier than the tier holds.
pub const TIER1_SOURCES: &[&str] = &[
    "ir/cfg.rs",
    "ir/dataflow.rs",
    "ir/extract/enrich.rs",
    "ir/extract/extractor/entry.rs",
    "ir/extract/extractor/mod.rs",
    "ir/extract/extractor/state.rs",
    "ir/extract/fingerprint.rs",
    "ir/extract/fn_scope.rs",
    "ir/extract/impls.rs",
    "ir/extract/imports.rs",
    "ir/extract/locals.rs",
    "ir/extract/mod.rs",
    PARSE_ROUTE,
    "ir/extract/paths.rs",
    "ir/extract/site_visitor.rs",
    "ir/extract/sites.rs",
    "ir/extract/syn_helpers.rs",
    "ir/extract/type_edges.rs",
    "ir/extract/use_paths.rs",
    "ir/extract/visitor/implementation.rs",
    "ir/extract/visitor/mod.rs",
    "ir/facts.rs",
    "ir/mod.rs",
    "ir/sites/declaration.rs",
    "ir/sites/definition.rs",
    "ir/sites/mod.rs",
    "ir/sites/range.rs",
    "ir/sites/reference.rs",
    "ir/sites/scope.rs",
    "ir/type_introspection.rs",
    "observe/event.rs",
    "observe/mod.rs",
    "observe/probe.rs",
    "resolution/mod.rs",
    "resolution/path_normalization.rs",
    "resolution/rust/dependency.rs",
    "resolution/rust/edition.rs",
    "resolution/rust/error.rs",
    "resolution/rust/identity.rs",
    "resolution/rust/limits.rs",
    "resolution/rust/load/dependency.rs",
    "resolution/rust/load/entry.rs",
    "resolution/rust/load/graph.rs",
    "resolution/rust/load/mod.rs",
    "resolution/rust/load/package.rs",
    "resolution/rust/load/target.rs",
    "resolution/rust/manifest.rs",
    "resolution/rust/members.rs",
    "resolution/rust/mod.rs",
    "resolution/rust/package.rs",
    "resolution/rust/paths.rs",
    "resolution/rust/project.rs",
    "resolution/rust/resolve/bindings.rs",
    "resolution/rust/resolve/claim.rs",
    "resolution/rust/resolve/coordinates.rs",
    "resolution/rust/resolve/corpus.rs",
    "resolution/rust/resolve/error.rs",
    "resolution/rust/resolve/graph.rs",
    "resolution/rust/resolve/imports.rs",
    "resolution/rust/resolve/index.rs",
    "resolution/rust/resolve/lookup.rs",
    "resolution/rust/resolve/mod.rs",
    "resolution/rust/resolve/pipeline.rs",
    "resolution/rust/resolve/promotion.rs",
    "resolution/rust/resolve/records.rs",
    "resolution/rust/resolve/references.rs",
    "resolution/rust/resolve/resolver.rs",
    "resolution/rust/resolve/semantic.rs",
    "resolution/rust/resolve/syntactic.rs",
    "resolution/rust/resolve/target.rs",
    "resolution/rust/resolve/units.rs",
    "resolution/rust/snapshot/activation.rs",
    "resolution/rust/snapshot/authority.rs",
    "resolution/rust/snapshot/closure/entry.rs",
    "resolution/rust/snapshot/closure/mod.rs",
    "resolution/rust/snapshot/closure/path.rs",
    "resolution/rust/snapshot/closure/state.rs",
    "resolution/rust/snapshot/closure/walk.rs",
    "resolution/rust/snapshot/declaration.rs",
    "resolution/rust/snapshot/depth.rs",
    "resolution/rust/snapshot/error.rs",
    "resolution/rust/snapshot/failure.rs",
    "resolution/rust/snapshot/mod.rs",
    "resolution/rust/snapshot/module.rs",
    "resolution/rust/snapshot/primary.rs",
    "resolution/rust/snapshot/reader.rs",
    "resolution/rust/snapshot/resolution.rs",
    "resolution/rust/snapshot/selection.rs",
    "resolution/rust/snapshot/selection_chain.rs",
    "resolution/rust/snapshot/selection_edge.rs",
    "resolution/rust/snapshot/source.rs",
    "resolution/rust/snapshot/store.rs",
    "resolution/rust/snapshot/target.rs",
    "resolution/rust/snapshot/unit.rs",
    "resolution/rust/target.rs",
    "resolution/rust/test_support.rs",
    "resolution/rust/toml_view.rs",
    "resolution/rust/version.rs",
    "resolution/rust/warning.rs",
];

/// The one source that may turn Rust text into a tree, stated as the crate's
/// single parse route. It sits in [`TIER1_SOURCES`] in sorted position, so the
/// tier model and the route model cannot name two different files.
pub const PARSE_ROUTE: &str = "ir/extract/parse.rs";

/// The `syn` entry points that produce a tree from text. A source naming any of
/// them parses, whatever it calls the result.
const SYN_PARSE_ENTRIES: &[&str] = &["parse_file", "parse_str", "parse2"];

/// Every path a probe observed, as comparable borrowed text.
pub fn observed(paths: &[Box<str>]) -> Vec<&str> {
    paths.iter().map(|path| &**path).collect()
}

/// Prove no observed read left the repository: every path a loader recorded is
/// repository-relative and climbs above no root.
///
/// The caller states the inventory this runs over, so an empty observation is
/// caught by that comparison rather than passing here for want of a path.
pub fn assert_reads_stay_inside(paths: &[Box<str>]) {
    assert!(
        !paths.is_empty(),
        "an escape check over no observed read proves nothing"
    );
    let escaping: Vec<&str> = paths
        .iter()
        .map(|path| &**path)
        .filter(|path| path.starts_with('/') || path.split('/').any(|part| part == ".."))
        .collect();
    assert!(
        escaping.is_empty(),
        "observed reads left the repository root: {escaping:?}"
    );
}

/// Prove the modules Tier 1 runs inside are exactly [`TIER1_SOURCES`] and that
/// none of them names a process-capability API.
pub fn assert_tier1_names_no_process_api() {
    let sources = scanned_sources();
    assert_eq!(
        relative_names(&sources),
        TIER1_SOURCES,
        "the scanned Tier 1 source set is not the stated one"
    );
    assert_semantic_exclusion_is_not_vacuous();

    let offenders: Vec<Box<str>> = sources
        .iter()
        .filter_map(|path| process_evidence(path))
        .collect();
    assert!(
        offenders.is_empty(),
        "Tier 1 sources name a process-capability API: {offenders:?}"
    );
}

/// Prove [`PARSE_ROUTE`] is the crate's only parse route: exactly one source
/// names a `syn` parse entry point, and it is that file.
///
/// The parse counter records inside that route, so a second route would parse
/// without being counted. Every parse-count claim above — and the stored-`FileIr`
/// reuse the supply chain attests — reads a reparse as reuse the moment a source
/// reaches `syn` another way. This is an AST scan, so the parse call in `lib.rs`'s
/// documentation example is text and not a route.
pub fn assert_parse_route_is_single() {
    let sources = crate_sources();
    let routes: Vec<PathBuf> = sources
        .iter()
        .filter(|path| PathIdents::scan(&parse_rust_file(path)).names_any(SYN_PARSE_ENTRIES))
        .cloned()
        .collect();
    assert_eq!(
        relative_names(&routes),
        [PARSE_ROUTE],
        "the crate's `syn` parse routes are not the stated one"
    );
}

/// Every file of every module in [`TIER1_MODULES`], less the semantic adapter
/// subtree, sorted.
fn scanned_sources() -> Vec<PathBuf> {
    let excluded = excluded_root();
    let mut files: Vec<PathBuf> = TIER1_MODULES
        .iter()
        .flat_map(|module| module_files(module).into_vec())
        .filter(|path| !path.starts_with(&excluded))
        .collect();
    files.sort();
    files
}

/// Each scanned path as `/`-separated text below `src/`, so the stated set
/// reads the way the module tree does.
fn relative_names(sources: &[PathBuf]) -> Vec<String> {
    let root = crate_path("src");
    sources
        .iter()
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or_else(|_| panic!("{} should sit under src/", path.display()))
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}
