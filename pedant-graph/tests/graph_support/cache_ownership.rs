//! What the cache boundary publishes, and what it may name.
//!
//! The module inventory, the exported vocabulary, every public signature, the
//! value semantics each published type carries, and the one inherent owner of
//! each of them are written down here and held against the tree. The
//! language-neutral family must name no resolution type at all.
//!
//! Every input is a compile-time source read through [`super::scan`], beside the
//! one directory listing that rejects a module which appeared without an entry.

use std::collections::BTreeSet;

use super::inventory::{CACHE_SOURCES, PRODUCTION_SOURCES, RUST_SOURCES, SOURCES};
use super::scan::{code_only, discovered_sources, naming, parsed, source};
use super::surface::{
    declared_items, declares_only, derived_paths, item_label, public_fields, public_signatures,
    public_use_leaves,
};

/// The exact vocabulary the language-neutral cache family publishes.
const CACHE_EXPORTS: &[&str] = &[
    "CachedCodeGraph",
    "CachedGraphAnalysis",
    "GraphCacheLimits",
    "GraphCacheStats",
];

/// The exact vocabulary the Rust adapter publishes.
const RUST_EXPORTS: &[&str] = &[
    "GraphCache",
    "build_rust_graph",
    "build_rust_graph_with_limits",
];

/// Every public function each cache-family module declares.
const CACHE_SIGNATURES: &[(&str, &[&str])] = &[
    (
        "src/cache/analysis.rs",
        &[
            "CachedGraphAnalysis::graph(&self) -> &CodeGraph",
            "CachedGraphAnalysis::selection(&self) -> GraphEdgeSelection",
            "CachedGraphAnalysis::limits(&self) -> GraphAnalysisLimits",
            "CachedGraphAnalysis::declared_partition(&self) -> &DeclaredModulePartition",
            "CachedGraphAnalysis::neighbors(&self, node: GraphNodeId, depth: u32, direction: \
             GraphDirection) -> Result<Arc<[GraphNeighbor]>, GraphAnalysisError>",
            "CachedGraphAnalysis::path(&self, source: GraphNodeId, target: GraphNodeId) -> \
             Result<Option<Arc<GraphPath>>, GraphAnalysisError>",
            "CachedGraphAnalysis::subgraph(&self, seed: GraphNodeId, depth: u32, direction: \
             GraphDirection) -> Result<Arc<GraphSubgraph>, GraphAnalysisError>",
            "CachedGraphAnalysis::degree_centrality(&self) -> Arc<[DegreeCentrality]>",
            "CachedGraphAnalysis::betweenness_centrality(&self) -> \
             Result<Arc<[BetweennessCentrality]>, GraphAnalysisError>",
            "CachedGraphAnalysis::strongly_connected_components(&self) -> Arc<GraphComponents>",
            "CachedGraphAnalysis::condensation(&self) -> Arc<CondensationGraph>",
            "CachedGraphAnalysis::divergence(&self) -> Arc<GraphDivergence>",
            "CachedGraphAnalysis::layout_assist(&self) -> Result<Arc<LayoutAssistMetadata>, \
             GraphAnalysisError>",
        ],
    ),
    (
        "src/cache/graph.rs",
        &[
            "CachedCodeGraph::graph(&self) -> &CodeGraph",
            "CachedCodeGraph::stats(&self) -> GraphCacheStats",
            "CachedCodeGraph::analyze(&self, selection: GraphEdgeSelection, limits: \
             GraphAnalysisLimits) -> Result<CachedGraphAnalysis, GraphAnalysisError>",
            "CachedCodeGraph::clear_analysis_cache(&self)",
        ],
    ),
    (
        "src/cache/limits.rs",
        &[
            "GraphCacheLimits::new(max_source_projections: u32, max_exact_graphs: u32, \
             max_selected_indexes_per_graph: u32, max_derived_products_per_graph: u32) -> Self",
            "GraphCacheLimits::max_source_projections(self) -> u32",
            "GraphCacheLimits::max_exact_graphs(self) -> u32",
            "GraphCacheLimits::max_selected_indexes_per_graph(self) -> u32",
            "GraphCacheLimits::max_derived_products_per_graph(self) -> u32",
        ],
    ),
    ("src/cache/mod.rs", &[]),
    ("src/cache/product.rs", &[]),
    ("src/cache/state.rs", &[]),
    (
        "src/cache/stats.rs",
        &[
            "GraphCacheStats::source_projection_hits(self) -> u64",
            "GraphCacheStats::source_projection_misses(self) -> u64",
            "GraphCacheStats::source_projection_evictions(self) -> u64",
            "GraphCacheStats::exact_graph_hits(self) -> u64",
            "GraphCacheStats::exact_graph_misses(self) -> u64",
            "GraphCacheStats::exact_graph_evictions(self) -> u64",
            "GraphCacheStats::selected_index_hits(self) -> u64",
            "GraphCacheStats::selected_index_misses(self) -> u64",
            "GraphCacheStats::selected_index_evictions(self) -> u64",
            "GraphCacheStats::derived_product_hits(self) -> u64",
            "GraphCacheStats::derived_product_misses(self) -> u64",
            "GraphCacheStats::derived_product_evictions(self) -> u64",
        ],
    ),
    ("src/cache/storage.rs", &[]),
];

/// The one public function surface the cache entry point declares.
const CACHE_ENTRY_SIGNATURES: &[&str] = &[
    "GraphCache::new(limits: GraphCacheLimits) -> Self",
    "GraphCache::build_rust_graph(&mut self, snapshot: &RustResolutionSnapshot, resolution: \
     &RustTargetResolution, limits: GraphLimits) -> Result<CachedCodeGraph, GraphBuildError>",
    "GraphCache::stats(&self) -> GraphCacheStats",
    "GraphCache::clear(&mut self)",
];

/// Every published cache type beside the derives it must and must not carry.
///
/// Written down rather than read back: a `Default` on the ceilings or a `Copy`
/// on a handle that owns shared state has to fail here.
const CACHE_DERIVES: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "src/cache/limits.rs",
        "GraphCacheLimits",
        &["Clone", "Copy", "Debug", "PartialEq", "Eq"],
        &["Default", "Serialize", "Deserialize"],
    ),
    (
        "src/cache/stats.rs",
        "GraphCacheStats",
        &["Clone", "Copy", "Debug", "PartialEq", "Eq"],
        &["Default", "Serialize", "Deserialize"],
    ),
    (
        "src/cache/analysis.rs",
        "CachedGraphAnalysis",
        &["Clone"],
        &["Copy", "Default", "Serialize", "Deserialize"],
    ),
    (
        "src/cache/graph.rs",
        "CachedCodeGraph",
        &["Clone"],
        &["Copy", "Default", "Serialize", "Deserialize"],
    ),
    (
        "src/rust/cache.rs",
        "GraphCache",
        &[],
        &["Clone", "Copy", "Default", "Serialize", "Deserialize"],
    ),
];

/// Every type the cache family owns exactly one inherent implementation of.
const SOLE_IMPL_OWNERS: &[(&str, &str)] = &[
    ("CachedCodeGraph", "src/cache/graph.rs"),
    ("CachedGraphAnalysis", "src/cache/analysis.rs"),
    ("GraphCache", "src/rust/cache.rs"),
    ("GraphCacheLimits", "src/cache/limits.rs"),
    ("GraphCacheStats", "src/cache/stats.rs"),
];

/// The spellings a language-neutral cache module may never name.
///
/// The cache holds already-built values. The moment it names the resolution
/// vocabulary, the language-neutral boundary has absorbed a Rust type.
const CORE_SPELLINGS: &[&str] = &[
    "pedant_core",
    "RustResolutionSnapshot",
    "RustTargetResolution",
    "RustUnitBinding",
    "RustSnapshotFingerprint",
    "ResolutionReport",
];

/// The cache family publishes exactly the stated modules, types, signatures,
/// derives, and owners, and names no resolution type.
pub fn assert_cache_public_boundary_is_exact() {
    assert_cache_modules_are_discovered();
    assert_module_root_only_declares();
    assert_exports_are_exact();
    assert_signatures_are_exact();
    assert_derives_are_exact();
    assert_records_are_closed();
    assert_one_inherent_owner_per_type();
    assert_cache_names_no_resolution_type();
}

/// The module inventory equals what the tree holds beneath `src/cache` and
/// `src/rust`.
pub fn assert_cache_modules_are_discovered() {
    for (prefix, modelled) in [("src/cache/", CACHE_SOURCES), ("src/rust/", RUST_SOURCES)] {
        let discovered: BTreeSet<String> = discovered_sources()
            .into_iter()
            .filter(|path| path.starts_with(prefix))
            .collect();
        assert_eq!(
            discovered,
            modelled
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<BTreeSet<String>>(),
            "every {prefix} module is modelled and every modelled module exists"
        );
        let scanned: Vec<&str> = PRODUCTION_SOURCES
            .iter()
            .copied()
            .filter(|path| path.starts_with(prefix))
            .collect();
        assert_eq!(
            scanned, *modelled,
            "every {prefix} module carries its compile-time text"
        );
    }
}

/// Both family roots declare modules and re-export names, and define nothing.
fn assert_module_root_only_declares() {
    for (path, modelled, prefix) in [
        ("src/cache/mod.rs", CACHE_SOURCES, "src/cache/"),
        ("src/rust/mod.rs", RUST_SOURCES, "src/rust/"),
    ] {
        let root = parsed(path);
        let defined: Vec<String> = root
            .items
            .iter()
            .filter(|item| !declares_only(item))
            .map(item_label)
            .collect();
        assert!(
            defined.is_empty(),
            "{path} must declare and re-export only: {defined:?}"
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
            modelled
                .iter()
                .filter(|entry| !entry.ends_with("mod.rs"))
                .map(|entry| entry
                    .trim_start_matches(prefix)
                    .trim_end_matches(".rs")
                    .to_owned())
                .collect::<BTreeSet<String>>(),
            "{path} declares exactly its own modules"
        );
    }
}

/// Each family and the crate root publish one vocabulary.
fn assert_exports_are_exact() {
    for (root, modelled, family) in [
        ("src/cache/mod.rs", CACHE_EXPORTS, "cache"),
        ("src/rust/mod.rs", RUST_EXPORTS, "rust"),
    ] {
        let published: BTreeSet<String> = modelled.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(
            public_use_leaves(root, None),
            published,
            "{root} re-exports exactly its public vocabulary"
        );
        assert_eq!(
            public_use_leaves("src/lib.rs", Some(family)),
            published,
            "the crate root re-exports exactly what the {family} family publishes"
        );
    }
}

/// Every cache module declares exactly the public functions modelled for it.
fn assert_signatures_are_exact() {
    assert_eq!(
        CACHE_SIGNATURES
            .iter()
            .map(|(path, _)| *path)
            .collect::<Vec<&str>>(),
        CACHE_SOURCES,
        "every cache module states its public function surface"
    );
    for (path, expected) in CACHE_SIGNATURES {
        assert_eq!(
            public_signatures(path),
            *expected,
            "{path} declares exactly its modelled public functions"
        );
    }
    assert_eq!(
        public_signatures("src/rust/cache.rs"),
        CACHE_ENTRY_SIGNATURES,
        "the cache entry point declares exactly its modelled public functions"
    );
}

/// Every published cache type carries exactly the value semantics modelled.
fn assert_derives_are_exact() {
    for (path, name, required, forbidden) in CACHE_DERIVES {
        let file = parsed(path);
        let declared = declared_items(&file.items)
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Struct(found) if found.ident == *name => Some(found),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{path} declares no {name} struct"));
        let derived = derived_paths(&declared.attrs);
        for trait_name in *required {
            assert!(
                derived.contains(*trait_name),
                "{name} must derive {trait_name}, deriving {derived:?}"
            );
        }
        for trait_name in *forbidden {
            assert!(
                !derived.contains(*trait_name),
                "{name} must not derive {trait_name}, deriving {derived:?}"
            );
            assert!(
                !code_only(source(path)).contains(&format!("impl {trait_name} for {name}")),
                "{path} must not implement {trait_name} for {name}"
            );
        }
    }
}

/// No cache record exposes a field, and none states a serialization contract.
fn assert_records_are_closed() {
    for path in CACHE_SOURCES.iter().chain(["src/rust/cache.rs"].iter()) {
        let file = parsed(path);
        let offenders = public_fields(&declared_items(&file.items), path);
        assert!(
            offenders.is_empty(),
            "cache records keep private fields: {offenders:?}"
        );
        let code = code_only(source(path));
        for forbidden in ["serde", "Serialize", "Deserialize"] {
            assert!(
                !code.contains(forbidden),
                "{path} must state no {forbidden} contract"
            );
        }
    }
}

/// Every published cache type has exactly one inherent implementation, in the
/// module the model names.
fn assert_one_inherent_owner_per_type() {
    for (name, owner) in SOLE_IMPL_OWNERS {
        let sites: Vec<&str> = SOURCES
            .iter()
            .filter(|entry| declares_inherent_impl(entry.path, name))
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            sites,
            vec![*owner],
            "{name} has exactly one inherent implementation owner"
        );
    }
}

/// Whether one source declares an inherent implementation of one type.
fn declares_inherent_impl(path: &str, name: &str) -> bool {
    let file = parsed(path);
    declared_items(&file.items)
        .into_iter()
        .any(|item| match item {
            syn::Item::Impl(block) => {
                block.trait_.is_none() && super::scan::token_text(&block.self_ty) == *name
            }
            _ => false,
        })
}

/// The language-neutral cache module names no resolution type at all.
fn assert_cache_names_no_resolution_type() {
    let offenders = naming(CACHE_SOURCES, CORE_SPELLINGS, "the resolution type");
    assert!(
        offenders.is_empty(),
        "the language-neutral cache module names a resolution type: {offenders:?}"
    );
}
