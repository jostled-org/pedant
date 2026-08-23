//! Every source these cases read, written down beside its compile-time text.
//!
//! The structural predicates compare a written-down model with the tree, so the
//! discovered set is checked against a fixed inventory before anything is
//! scanned: a discovered-only set would agree with whatever the crate happens
//! to contain and could never reject a module that appeared.
//!
//! `include_str!` reads at compile time, so no case here performs a runtime
//! file read or gives the graph crate a feature.

/// Every production source of this crate, repository-relative to its manifest.
///
/// Written down, never discovered. `graph_projection_uses_only_supplied_resolution_facts`
/// compares it with the tree and fails on a missing or an extra entry.
pub const PRODUCTION_SOURCES: &[&str] = &[
    "src/analysis/betweenness.rs",
    "src/analysis/components.rs",
    "src/analysis/degree.rs",
    "src/analysis/divergence.rs",
    "src/analysis/error.rs",
    "src/analysis/index.rs",
    "src/analysis/layout.rs",
    "src/analysis/limits.rs",
    "src/analysis/mod.rs",
    "src/analysis/partition.rs",
    "src/analysis/selection.rs",
    "src/analysis/traversal.rs",
    "src/cache/analysis.rs",
    "src/cache/graph.rs",
    "src/cache/limits.rs",
    "src/cache/mod.rs",
    "src/cache/product.rs",
    "src/cache/state.rs",
    "src/cache/stats.rs",
    "src/cache/storage.rs",
    "src/containment.rs",
    "src/edge.rs",
    "src/error.rs",
    "src/go/entry.rs",
    "src/go/mapping.rs",
    "src/go/mod.rs",
    "src/go/placement.rs",
    "src/go/projection.rs",
    "src/go/validation.rs",
    "src/graph.rs",
    "src/id.rs",
    "src/lib.rs",
    "src/limits.rs",
    "src/node.rs",
    "src/projection/assembly.rs",
    "src/projection/draft.rs",
    "src/projection/forest.rs",
    "src/projection/mod.rs",
    "src/projection/placement.rs",
    "src/projection/state.rs",
    "src/projection/validation.rs",
    "src/reference.rs",
    "src/rust/cache.rs",
    "src/rust/claim.rs",
    "src/rust/entry.rs",
    "src/rust/mapping.rs",
    "src/rust/mod.rs",
    "src/rust/projection.rs",
    "src/rust/reuse.rs",
    "src/rust/source.rs",
    "src/rust/validation.rs",
];

/// Every cache module, and the source-relative path it is scanned at.
pub const CACHE_SOURCES: &[&str] = &[
    "src/cache/analysis.rs",
    "src/cache/graph.rs",
    "src/cache/limits.rs",
    "src/cache/mod.rs",
    "src/cache/product.rs",
    "src/cache/state.rs",
    "src/cache/stats.rs",
    "src/cache/storage.rs",
];

/// Every module the language-neutral projection family states.
///
/// The drafts a language adapter fills in, where each stated record sits, the
/// tables one assembly resolves its joins through, the whole-relation
/// containment rule, every neutral refusal, and the one checked assembler.
pub const PROJECTION_SOURCES: &[&str] = &[
    "src/projection/assembly.rs",
    "src/projection/draft.rs",
    "src/projection/forest.rs",
    "src/projection/mod.rs",
    "src/projection/placement.rs",
    "src/projection/state.rs",
    "src/projection/validation.rs",
];

/// Every module the Go adapter states.
///
/// Compiled only under this crate's `go` feature, and modelled unconditionally:
/// the inventory is what proves a module appeared, and a model that vanished
/// with the feature would prove nothing about the build that has it.
pub const GO_SOURCES: &[&str] = &[
    "src/go/entry.rs",
    "src/go/mapping.rs",
    "src/go/mod.rs",
    "src/go/placement.rs",
    "src/go/projection.rs",
    "src/go/validation.rs",
];

/// Every module the Rust adapter states, after the planner and assembler split.
pub const RUST_SOURCES: &[&str] = &[
    "src/rust/cache.rs",
    "src/rust/claim.rs",
    "src/rust/entry.rs",
    "src/rust/mapping.rs",
    "src/rust/mod.rs",
    "src/rust/projection.rs",
    "src/rust/reuse.rs",
    "src/rust/source.rs",
    "src/rust/validation.rs",
];

/// One production source and its exact text.
pub struct Source {
    /// The manifest-relative path.
    pub path: &'static str,
    /// The exact file contents.
    pub text: &'static str,
}

/// Every production source with its compile-time contents.
///
/// The array and [`PRODUCTION_SOURCES`] are compared against each other and
/// against the tree, so a file that stopped being scanned fails rather than
/// silently narrows the search set.
pub const SOURCES: &[Source] = &[
    Source {
        path: "src/analysis/betweenness.rs",
        text: include_str!("../../src/analysis/betweenness.rs"),
    },
    Source {
        path: "src/analysis/components.rs",
        text: include_str!("../../src/analysis/components.rs"),
    },
    Source {
        path: "src/analysis/degree.rs",
        text: include_str!("../../src/analysis/degree.rs"),
    },
    Source {
        path: "src/analysis/divergence.rs",
        text: include_str!("../../src/analysis/divergence.rs"),
    },
    Source {
        path: "src/analysis/error.rs",
        text: include_str!("../../src/analysis/error.rs"),
    },
    Source {
        path: "src/analysis/index.rs",
        text: include_str!("../../src/analysis/index.rs"),
    },
    Source {
        path: "src/analysis/layout.rs",
        text: include_str!("../../src/analysis/layout.rs"),
    },
    Source {
        path: "src/analysis/limits.rs",
        text: include_str!("../../src/analysis/limits.rs"),
    },
    Source {
        path: "src/analysis/mod.rs",
        text: include_str!("../../src/analysis/mod.rs"),
    },
    Source {
        path: "src/analysis/partition.rs",
        text: include_str!("../../src/analysis/partition.rs"),
    },
    Source {
        path: "src/analysis/selection.rs",
        text: include_str!("../../src/analysis/selection.rs"),
    },
    Source {
        path: "src/analysis/traversal.rs",
        text: include_str!("../../src/analysis/traversal.rs"),
    },
    Source {
        path: "src/cache/analysis.rs",
        text: include_str!("../../src/cache/analysis.rs"),
    },
    Source {
        path: "src/cache/graph.rs",
        text: include_str!("../../src/cache/graph.rs"),
    },
    Source {
        path: "src/cache/limits.rs",
        text: include_str!("../../src/cache/limits.rs"),
    },
    Source {
        path: "src/cache/mod.rs",
        text: include_str!("../../src/cache/mod.rs"),
    },
    Source {
        path: "src/cache/product.rs",
        text: include_str!("../../src/cache/product.rs"),
    },
    Source {
        path: "src/cache/state.rs",
        text: include_str!("../../src/cache/state.rs"),
    },
    Source {
        path: "src/cache/stats.rs",
        text: include_str!("../../src/cache/stats.rs"),
    },
    Source {
        path: "src/cache/storage.rs",
        text: include_str!("../../src/cache/storage.rs"),
    },
    Source {
        path: "src/containment.rs",
        text: include_str!("../../src/containment.rs"),
    },
    Source {
        path: "src/edge.rs",
        text: include_str!("../../src/edge.rs"),
    },
    Source {
        path: "src/error.rs",
        text: include_str!("../../src/error.rs"),
    },
    Source {
        path: "src/go/entry.rs",
        text: include_str!("../../src/go/entry.rs"),
    },
    Source {
        path: "src/go/mapping.rs",
        text: include_str!("../../src/go/mapping.rs"),
    },
    Source {
        path: "src/go/mod.rs",
        text: include_str!("../../src/go/mod.rs"),
    },
    Source {
        path: "src/go/placement.rs",
        text: include_str!("../../src/go/placement.rs"),
    },
    Source {
        path: "src/go/projection.rs",
        text: include_str!("../../src/go/projection.rs"),
    },
    Source {
        path: "src/go/validation.rs",
        text: include_str!("../../src/go/validation.rs"),
    },
    Source {
        path: "src/graph.rs",
        text: include_str!("../../src/graph.rs"),
    },
    Source {
        path: "src/id.rs",
        text: include_str!("../../src/id.rs"),
    },
    Source {
        path: "src/lib.rs",
        text: include_str!("../../src/lib.rs"),
    },
    Source {
        path: "src/limits.rs",
        text: include_str!("../../src/limits.rs"),
    },
    Source {
        path: "src/node.rs",
        text: include_str!("../../src/node.rs"),
    },
    Source {
        path: "src/projection/assembly.rs",
        text: include_str!("../../src/projection/assembly.rs"),
    },
    Source {
        path: "src/projection/draft.rs",
        text: include_str!("../../src/projection/draft.rs"),
    },
    Source {
        path: "src/projection/forest.rs",
        text: include_str!("../../src/projection/forest.rs"),
    },
    Source {
        path: "src/projection/mod.rs",
        text: include_str!("../../src/projection/mod.rs"),
    },
    Source {
        path: "src/projection/placement.rs",
        text: include_str!("../../src/projection/placement.rs"),
    },
    Source {
        path: "src/projection/state.rs",
        text: include_str!("../../src/projection/state.rs"),
    },
    Source {
        path: "src/projection/validation.rs",
        text: include_str!("../../src/projection/validation.rs"),
    },
    Source {
        path: "src/reference.rs",
        text: include_str!("../../src/reference.rs"),
    },
    Source {
        path: "src/rust/cache.rs",
        text: include_str!("../../src/rust/cache.rs"),
    },
    Source {
        path: "src/rust/claim.rs",
        text: include_str!("../../src/rust/claim.rs"),
    },
    Source {
        path: "src/rust/entry.rs",
        text: include_str!("../../src/rust/entry.rs"),
    },
    Source {
        path: "src/rust/mapping.rs",
        text: include_str!("../../src/rust/mapping.rs"),
    },
    Source {
        path: "src/rust/mod.rs",
        text: include_str!("../../src/rust/mod.rs"),
    },
    Source {
        path: "src/rust/projection.rs",
        text: include_str!("../../src/rust/projection.rs"),
    },
    Source {
        path: "src/rust/reuse.rs",
        text: include_str!("../../src/rust/reuse.rs"),
    },
    Source {
        path: "src/rust/source.rs",
        text: include_str!("../../src/rust/source.rs"),
    },
    Source {
        path: "src/rust/validation.rs",
        text: include_str!("../../src/rust/validation.rs"),
    },
];

/// The registered test root, read at compile time.
///
/// Every `#[test]` wrapper this crate registers is declared there, so the
/// structural cases can hold each production module to a predicate that names
/// it without reading a file at run time.
pub const TEST_ROOT: &str = include_str!("../graph.rs");

/// This crate's tracked manifest, read at compile time.
///
/// The dependency and feature boundary is a property of the published package,
/// so the case that holds it to a model reads the manifest itself rather than a
/// lifecycle file describing it.
pub const MANIFEST: &str = include_str!("../../Cargo.toml");

/// One support module beside its compile-time contents.
///
/// Written as a list of module names: the path a case reports and the text it
/// reads are one entry, so a module cannot be scanned under a name the tree does
/// not hold.
macro_rules! support_sources {
    ($($name:literal),* $(,)?) => {
        &[$(Source {
            path: concat!("tests/graph_support/", $name, ".rs"),
            text: include_str!(concat!($name, ".rs")),
        }),*]
    };
}

/// Every support module beneath the one registered root.
///
/// The root owns every libtest identity this crate registers; these declare
/// fixtures, cases, and scanners. The inventory is compared with the tree, so a
/// module that appeared without an entry fails rather than escaping the scan.
pub const TEST_SUPPORT_SOURCES: &[Source] = support_sources![
    "analysis_centrality",
    "analysis_components",
    "analysis_derived_bounds",
    "analysis_derived_determinism",
    "analysis_determinism",
    "analysis_divergence",
    "analysis_divergence_model",
    "analysis_fixture",
    "analysis_layout",
    "analysis_oracle",
    "analysis_ownership",
    "analysis_ownership_bounds",
    "analysis_ownership_model",
    "analysis_ownership_sharing",
    "analysis_partition",
    "analysis_perturbation",
    "analysis_selection",
    "analysis_source_boundary",
    "analysis_traversal",
    "cache_analysis",
    "cache_analysis_lifetime",
    "cache_analysis_reading",
    "cache_analysis_retention",
    "cache_analysis_sharing",
    "cache_counting",
    "cache_exact",
    "cache_fixture",
    "cache_ownership",
    "cache_ownership_path",
    "cache_ownership_state",
    "cache_projection",
    "cache_remapping",
    "cache_revision",
    "cache_rust_only",
    "cache_source_boundary",
    "call_graph",
    "contract",
    "corpus",
    "corpus_analysis",
    "corpus_generated",
    "corpus_revision",
    "defensive",
    "evidence",
    "fixture",
    "go_corpus",
    "go_defensive",
    "go_evidence",
    "go_fixture",
    "go_model",
    "go_ownership",
    "go_topology",
    "go_wire",
    "inventory",
    "isolation",
    "mod",
    "ownership",
    "ownership_model",
    "projection_exactness",
    "projection_ownership",
    "promotion",
    "render",
    "scan",
    "surface",
    "topology",
    "wire",
];
