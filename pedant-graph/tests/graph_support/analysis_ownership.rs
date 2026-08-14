//! Structural ownership of the analysis family's boundary: which modules it
//! holds, which case owns each of them, and exactly what it publishes.
//!
//! The predecessor ownership cases in [`super::ownership`] own the projection's
//! structure, and [`super::analysis_ownership_bounds`] owns how the derived
//! boundary spends. These own what it states, so no one file has to be read to
//! know what the others hold.

use std::collections::BTreeSet;

use pedant_graph::CodeGraph;

use super::analysis_ownership_model::{
    ANALYSIS_EXPORTS, ANALYSIS_SIGNATURES, LAYOUT_FIELDS, RENDERER_STATE, WIRE_KEYS,
};
use super::inventory::{PRODUCTION_SOURCES, TEST_ROOT};
use super::scan::{code_only, parsed, source};
use super::surface::{
    declared_fields, declared_items, declares_only, item_label, public_constructors, public_fields,
    public_signatures, public_use_leaves,
};

/// Every analysis module, and the source-relative path it is scanned at.
pub const ANALYSIS_SOURCES: &[&str] = &[
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
];

/// The one analysis module allowed to read the raw edge slice and to apply the
/// selection to it.
pub const SELECTION_OWNER: &str = "src/analysis/index.rs";

/// The one analysis module allowed to state a selection.
pub const SELECTION_DECLARER: &str = "src/analysis/selection.rs";

/// The one analysis module that derives the declared partition.
pub const PARTITION_OWNER: &str = "src/analysis/partition.rs";

/// The one analysis module that measures degree.
pub const DEGREE_OWNER: &str = "src/analysis/degree.rs";

/// The one analysis module that measures betweenness.
pub const BETWEENNESS_OWNER: &str = "src/analysis/betweenness.rs";

/// The one analysis module that discovers components and condenses them.
pub const COMPONENT_OWNER: &str = "src/analysis/components.rs";

/// Every analysis module beside the registered predicate that owns it.
const ANALYSIS_OWNERS: &[(&str, &str)] = &[
    (
        "src/analysis/betweenness.rs",
        "graph_degree_and_betweenness_match_directed_oracles",
    ),
    (
        "src/analysis/components.rs",
        "graph_components_and_condensation_are_exact",
    ),
    (
        "src/analysis/degree.rs",
        "graph_degree_and_betweenness_match_directed_oracles",
    ),
    (
        "src/analysis/divergence.rs",
        "graph_divergence_matches_declared_partition_arithmetic",
    ),
    (
        "src/analysis/error.rs",
        "graph_analysis_limits_refuse_before_work",
    ),
    (
        "src/analysis/index.rs",
        "graph_analysis_selection_is_explicit_and_shared",
    ),
    (
        "src/analysis/layout.rs",
        "graph_layout_assist_is_complete_and_coordinate_free",
    ),
    (
        "src/analysis/limits.rs",
        "graph_analysis_limits_refuse_before_work",
    ),
    (
        "src/analysis/mod.rs",
        "graph_analysis_public_boundary_is_exact",
    ),
    (
        "src/analysis/partition.rs",
        "graph_declared_partition_follows_nearest_container",
    ),
    (
        "src/analysis/selection.rs",
        "graph_analysis_selection_is_explicit_and_shared",
    ),
    (
        "src/analysis/traversal.rs",
        "graph_neighbors_are_bounded_directed_and_ordered",
    ),
];

/// The analysis family publishes exactly the stated modules, exports, and
/// signatures, and nothing that would let a result be stated or hydrated.
pub fn assert_analysis_public_boundary_is_exact() {
    let modelled: Vec<&str> = PRODUCTION_SOURCES
        .iter()
        .copied()
        .filter(|path| path.starts_with("src/analysis/"))
        .collect();
    assert_eq!(
        modelled, ANALYSIS_SOURCES,
        "the analysis module inventory is exact"
    );
    assert_eq!(
        ANALYSIS_OWNERS
            .iter()
            .map(|(path, _)| *path)
            .collect::<Vec<&str>>(),
        ANALYSIS_SOURCES,
        "every analysis module states the predicate that owns it"
    );
    for (path, predicate) in ANALYSIS_OWNERS {
        assert!(
            TEST_ROOT.contains(&format!("#[test]\nfn {predicate}()")),
            "{path} names {predicate}, which the test root does not register"
        );
    }

    assert_module_root_only_declares();
    assert_exports_are_exact();
    assert_signatures_are_exact();
    assert_results_are_closed();
    assert_layout_states_no_renderer_state();
    assert_graph_wire_is_untouched();
}

/// The layout projection states exactly the metadata modelled for it, and no
/// analysis module names renderer state at all.
fn assert_layout_states_no_renderer_state() {
    let file = parsed("src/analysis/layout.rs");
    let items = declared_items(&file.items);
    for (record, fields) in LAYOUT_FIELDS {
        assert_eq!(
            declared_fields(&items, record),
            *fields,
            "{record} states exactly the metadata a renderer is handed"
        );
    }
    for path in ANALYSIS_SOURCES {
        let code = code_only(source(path)).to_lowercase();
        let stated: Vec<&str> = RENDERER_STATE
            .iter()
            .copied()
            .filter(|spelling| code.contains(spelling))
            .collect();
        assert!(
            stated.is_empty(),
            "{path} must state no coordinate or renderer state: {stated:?}"
        );
    }
}

/// Derived analysis leaves the published version-1 object exactly as it found
/// it.
fn assert_graph_wire_is_untouched() {
    assert_eq!(
        CodeGraph::SCHEMA_VERSION,
        1,
        "derived analysis does not advance the published schema"
    );
    let graph = parsed("src/graph.rs");
    let declared: Vec<String> = declared_items(&graph.items)
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Struct(record) if record.ident == "CodeGraph" => Some(record),
            _ => None,
        })
        .flat_map(|record| record.fields.iter())
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect();
    assert_eq!(
        declared, WIRE_KEYS,
        "the serialized graph object states exactly its six version-1 keys"
    );
    for path in ANALYSIS_SOURCES {
        assert!(
            !code_only(source(path)).contains("serde"),
            "{path} must state no serialization contract of its own"
        );
    }
}

/// The analysis module root declares and re-exports, and defines nothing.
///
/// Read as parsed items rather than as forbidden spellings. A list of keywords
/// has to name every way Rust states a definition, and whatever it misses — a
/// trait, a static, a union, a `macro_rules!` — passes. Two item kinds are
/// admitted here, so everything else fails whether or not this case has heard
/// of it. A module with a body is a definition site too, so only the file
/// declarations are admitted.
fn assert_module_root_only_declares() {
    let root = parsed("src/analysis/mod.rs");
    let defined: Vec<String> = root
        .items
        .iter()
        .filter(|item| !declares_only(item))
        .map(item_label)
        .collect();
    assert!(
        defined.is_empty(),
        "the analysis module root must not define anything: {defined:?}"
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
        ANALYSIS_SOURCES
            .iter()
            .filter(|path| !path.ends_with("mod.rs"))
            .map(|path| path
                .trim_start_matches("src/analysis/")
                .trim_end_matches(".rs")
                .to_owned())
            .collect::<BTreeSet<String>>(),
        "the module root declares exactly the analysis modules"
    );
}

/// The family and the crate root publish exactly one vocabulary.
fn assert_exports_are_exact() {
    let published: BTreeSet<String> = ANALYSIS_EXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(
        public_use_leaves("src/analysis/mod.rs", None),
        published,
        "the analysis family re-exports exactly its public vocabulary"
    );
    assert_eq!(
        public_use_leaves("src/lib.rs", Some("analysis")),
        published,
        "the crate root re-exports exactly what the family publishes"
    );
}

/// Every analysis module declares exactly the public functions modelled for
/// it.
fn assert_signatures_are_exact() {
    assert_eq!(
        ANALYSIS_SIGNATURES
            .iter()
            .map(|(path, _)| *path)
            .collect::<Vec<&str>>(),
        ANALYSIS_SOURCES,
        "every analysis module states its public function surface"
    );
    for (path, expected) in ANALYSIS_SIGNATURES {
        assert_eq!(
            public_signatures(path),
            *expected,
            "{path} declares exactly its modelled public functions"
        );
    }
}

/// No analysis result can be defaulted, hydrated, or serialized.
fn assert_results_are_closed() {
    for path in ANALYSIS_SOURCES {
        let code = code_only(source(path));
        for forbidden in ["Default", "Serialize", "Deserialize"] {
            assert!(
                !code.contains(forbidden),
                "{path} must state no {forbidden} contract"
            );
        }
        let file = parsed(path);
        let items = declared_items(&file.items);
        let offenders: Vec<String> = public_fields(&items, path)
            .into_iter()
            .chain(public_constructors(&items, path))
            .collect();
        assert!(
            offenders.is_empty(),
            "analysis results keep private fields and private constructors: {offenders:?}"
        );
    }
}
