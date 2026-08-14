//! How the derived answers spend: what divergence and layout may read, and what
//! the layout must prove before it describes anything.
//!
//! [`super::analysis_ownership_bounds`] owns the admission and shared-index
//! rules every earlier seam states. This owns the two consumers built on top of
//! them, so neither file has to be read to know what the other holds.

use super::analysis_ownership::ANALYSIS_SOURCES;
use super::analysis_ownership_bounds::{
    ALLOCATION_SPELLINGS, SELECTION_OWNER, analysis_sources_naming, assert_ordered,
};
use super::scan::{code_only, compact, function_body, position_of, source};

/// The one analysis module that derives declared-partition divergence.
const DIVERGENCE_OWNER: &str = "src/analysis/divergence.rs";

/// The one analysis module that projects layout metadata.
const LAYOUT_OWNER: &str = "src/analysis/layout.rs";

/// The layout functions that allocate the metadata the entry hands back.
///
/// The entry allocates nothing itself, so this is where the work bound's refusal
/// has to dominate: each of these is reached, and only then does anything exist.
const METADATA_ALLOCATORS: &[&str] = &["described", "connections"];

/// The stored indexes and shared results each derived consumer reads its
/// answers from.
const DERIVED_ACCESSORS: &[(&str, &[&str])] = &[
    (
        DIVERGENCE_OWNER,
        &[
            "analysis.indexes()",
            "indexes.outgoing(",
            "analysis.declared_partition()",
            "partition.owners()",
            "partition.owner(",
            "partition.roots()",
            "degree::degree(",
            "components::discover(",
        ],
    ),
    (
        LAYOUT_OWNER,
        &[
            "analysis.indexes()",
            "analysis.graph()",
            "analysis.declared_partition()",
            "indexes.parent(",
            "degree::degree(",
            "betweenness::betweenness(",
        ],
    ),
];

/// Every derived operation the analysis view publishes, beside every analysis
/// module that reaches its one implementation.
const DERIVED_CONSUMERS: &[(&str, &[&str])] = &[
    (
        "degree::degree",
        &[DIVERGENCE_OWNER, SELECTION_OWNER, LAYOUT_OWNER],
    ),
    ("components::discover", &[DIVERGENCE_OWNER, SELECTION_OWNER]),
    ("betweenness::betweenness", &[SELECTION_OWNER, LAYOUT_OWNER]),
];

/// Divergence and layout derive nothing a shared index or a shared result
/// already holds, and the layout bounds itself through the one Brandes owner
/// before it describes anything.
pub fn assert_derived_consumers_reuse_analysis_results() {
    for path in [DIVERGENCE_OWNER, LAYOUT_OWNER] {
        let code = compact(source(path));
        for spelling in [".edges()", ".allows(", "GraphEdgeSelection"] {
            assert!(
                !code.contains(spelling),
                "{path} must read the shared indexes rather than the graph or \
                 the selection: {spelling}"
            );
        }
    }
    for (path, accessors) in DERIVED_ACCESSORS {
        let code = compact(source(path));
        for accessor in *accessors {
            assert!(
                code.contains(accessor),
                "{path} must reach its inputs through {accessor}"
            );
        }
    }
    for (operation, consumers) in DERIVED_CONSUMERS {
        assert_eq!(
            analysis_sources_naming(operation),
            ordered_sources(consumers),
            "{operation} is implemented once and reached by exactly these \
             consumers"
        );
    }
    assert_layout_bounds_itself_before_describing();
}

/// The named sources, in [`ANALYSIS_SOURCES`] order.
fn ordered_sources(paths: &[&str]) -> Vec<&'static str> {
    ANALYSIS_SOURCES
        .iter()
        .copied()
        .filter(|path| paths.contains(path))
        .collect()
}

/// The layout reaches the bounded pass, and propagates its refusal, before any
/// metadata exists.
fn assert_layout_bounds_itself_before_describing() {
    let body = function_body(LAYOUT_OWNER, "layout_assist");
    assert_ordered(
        &body,
        &[
            "betweenness :: betweenness",
            "?",
            "degree :: degree",
            "LayoutAssistMetadata",
        ],
        "layout_assist",
    );
    assert_metadata_is_allocated_after_the_refusal(&body);
    assert!(
        !code_only(source(LAYOUT_OWNER)).contains("GraphAnalysisError::"),
        "the layout states no refusal of its own: both betweenness refusals \
         travel unchanged through its own Result"
    );
}

/// The layout entry allocates through the functions it calls, each of them does
/// allocate, and it reaches none of them until the work bound has refused.
fn assert_metadata_is_allocated_after_the_refusal(body: &str) {
    let inline = allocating_spellings(body);
    assert!(
        inline.is_empty(),
        "layout_assist allocates through the functions it calls rather than in \
         its own body: {inline:?}"
    );
    let refused = position_of(body, "?", "layout_assist");
    for allocator in METADATA_ALLOCATORS {
        let allocating = allocating_spellings(&function_body(LAYOUT_OWNER, allocator));
        assert!(
            !allocating.is_empty(),
            "{allocator} is where the layout's metadata is allocated"
        );
        assert!(
            position_of(body, &format!("{allocator} ("), "layout_assist") > refused,
            "layout_assist reaches {allocator}, which allocates {allocating:?}, \
             only after the work bound refuses"
        );
    }
}

/// Every allocating spelling one body names.
fn allocating_spellings(body: &str) -> Vec<&'static str> {
    ALLOCATION_SPELLINGS
        .iter()
        .copied()
        .filter(|spelling| body.contains(spelling))
        .collect()
}
