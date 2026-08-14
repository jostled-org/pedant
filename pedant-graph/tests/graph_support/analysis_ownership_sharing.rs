//! One selection applied once, and every consumer reading the indexes it
//! produced.
//!
//! The selection is stated by one module and applied by one module, so no
//! metric, component, traversal, or partition consumer may reach the raw edge
//! slice, reconstruct a selection, or rebuild what a selection already
//! produced. Each derived algorithm has exactly one implementation owner, and
//! the analysis view reaches it by delegation.

use super::analysis_ownership::{
    BETWEENNESS_OWNER, COMPONENT_OWNER, DEGREE_OWNER, PARTITION_OWNER, SELECTION_DECLARER,
    SELECTION_OWNER,
};
use super::analysis_ownership_bounds::{
    analysis_sources_naming, assert_reaches, assert_reads_indexes_not_graph,
};
use super::scan::{code_only, compact, method_body, source};

/// The modules that consume the shared indexes without rebuilding them.
const INDEX_CONSUMERS: &[&str] = &[BETWEENNESS_OWNER, COMPONENT_OWNER, DEGREE_OWNER];

/// The stored accessors a metric or component consumer must reach the selected
/// topology through.
const SHARED_ACCESSORS: &[(&str, &[&str])] = &[
    (
        BETWEENNESS_OWNER,
        &[
            "analysis.indexes()",
            "indexes.outgoing(",
            "indexes.node_count()",
            "indexes.selected_edges()",
        ],
    ),
    (
        COMPONENT_OWNER,
        &[
            "analysis.indexes()",
            "indexes.outgoing(",
            "indexes.incoming(",
            "indexes.node_count()",
        ],
    ),
    (
        DEGREE_OWNER,
        &[
            "analysis.indexes()",
            "indexes.outgoing(",
            "indexes.incoming(",
            "indexes.node_count()",
        ],
    ),
];

/// The stored accessors the walk and the partition derivation read their
/// topology through.
const WALK_ACCESSORS: &[(&str, &[&str])] = &[
    (
        "src/analysis/traversal.rs",
        &[
            "analysis.indexes()",
            "indexes.outgoing(",
            "indexes.incoming(",
            "indexes.parent(",
            "indexes.holds(",
            "indexes.node_count()",
        ],
    ),
    (PARTITION_OWNER, &["indexes.parent("]),
];

/// Every derived operation the analysis view publishes, beside the one module
/// that implements it.
const ALGORITHM_OWNERS: &[(&str, &str)] = &[
    ("degree::degree", DEGREE_OWNER),
    ("betweenness::betweenness", BETWEENNESS_OWNER),
    ("components::discover", COMPONENT_OWNER),
    ("components::condense", COMPONENT_OWNER),
];

/// One selection is applied once, and every consumer reads the indexes it
/// produced rather than the graph it was applied to.
pub fn assert_traversal_consumes_shared_indexes() {
    for spelling in [".edges()", ".allows("] {
        let sites: Vec<&str> = analysis_sources_naming(spelling);
        assert_eq!(
            sites,
            [SELECTION_OWNER],
            "{spelling} belongs to the one module that indexes the selection"
        );
    }
    assert_eq!(
        compact(source(SELECTION_OWNER)).matches(".edges()").count(),
        1,
        "the raw edge slice is read exactly once"
    );
    assert_eq!(
        compact(source(SELECTION_OWNER)).matches(".allows(").count(),
        1,
        "the selection is applied exactly once"
    );
    for constructor in [
        "GraphEdgeSelection::new",
        "GraphEdgeSelection::all",
        "GraphEdgeSelection::code_relations",
    ] {
        assert!(
            analysis_sources_naming(constructor).is_empty(),
            "no analysis module may reconstruct a selection: {constructor}"
        );
    }
    assert_eq!(
        analysis_sources_naming("GraphEdgeSelection"),
        [SELECTION_OWNER, "src/analysis/mod.rs", SELECTION_DECLARER],
        "a selection is stated by one module, applied by one module, and \
         published by the family root"
    );
    let declarer = code_only(source(SELECTION_DECLARER));
    for constructor in [
        "pub fn new(kinds",
        "pub fn all()",
        "pub fn code_relations()",
        "pub fn allows(",
    ] {
        assert_eq!(
            declarer.matches(constructor).count(),
            1,
            "the selection is stated exactly once, by {SELECTION_DECLARER}: {constructor}"
        );
    }

    assert_consumers_read_stored_indexes();
    assert_partition_is_derived_once();
}

/// Every traversal and partition consumer reaches the stored accessors.
fn assert_consumers_read_stored_indexes() {
    assert_reaches(WALK_ACCESSORS);
}

/// The declared partition is derived once, inside analysis construction.
fn assert_partition_is_derived_once() {
    let sites: Vec<&str> = analysis_sources_naming("partition::derive");
    assert_eq!(
        sites,
        [SELECTION_OWNER],
        "the partition is derived where the analysis is built"
    );
    assert_eq!(
        compact(source(SELECTION_OWNER))
            .matches("partition::derive")
            .count(),
        1,
        "the partition is derived exactly once"
    );
    assert!(
        method_body(SELECTION_OWNER, "from_admitted").contains("partition :: derive"),
        "the one derivation runs during successful construction"
    );
}

/// Every metric and component consumer reads the indexes one selection
/// produced, and each derived algorithm has exactly one implementation owner.
pub fn assert_metrics_and_components_consume_shared_indexes() {
    assert_reads_indexes_not_graph(INDEX_CONSUMERS);
    assert_reaches(SHARED_ACCESSORS);
    assert_algorithms_have_one_owner();
}

/// Each derived algorithm is implemented once and reached by delegation.
fn assert_algorithms_have_one_owner() {
    for (operation, owner) in ALGORITHM_OWNERS {
        let called = operation
            .rsplit("::")
            .next()
            .unwrap_or_else(|| panic!("{operation} names a function"));
        assert_eq!(
            code_only(source(owner))
                .matches(&format!("fn {called}("))
                .count(),
            1,
            "{owner} declares {called} exactly once"
        );
        assert!(
            compact(source(SELECTION_OWNER)).contains(operation),
            "the analysis view must reach {operation}"
        );
    }
    assert_eq!(
        compact(source(COMPONENT_OWNER))
            .matches("discover(")
            .count(),
        2,
        "the one component algorithm is declared once and reached once by the \
         condensation that contracts it"
    );
    let pass = compact(source(BETWEENNESS_OWNER));
    assert_eq!(
        pass.matches("fnempty(").count(),
        1,
        "the one bounded Brandes pass is declared exactly once"
    );
    assert_eq!(
        pass.matches("Brandes::empty(").count(),
        1,
        "the one bounded Brandes pass is started from exactly one place"
    );
}
