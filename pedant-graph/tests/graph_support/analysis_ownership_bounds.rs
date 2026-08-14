//! Structural ownership of the analysis family's own work: which module may
//! read the raw graph, in which order a ceiling is proved against the state it
//! protects, and that no walk over a repository-sized graph recurses.
//!
//! The boundary cases in [`super::analysis_ownership`] own what the family
//! publishes. These own how it spends, so neither file has to be read to know
//! what the other holds.

use super::analysis_ownership::ANALYSIS_SOURCES;
use super::scan::{SOURCES, code_only, compact, function_body, method_body, position_of, source};
use super::surface::{declared_call_graph, recursive_functions};

/// The spellings that allocate. A count taken to decide whether to allocate
/// may name none of them.
///
/// Written as families rather than as exact calls. `:: new` and
/// `:: with_capacity` catch every owning container at once; the container names
/// catch whatever else is reached through one, so `Vec :: from` and
/// `String :: from_utf8` need no entry of their own. The rest catch copying,
/// formatting, gathering, and filling.
///
/// A bare `:: from` is deliberately absent: `u64 :: from` converts a number and
/// allocates nothing, and naming it would fail arithmetic that a count must be
/// free to do. The container names above carry the allocating `from`.
pub const ALLOCATION_SPELLINGS: &[&str] = &[
    ":: new",
    ":: with_capacity",
    "Arc ::",
    "BTreeMap ::",
    "BTreeSet ::",
    "BinaryHeap ::",
    "Box ::",
    "HashMap ::",
    "HashSet ::",
    "Rc ::",
    "String ::",
    "Vec ::",
    "VecDeque ::",
    "clone ()",
    "collect",
    "extend (",
    "format !",
    "from_iter",
    "insert (",
    "into_boxed_slice",
    "push (",
    "to_owned",
    "to_string",
    "to_vec",
    "vec !",
];

/// The order analysis construction proves and then spends, in source spelling.
const CONSTRUCTION_ORDER: &[&str] = &[
    "admitted_nodes",
    "admitted_edges",
    "SelectedIndexes :: build",
    "partition :: derive",
];

/// The order a bounded query validates and then walks, in source spelling.
const QUERY_ORDER: &[&str] = &["known_node", "admitted_depth", "walk ("];

/// The one analysis module allowed to read the raw edge slice and to apply the
/// selection to it.
pub const SELECTION_OWNER: &str = "src/analysis/index.rs";

/// The one analysis module allowed to state a selection.
const SELECTION_DECLARER: &str = "src/analysis/selection.rs";

/// The one analysis module that derives the declared partition.
const PARTITION_OWNER: &str = "src/analysis/partition.rs";

/// The one analysis module that measures degree.
const DEGREE_OWNER: &str = "src/analysis/degree.rs";

/// The one analysis module that measures betweenness.
const BETWEENNESS_OWNER: &str = "src/analysis/betweenness.rs";

/// The one analysis module that discovers components and condenses them.
const COMPONENT_OWNER: &str = "src/analysis/components.rs";

/// The analysis modules whose every walk must be iterative.
const ITERATIVE_SOURCES: &[&str] = &[COMPONENT_OWNER, "src/analysis/traversal.rs"];

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

/// Every derived operation the analysis view publishes, beside the one module
/// that implements it.
const ALGORITHM_OWNERS: &[(&str, &str)] = &[
    ("degree::degree", DEGREE_OWNER),
    ("betweenness::betweenness", BETWEENNESS_OWNER),
    ("components::discover", COMPONENT_OWNER),
    ("components::condense", COMPONENT_OWNER),
];

/// Every stated ceiling is proved before the work it protects is done.
pub fn assert_analysis_limit_checks_dominate() {
    assert_ordered(
        &method_body(SELECTION_OWNER, "new"),
        CONSTRUCTION_ORDER,
        "the analysis constructor",
    );
    for counted in ["admitted_nodes", "admitted_edges"] {
        let body = function_body(SELECTION_OWNER, counted);
        let allocating: Vec<&str> = ALLOCATION_SPELLINGS
            .iter()
            .copied()
            .filter(|spelling| body.contains(spelling))
            .collect();
        assert!(
            allocating.is_empty(),
            "{counted} decides whether to allocate and so allocates nothing: {allocating:?}"
        );
    }
    assert!(
        method_body(SELECTION_OWNER, "build").contains("vec !"),
        "the indexed tables are allocated only after both counts are proved"
    );

    for entry in ["neighbors", "subgraph"] {
        assert_ordered(
            &function_body("src/analysis/traversal.rs", entry),
            QUERY_ORDER,
            entry,
        );
    }
    assert!(
        function_body("src/analysis/traversal.rs", "walk").contains("vec !"),
        "the visited state is allocated only after the depth is proved"
    );
    assert_one_consumed_invariant_owner();
}

/// The defensive partition refusal is built once, by the derivation that owns
/// it.
fn assert_one_consumed_invariant_owner() {
    let sites: Vec<&str> = SOURCES
        .iter()
        .filter(|entry| {
            code_only(entry.text).contains("GraphAnalysisError::ConsumedGraphInvariant")
        })
        .map(|entry| entry.path)
        .collect();
    assert_eq!(
        sites,
        [PARTITION_OWNER],
        "only partition derivation may state that a node has no container"
    );
    assert_eq!(
        code_only(source(PARTITION_OWNER))
            .matches("ConsumedGraphInvariant")
            .count(),
        1,
        "the defensive refusal has exactly one construction site"
    );
}

/// Every named spelling occurs, in the stated order.
pub fn assert_ordered(body: &str, sequence: &[&str], subject: &str) {
    let positions: Vec<usize> = sequence
        .iter()
        .map(|spelling| position_of(body, spelling, subject))
        .collect();
    assert!(
        positions.is_sorted(),
        "{subject} must reach {sequence:?} in that order, reaching them at {positions:?}"
    );
}

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
    let traversal = compact(source("src/analysis/traversal.rs"));
    for accessor in [
        "analysis.indexes()",
        "indexes.outgoing(",
        "indexes.incoming(",
        "indexes.parent(",
        "indexes.holds(",
        "indexes.node_count()",
    ] {
        assert!(
            traversal.contains(accessor),
            "traversal must reach the shared indexes through {accessor}"
        );
    }
    assert!(
        compact(source(PARTITION_OWNER)).contains("indexes.parent("),
        "partition derivation must read the stored containment parents"
    );
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
        method_body(SELECTION_OWNER, "new").contains("partition :: derive"),
        "the one derivation runs during successful construction"
    );
}

/// Every analysis module that names one spelling, in [`ANALYSIS_SOURCES`]
/// order.
pub fn analysis_sources_naming(spelling: &str) -> Vec<&'static str> {
    ANALYSIS_SOURCES
        .iter()
        .copied()
        .filter(|path| compact(source(path)).contains(spelling))
        .collect()
}

/// Every metric and component consumer reads the indexes one selection
/// produced, and each derived algorithm has exactly one implementation owner.
pub fn assert_metrics_and_components_consume_shared_indexes() {
    for path in INDEX_CONSUMERS {
        let code = compact(source(path));
        for spelling in [".edges()", ".allows(", "GraphEdgeSelection"] {
            assert!(
                !code.contains(spelling),
                "{path} must read the indexes rather than the graph or the \
                 selection: {spelling}"
            );
        }
    }
    for (path, accessors) in SHARED_ACCESSORS {
        let code = compact(source(path));
        for accessor in *accessors {
            assert!(
                code.contains(accessor),
                "{path} must reach the shared indexes through {accessor}"
            );
        }
    }
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

/// The betweenness work bound is proved before any state exists to prove it
/// against.
pub fn assert_betweenness_work_checks_dominate() {
    let admission = function_body(BETWEENNESS_OWNER, "admitted_work");
    for spelling in [
        "checked_add",
        "checked_mul",
        "BetweennessWorkOverflow",
        "BetweennessWorkLimitExceeded",
    ] {
        assert!(
            admission.contains(spelling),
            "the work bound must state {spelling}"
        );
    }
    let allocating: Vec<&str> = ALLOCATION_SPELLINGS
        .iter()
        .copied()
        .filter(|spelling| admission.contains(spelling))
        .collect();
    assert!(
        allocating.is_empty(),
        "admitted_work decides whether to allocate and so allocates nothing: {allocating:?}"
    );

    let entry = function_body(BETWEENNESS_OWNER, "betweenness");
    assert_ordered(
        &entry,
        &["admitted_work", "Brandes :: empty", "walk (", "scored ("],
        "bounded betweenness",
    );
    assert!(
        method_body(BETWEENNESS_OWNER, "empty").contains("vec !"),
        "the pass allocates its state only after the work bound is proved"
    );
    assert_counts_are_read_rather_than_stated();
    assert_one_work_error_owner();
}

/// The counts the bound is proved against are read from the shared indexes, and
/// neither module holding them offers a second way to state one.
///
/// The published surface of both modules is pinned exactly by
/// `graph_analysis_public_boundary_is_exact`. What is proved here is that no
/// conditionally compiled surface stands beside it: a test-only constructor for
/// these counts would make the defensive overflow reachable from a case rather
/// than from the arithmetic that owns it.
fn assert_counts_are_read_rather_than_stated() {
    let admission = function_body(BETWEENNESS_OWNER, "admitted_work");
    for reader in ["indexes . node_count ()", "indexes . selected_edges ()"] {
        assert!(
            admission.contains(reader),
            "the work bound counts what the shared indexes hold: {reader}"
        );
    }
    for path in [BETWEENNESS_OWNER, SELECTION_OWNER] {
        let code = code_only(source(path));
        let conditional: Vec<&str> = ["cfg(", "cfg_attr"]
            .into_iter()
            .filter(|spelling| code.contains(spelling))
            .collect();
        assert!(
            conditional.is_empty(),
            "{path} must state no conditionally compiled surface beside its \
             published one: {conditional:?}"
        );
    }
}

/// Both betweenness refusals are built only by the pass that bounds itself.
fn assert_one_work_error_owner() {
    for variant in [
        "GraphAnalysisError::BetweennessWorkOverflow",
        "GraphAnalysisError::BetweennessWorkLimitExceeded",
    ] {
        let sites: Vec<&str> = SOURCES
            .iter()
            .filter(|entry| code_only(entry.text).contains(variant))
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            sites,
            [BETWEENNESS_OWNER],
            "{variant} belongs to the one operation that bounds its own work"
        );
    }
    let owner = code_only(source(BETWEENNESS_OWNER));
    for variant in ["BetweennessWorkOverflow", "BetweennessWorkLimitExceeded"] {
        assert_eq!(
            owner.matches(variant).count(),
            1,
            "{variant} has exactly one construction site"
        );
    }
}

/// No walk in the traversal or component modules calls itself, directly or
/// through another.
pub fn assert_traversal_and_components_do_not_recurse() {
    for path in ITERATIVE_SOURCES {
        let calls = declared_call_graph(path);
        assert!(
            calls.len() > 5,
            "{path} declares the functions this case reads: {}",
            calls.len()
        );
        assert_eq!(
            recursive_functions(&calls),
            Vec::<String>::new(),
            "{path} must reach every node of a repository-sized graph without \
             recursing"
        );
    }
}
