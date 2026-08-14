//! How the analysis family spends: in which order a ceiling is proved against
//! the state it protects, and that no walk over a repository-sized graph
//! recurses.
//!
//! The boundary cases in [`super::analysis_ownership`] own what the family
//! publishes, and [`super::analysis_ownership_sharing`] owns what one selection
//! produces and who may read it. These own how it spends, so no one file has to
//! be read to know what the others hold.

use super::analysis_ownership::{
    ANALYSIS_SOURCES, BETWEENNESS_OWNER, COMPONENT_OWNER, PARTITION_OWNER, SELECTION_OWNER,
};
use super::inventory::SOURCES;
use super::scan::{code_only, compact, function_body, method_body, position_of, source};
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

/// The order the one admission owner proves both counts, in source spelling.
const ADMISSION_ORDER: &[&str] = &["admitted_nodes", "admitted_edges"];

/// The order shared analysis state is admitted and then built, in source
/// spelling.
///
/// The counts are proved by one owner and the tables are filled by another, so
/// a borrowed analysis and a cached lookup reach the same proof before either
/// allocates anything indexed by it.
const CONSTRUCTION_ORDER: &[&str] = &["admitted_counts (", "from_admitted"];

/// The order the admitted counts are spent, in source spelling.
const INDEXING_ORDER: &[&str] = &["SelectedIndexes :: build", "partition :: derive"];

/// The order the one walk admission owner proves a seed and a depth, in source
/// spelling.
const QUERY_ORDER: &[&str] = &["known_node", "admitted_depth"];

/// The order each bounded query proves its arguments and then walks, in source
/// spelling.
///
/// The walk is named by the spelling that consumes it rather than by a bare
/// `walk (`, which the admission spelling contains: an element its predecessor
/// spells resolves inside that predecessor, so it would sort by construction
/// and still hold with the walk deleted. [`assert_ordered`] refuses that shape
/// outright; these spellings state the consumer so the element binds the real
/// walk.
const WALK_ORDER: &[(&str, &[&str])] = &[
    ("neighbors", &["admitted_walk (", "Ok (walk ("]),
    ("subgraph", &["admitted_walk (", "& walk ("]),
];

/// The one cached module answering bounded walks from retained products.
const CACHED_QUERY_OWNER: &str = "src/cache/analysis.rs";

/// The order a cached bounded query proves its arguments and then looks, in
/// source spelling.
const CACHED_QUERY_ORDER: &[&str] = &["self . admits_walk (", "self . product ("];

/// The analysis modules whose every walk must be iterative.
const ITERATIVE_SOURCES: &[&str] = &[COMPONENT_OWNER, "src/analysis/traversal.rs"];

/// Every stated ceiling is proved before the work it protects is done.
pub fn assert_analysis_limit_checks_dominate() {
    assert_ordered(
        &function_body(SELECTION_OWNER, "admitted_counts"),
        ADMISSION_ORDER,
        "the admission owner",
    );
    assert_ordered(
        &method_body(SELECTION_OWNER, "indexed"),
        CONSTRUCTION_ORDER,
        "shared analysis construction",
    );
    assert_ordered(
        &method_body(SELECTION_OWNER, "from_admitted"),
        INDEXING_ORDER,
        "shared analysis indexing",
    );
    assert!(
        method_body(SELECTION_OWNER, "new").contains("SharedAnalysis :: indexed"),
        "the borrowed analysis is built through the one shared owner"
    );
    for counted in ["admitted_nodes", "admitted_edges", "admitted_counts"] {
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

    assert_ordered(
        &function_body("src/analysis/traversal.rs", "admitted_walk"),
        QUERY_ORDER,
        "the walk admission owner",
    );
    for &(entry, order) in WALK_ORDER {
        assert_ordered(
            &function_body("src/analysis/traversal.rs", entry),
            order,
            entry,
        );
    }
    assert!(
        function_body("src/analysis/traversal.rs", "walk").contains("vec !"),
        "the visited state is allocated only after the depth is proved"
    );
    assert_cached_walks_reach_the_admission_owner();
    assert_one_consumed_invariant_owner();
}

/// A cached bounded walk proves its arguments through the one admission owner,
/// before it examines anything the graph retained.
///
/// The order matters as much as the checks do. Two refusals apply to one walk,
/// and a handle that proved the depth first would answer an unknown node with
/// the depth refusal the direct analysis never states for it.
fn assert_cached_walks_reach_the_admission_owner() {
    for entry in ["neighbors", "subgraph"] {
        assert_ordered(
            &method_body(CACHED_QUERY_OWNER, entry),
            CACHED_QUERY_ORDER,
            &format!("the cached {entry}"),
        );
    }
    let admission = method_body(CACHED_QUERY_OWNER, "admits_walk");
    assert!(
        admission.contains("traversal :: admitted_walk ("),
        "a cached walk is admitted by the owner the borrowed walks reach"
    );
    let stated: Vec<&str> = ["known_node", "admitted_depth"]
        .into_iter()
        .filter(|spelling| code_only(source(CACHED_QUERY_OWNER)).contains(spelling))
        .collect();
    assert!(
        stated.is_empty(),
        "{CACHED_QUERY_OWNER} must state no second walk admission: {stated:?}"
    );
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

/// Every named spelling occurs, in the stated order, at its own place in the
/// body.
///
/// Each spelling is resolved by first occurrence, so one that another spelling
/// contains would resolve inside it: the positions would sort by construction
/// and the clause would hold with the named work deleted. Each occurrence must
/// therefore begin at or after the end of the one before it, which every
/// distinct step of a real sequence does.
pub fn assert_ordered(body: &str, sequence: &[&str], subject: &str) {
    let mut previous: Option<(&str, usize)> = None;
    for spelling in sequence {
        let at = position_of(body, spelling, subject);
        if let Some((before, from)) = previous {
            assert!(
                from + before.len() <= at,
                "{subject} must reach {spelling:?} at {at} beyond {before:?} at {from}, rather \
                 than inside it"
            );
        }
        previous = Some((spelling, at));
    }
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

/// The spellings a consumer would reach past the shared indexes with.
///
/// The raw edge slice, the selection predicate, and the selection type itself. A
/// consumer that names one of them is answering from the graph or from a
/// selection it reconstructed rather than from the indexes one selection already
/// produced.
const GRAPH_READS: &[&str] = &[".edges()", ".allows(", "GraphEdgeSelection"];

/// No listed consumer reads the graph or the selection.
///
/// One rule, stated once. Every seam that has consumers — metrics, components,
/// and the two derived answers built on them — asks the same question of them,
/// and a copy of this loop per seam is a rule that can drift into two rules.
pub fn assert_reads_indexes_not_graph(paths: &[&str]) {
    for path in paths {
        let code = compact(source(path));
        for spelling in GRAPH_READS {
            assert!(
                !code.contains(spelling),
                "{path} must read the shared indexes rather than the graph or \
                 the selection: {spelling}"
            );
        }
    }
}

/// Every listed consumer reaches its inputs through the stated accessors.
pub fn assert_reaches(table: &[(&str, &[&str])]) {
    for (path, accessors) in table {
        let code = compact(source(path));
        for accessor in *accessors {
            assert!(
                code.contains(accessor),
                "{path} must reach its inputs through {accessor}"
            );
        }
    }
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
