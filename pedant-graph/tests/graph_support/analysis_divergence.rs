//! Declared-partition divergence, stated by hand and read back.
//!
//! Every count and ratio below is written from the corpus source and the
//! selected topology it produces. The comparison itself, and the independent
//! model the selection case is compared against, live in
//! [`super::analysis_divergence_model`], so this module states what is true and
//! that one states how two answers are compared.

use std::collections::BTreeSet;

use pedant_graph::{
    CodeGraph, GraphAnalysis, GraphEdgeId, GraphEdgeSelection, MisplacementCandidate,
};

use super::analysis_divergence_model::{self as model, DivergenceModel};
use super::analysis_fixture as given;
use super::analysis_oracle as oracle;

/// The selected code relations the hand calculations below were taken from, in
/// raw edge-id order.
///
/// `pub mod alpha;` states the one non-call relation, from the source holding
/// that declaration to the module it declares. Every call is written in the
/// corpus source, and `crate::root_call()` closes the one cycle that leaves its
/// own partition.
const CODE_RELATION_EDGES: &[&str] = &[
    "alpha_call>alpha_leaf|Call|Resolved",
    "alpha_leaf>root_call|Call|Resolved",
    "src/lib.rs>alpha|Reference|Resolved",
    "beta_call>beta_leaf|Call|Resolved",
    "root_call>alpha_call|Call|Resolved",
    "root_call>beta_call|Call|Resolved",
    "root_call>root_leaf|Call|Resolved",
];

/// The same relations, plus the package dependency no source states. Dependency
/// evidence is minted before any source relation, so it leads the order.
const EVERY_EDGE: &[&str] = &[
    "app>helper|DependsOn|Resolved",
    "alpha_call>alpha_leaf|Call|Resolved",
    "alpha_leaf>root_call|Call|Resolved",
    "src/lib.rs>alpha|Reference|Resolved",
    "beta_call>beta_leaf|Call|Resolved",
    "root_call>alpha_call|Call|Resolved",
    "root_call>beta_call|Call|Resolved",
    "root_call>root_leaf|Call|Resolved",
];

/// One partition's cohesion, hand-counted: root, internal, boundary, score.
type CohesionRow = (&'static str, u32, u32, Option<f64>);

/// One affinity record, hand-counted: symbol, declared, candidate, `k`, `n`,
/// `k / n`.
type CandidateRow = (&'static str, &'static str, &'static str, u32, u32, f64);

/// One cycle crossing a partition boundary: its members, then its partitions.
type BoundaryRow = (&'static str, &'static str);

/// One hand-calculated case: what was selected, and what that selection makes
/// true.
struct DivergenceCase {
    label: &'static str,
    selection: GraphEdgeSelection,
    edges: &'static [&'static str],
    cohesion: &'static [CohesionRow],
    modularity: f64,
    candidates: &'static [CandidateRow],
    boundary: &'static [BoundaryRow],
}

/// Cohesion under the code relations alone.
///
/// `app` states one internal call — `root_call` to `root_leaf` — against three
/// relations leaving it: the module declaration its own source states, and the
/// two calls into `alpha` and `beta`. Both the source holding that declaration
/// and the two root functions are declared by the unit root, so all four
/// relations are counted for `app`. `alpha` calls itself once and calls back
/// into the unit root once.
/// `beta` calls only itself. `helper` states no relation at all, so its score
/// has no denominator.
const CODE_RELATION_COHESION: &[CohesionRow] = &[
    ("app", 1, 3, Some(0.25)),
    ("alpha", 1, 1, Some(0.5)),
    ("beta", 1, 0, Some(1.0)),
    ("helper", 0, 0, None),
];

/// Cohesion once the package dependency is selected too: one more relation
/// leaves `app` for another unit root.
const EVERY_EDGE_COHESION: &[CohesionRow] = &[
    ("app", 1, 4, Some(0.2)),
    ("alpha", 1, 1, Some(0.5)),
    ("beta", 1, 0, Some(1.0)),
    ("helper", 0, 0, None),
];

/// `Q = 3/7 - (4*2 + 2*3 + 1*2) / 49 = 5/49`.
const CODE_RELATION_MODULARITY: f64 = 5.0 / 49.0;

/// `Q = 3/8 - (5*2 + 2*3 + 1*2) / 64 = 3/32`.
const EVERY_EDGE_MODULARITY: f64 = 3.0 / 32.0;

/// Every symbol with a call leaving its own partition, by symbol name.
///
/// `root_call` states three calls, one into each foreign partition, so both of
/// its ratios are a third — recorded rather than thresholded away.
/// `alpha_leaf`'s one call leaves its partition entirely. Both selections state
/// the same records: the dependency edge joins two unit roots rather than two
/// symbols.
const EXPECTED_CANDIDATES: &[CandidateRow] = &[
    ("alpha_leaf", "alpha", "app", 1, 1, 1.0),
    ("root_call", "app", "alpha", 1, 3, 1.0 / 3.0),
    ("root_call", "app", "beta", 1, 3, 1.0 / 3.0),
];

/// The one cycle whose members are declared in two partitions.
const EXPECTED_BOUNDARY: &[BoundaryRow] = &[("alpha_call,alpha_leaf,root_call", "alpha,app")];

/// Every hand-calculated cohesion count, modularity value, affinity ratio, and
/// boundary-crossing cycle, under both selections.
pub fn assert_divergence_matches_declared_partition_arithmetic() {
    let graph = given::divergence_graph();
    for case in hand_calculated_cases() {
        let analysis = given::analysis(&graph, case.selection);
        assert_eq!(
            given::edge_texts(&graph, &selected_ids(&graph, case.selection)),
            case.edges,
            "{}: the arithmetic below is taken from this exact topology",
            case.label
        );
        model::assert_matches(
            &model::observed(&graph, &analysis),
            &hand_written(&case),
            case.label,
        );
        assert_cohesion_is_in_root_order(&graph, &analysis);
        assert_candidates_are_sorted(&graph, analysis.divergence().candidates());
    }
    assert_no_threshold_is_applied(&graph);
}

/// Both hand-calculated selections.
fn hand_calculated_cases() -> [DivergenceCase; 2] {
    [
        DivergenceCase {
            label: "code relations",
            selection: GraphEdgeSelection::code_relations(),
            edges: CODE_RELATION_EDGES,
            cohesion: CODE_RELATION_COHESION,
            modularity: CODE_RELATION_MODULARITY,
            candidates: EXPECTED_CANDIDATES,
            boundary: EXPECTED_BOUNDARY,
        },
        DivergenceCase {
            label: "all",
            selection: GraphEdgeSelection::all(),
            edges: EVERY_EDGE,
            cohesion: EVERY_EDGE_COHESION,
            modularity: EVERY_EDGE_MODULARITY,
            candidates: EXPECTED_CANDIDATES,
            boundary: EXPECTED_BOUNDARY,
        },
    ]
}

/// Every raw edge one selection admits, taken from the raw slice.
fn selected_ids(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<GraphEdgeId> {
    oracle::selected(graph, selection)
        .iter()
        .map(|edge| edge.id)
        .collect()
}

/// One case's hand-written answer, as one comparable model.
fn hand_written(case: &DivergenceCase) -> DivergenceModel {
    DivergenceModel {
        cohesion: case
            .cohesion
            .iter()
            .map(|(root, internal, boundary, score)| {
                ((*root).to_owned(), *internal, *boundary, *score)
            })
            .collect(),
        modularity: Some(case.modularity),
        candidates: case
            .candidates
            .iter()
            .map(|(symbol, declared, candidate, foreign, total, ratio)| {
                (
                    (*symbol).to_owned(),
                    (*declared).to_owned(),
                    (*candidate).to_owned(),
                    *foreign,
                    *total,
                    *ratio,
                )
            })
            .collect(),
        boundary: case
            .boundary
            .iter()
            .map(|(members, partitions)| ((*members).to_owned(), (*partitions).to_owned()))
            .collect(),
    }
}

/// Cohesion is stated once per partition root, in root-id order.
fn assert_cohesion_is_in_root_order(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    let divergence = analysis.divergence();
    let stated: Vec<u32> = divergence
        .cohesion()
        .iter()
        .map(|record| record.root().index())
        .collect();
    let roots: Vec<u32> = analysis
        .declared_partition()
        .roots()
        .iter()
        .map(|root| root.index())
        .collect();
    assert_eq!(
        stated,
        roots,
        "cohesion answers for every partition root once, in root-id order: {:?}",
        given::cohesion_texts(graph, divergence.cohesion())
    );
}

/// Affinity records rise strictly by symbol, then by candidate partition.
///
/// A strict rise is the stronger claim: one record per symbol and candidate
/// partition, which is what the production count states.
fn assert_candidates_are_sorted(graph: &CodeGraph, candidates: &[MisplacementCandidate]) {
    let keys: Vec<(u32, u32)> = candidates
        .iter()
        .map(|record| {
            (
                record.symbol().index(),
                record.candidate_partition().index(),
            )
        })
        .collect();
    assert!(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "affinity records rise strictly by symbol then candidate: {:?}",
        given::candidate_texts(graph, candidates)
    );
}

/// A symbol whose calls mostly stay at home still states its foreign evidence,
/// and a symbol with no foreign call states none.
fn assert_no_threshold_is_applied(graph: &CodeGraph) {
    let analysis = given::analysis(graph, GraphEdgeSelection::code_relations());
    let divergence = analysis.divergence();
    let smallest = divergence
        .candidates()
        .iter()
        .map(|record| record.affinity())
        .fold(f64::INFINITY, f64::min);
    assert!(
        smallest < 0.5,
        "a minority of foreign calls is still recorded: {smallest}"
    );
    let symbols: BTreeSet<String> = divergence
        .candidates()
        .iter()
        .map(|record| given::name(graph, record.symbol()))
        .collect();
    assert!(
        !symbols.contains("alpha_call"),
        "a symbol whose every call stays at home states no candidate: {symbols:?}"
    );
}

/// Every divergence answer reads the selected indexes, while partition
/// ownership answers the same whatever was selected.
pub fn assert_divergence_selection_reuses_indexes() {
    for graph in [given::divergence_graph(), given::selection_graph()] {
        let mut ownership: BTreeSet<Vec<String>> = BTreeSet::new();
        let mut answers: BTreeSet<Vec<String>> = BTreeSet::new();
        for (label, selection) in given::metric_selections() {
            let analysis = given::analysis(&graph, selection);
            ownership.insert(owner_names(&graph, &analysis));
            answers.insert(rendered(&graph, &analysis));
            model::assert_matches(
                &model::observed(&graph, &analysis),
                &model::modelled(&graph, &analysis, selection),
                &format!("{label}: the selected topology"),
            );
        }
        assert_eq!(
            ownership.len(),
            1,
            "which container owns a node is not a function of the selection"
        );
        assert!(
            answers.len() > 1,
            "the selections compared must not all answer the same"
        );
    }
}

/// Every node beside the partition that owns it, named.
fn owner_names(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> Vec<String> {
    let partition = analysis.declared_partition();
    graph
        .nodes()
        .iter()
        .map(|node| {
            let owner = partition
                .owner(node.id())
                .unwrap_or_else(|| panic!("{} belongs to no partition", node.name()));
            format!("{}|{}", node.name(), given::name(graph, owner))
        })
        .collect()
}

/// Every divergence and layout answer as comparable text, keyed by name and
/// sorted.
///
/// Every value written here is either an integer count or one record's own
/// division, so two graphs stating the same declarations in different orders
/// render the same text. The one value summed across records — modularity — is
/// compared by its own caller, within [`TOLERANCE`].
pub fn rendered(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> Vec<String> {
    let divergence = analysis.divergence();
    let components = analysis.strongly_connected_components();
    let mut answers = given::cohesion_texts(graph, divergence.cohesion());
    answers.extend(given::candidate_texts(graph, divergence.candidates()));
    answers.extend(given::boundary_texts(
        graph,
        &components,
        divergence.boundary_components(),
    ));
    let layout = analysis
        .layout_assist()
        .expect("the fixture graph is far below every ceiling");
    answers.extend(given::layout_edge_texts(graph, layout.edges()));
    answers.extend(given::layout_node_texts(graph, layout.nodes()));
    answers.sort();
    answers
}
