//! One explicit edge selection, shared by every query, and the admission
//! ceilings analysis construction refuses at.

use std::collections::BTreeSet;

use pedant_graph::{
    CodeGraph, GraphAnalysis, GraphAnalysisLimits, GraphCertainty, GraphDirection, GraphEdgeId,
    GraphEdgeKind, GraphEdgeSelection,
};

use super::analysis_fixture as given;

/// Every edge kind the graph vocabulary states.
const EVERY_KIND: &[GraphEdgeKind] = &[
    GraphEdgeKind::Call,
    GraphEdgeKind::Import,
    GraphEdgeKind::Implementation,
    GraphEdgeKind::Reference,
    GraphEdgeKind::DependsOn,
];

/// Every source relation, which is every kind but the build-unit dependency.
const CODE_RELATION_KINDS: &[GraphEdgeKind] = &[
    GraphEdgeKind::Call,
    GraphEdgeKind::Import,
    GraphEdgeKind::Implementation,
    GraphEdgeKind::Reference,
];

/// Every certainty the graph vocabulary states.
const EVERY_CERTAINTY: &[GraphCertainty] = &[GraphCertainty::Resolved, GraphCertainty::Possible];

/// One selection and the kinds and certainties it must admit.
struct SelectionCase {
    label: &'static str,
    selection: GraphEdgeSelection,
    kinds: &'static [GraphEdgeKind],
    certainties: &'static [GraphCertainty],
}

/// Each stated selection admits exactly its Cartesian intersection, and every
/// query reads that one admitted set.
pub fn assert_selection_is_explicit_and_shared() {
    let graph = given::selection_graph();
    let admitted = every_case(&graph);
    for case in &admitted {
        let analysis = given::analysis(&graph, case.selection);
        assert_eq!(
            given::edge_texts(&graph, &observed_edges(&analysis, &graph)),
            given::edge_texts(
                &graph,
                &given::admitted_ids(&graph, case.kinds, case.certainties)
            ),
            "{}: every query reads exactly the stated intersection",
            case.label
        );
        assert_view_reads_back_its_own_terms(&graph, &analysis, case);
    }
    assert_cases_are_distinct(&graph, &admitted);
    assert_rejected_edges_are_invisible(&graph);
}

/// An analysis reports the graph it borrowed, the selection it indexed, and
/// the ceilings it was admitted under.
///
/// The reported selection is compared against the same independent Cartesian
/// model the induced edges are, so an accessor answering one fixed selection
/// for every case fails here even though every induced subgraph would still be
/// right.
fn assert_view_reads_back_its_own_terms(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    case: &SelectionCase,
) {
    assert!(
        std::ptr::eq(analysis.graph(), graph),
        "{}: an analysis answers with the graph it borrowed",
        case.label
    );
    let reported: Vec<GraphEdgeId> = graph
        .edges()
        .iter()
        .filter(|edge| analysis.selection().allows(edge))
        .map(|edge| edge.id())
        .collect();
    assert_eq!(
        given::edge_texts(graph, &reported),
        given::edge_texts(
            graph,
            &given::admitted_ids(graph, case.kinds, case.certainties)
        ),
        "{}: the reported selection admits exactly what the indexes were built \
         from",
        case.label
    );
    assert_eq!(
        analysis.limits(),
        given::generous_limits(),
        "{}: the reported ceilings are the ones construction was admitted \
         under",
        case.label
    );
}

/// Every case's selection and the model it is compared against.
fn every_case(graph: &CodeGraph) -> Vec<SelectionCase> {
    let cases = vec![
        SelectionCase {
            label: "no kind",
            selection: GraphEdgeSelection::new(&[], EVERY_CERTAINTY),
            kinds: &[],
            certainties: EVERY_CERTAINTY,
        },
        SelectionCase {
            label: "no certainty",
            selection: GraphEdgeSelection::new(EVERY_KIND, &[]),
            kinds: EVERY_KIND,
            certainties: &[],
        },
        SelectionCase {
            label: "all",
            selection: GraphEdgeSelection::all(),
            kinds: EVERY_KIND,
            certainties: EVERY_CERTAINTY,
        },
        SelectionCase {
            label: "code relations",
            selection: GraphEdgeSelection::code_relations(),
            kinds: CODE_RELATION_KINDS,
            certainties: EVERY_CERTAINTY,
        },
        SelectionCase {
            label: "duplicated calls",
            selection: GraphEdgeSelection::new(
                &[GraphEdgeKind::Call, GraphEdgeKind::Call],
                &[GraphCertainty::Resolved, GraphCertainty::Resolved],
            ),
            kinds: &[GraphEdgeKind::Call],
            certainties: &[GraphCertainty::Resolved],
        },
        SelectionCase {
            label: "resolved dependencies",
            selection: GraphEdgeSelection::new(
                &[GraphEdgeKind::DependsOn],
                &[GraphCertainty::Resolved],
            ),
            kinds: &[GraphEdgeKind::DependsOn],
            certainties: &[GraphCertainty::Resolved],
        },
    ];
    for case in &cases {
        let stated = !case.kinds.is_empty() && !case.certainties.is_empty();
        let admitted = !given::admitted_ids(graph, case.kinds, case.certainties).is_empty();
        assert_eq!(
            stated, admitted,
            "{}: a stated intersection must admit an edge and an empty one must not",
            case.label
        );
    }
    cases
}

/// The stated intersections differ from each other, so no case passes because
/// every selection answers the same set.
fn assert_cases_are_distinct(graph: &CodeGraph, cases: &[SelectionCase]) {
    let sets: Vec<Vec<String>> = cases
        .iter()
        .map(|case| {
            given::edge_texts(
                graph,
                &given::admitted_ids(graph, case.kinds, case.certainties),
            )
        })
        .collect();
    let distinct: BTreeSet<&Vec<String>> = sets.iter().collect();
    assert_eq!(
        distinct.len(),
        sets.len() - 1,
        "only the two empty intersections may agree: {sets:?}"
    );
    assert_eq!(
        given::edge_texts(
            graph,
            &given::admitted_ids(
                graph,
                &[GraphEdgeKind::DependsOn],
                &[GraphCertainty::Resolved]
            )
        ),
        ["app>helper|DependsOn|Resolved"],
        "one kind at one certainty admits the one edge stating both"
    );
}

/// A rejected edge reaches neither a neighborhood nor a subgraph.
fn assert_rejected_edges_are_invisible(graph: &CodeGraph) {
    let root = given::unit_container(graph, "app");
    let depth = u32::try_from(graph.nodes().len()).expect("the corpus is small");

    let dependencies = given::analysis(
        graph,
        GraphEdgeSelection::new(&[GraphEdgeKind::DependsOn], &[GraphCertainty::Resolved]),
    );
    let reached = dependencies
        .neighbors(root, depth, GraphDirection::Both)
        .expect("the admitted depth is below the ceiling");
    assert_eq!(
        given::neighbor_texts(graph, &reached),
        ["helper:1"],
        "a resolved-dependency selection reaches only the resolved dependency"
    );

    let none = given::analysis(graph, GraphEdgeSelection::new(&[], &[]));
    let empty = none
        .subgraph(root, depth, GraphDirection::Both)
        .expect("the admitted depth is below the ceiling");
    assert!(
        empty.edges().is_empty(),
        "an empty selection induces no edge: {:?}",
        given::edge_texts(graph, empty.edges())
    );
    assert_eq!(
        given::names(graph, empty.nodes()),
        ["app"],
        "an empty selection leaves the seed alone"
    );
}

/// Every edge one analysis admits, observed through the induced subgraphs its
/// own queries answer with.
///
/// A subgraph reports every selected edge whose endpoints it holds, and a
/// both-direction walk of the whole node count holds both endpoints of every
/// selected edge, so the union is exactly what the analysis indexed.
fn observed_edges(analysis: &GraphAnalysis<'_>, graph: &CodeGraph) -> Vec<GraphEdgeId> {
    let depth = u32::try_from(graph.nodes().len()).expect("the corpus is small");
    let mut seen: BTreeSet<GraphEdgeId> = BTreeSet::new();
    for node in graph.nodes() {
        let induced = analysis
            .subgraph(node.id(), depth, GraphDirection::Both)
            .expect("the admitted depth is below the ceiling");
        seen.extend(induced.edges().iter().copied());
    }
    seen.into_iter().collect()
}

/// Construction refuses the node and selected-edge ceilings with exact counts,
/// and a refusal answers with no analysis at all.
pub fn assert_admission_limits_refuse() {
    let graph = given::selection_graph();
    let nodes = u32::try_from(graph.nodes().len()).expect("the corpus is small");
    let selected = u32::try_from(given::admitted_ids(&graph, EVERY_KIND, EVERY_CERTAINTY).len())
        .expect("the corpus is small");

    let exact = GraphAnalysisLimits::new(nodes, selected, 0, 0);
    let admitted = GraphAnalysis::new(&graph, GraphEdgeSelection::all(), exact)
        .expect("ceilings equal to the produced counts admit the whole graph");
    assert_eq!(
        admitted.limits(),
        exact,
        "an admitted analysis reports the exact ceilings it was stated with"
    );

    for (label, limits, message) in admission_cases(nodes, selected) {
        let refused = GraphAnalysis::new(&graph, GraphEdgeSelection::all(), limits)
            .err()
            .unwrap_or_else(|| panic!("{label}: the lowered ceiling was admitted"));
        assert_eq!(
            refused.to_string(),
            message,
            "{label}: the refusal must name its own count and ceiling"
        );
    }

    assert!(
        GraphAnalysis::new(
            &graph,
            GraphEdgeSelection::new(&[], &[]),
            GraphAnalysisLimits::new(nodes, 0, u32::MAX, u64::MAX),
        )
        .is_ok(),
        "the edge ceiling bounds the selected edges, not the graph's own"
    );
    assert!(
        GraphAnalysis::new(&graph, GraphEdgeSelection::all(), given::generous_limits()).is_ok(),
        "a refusal consumes nothing: the same graph still admits an analysis"
    );
}

/// Each lowered ceiling and the exact refusal it must produce, as a label, the
/// ceilings it states, and the message the analysis must answer with.
fn admission_cases(nodes: u32, selected: u32) -> [(&'static str, GraphAnalysisLimits, String); 3] {
    let refused_nodes = format!(
        "the graph states {nodes} nodes, above the ceiling of {}",
        nodes - 1
    );
    let refused_edges = format!(
        "the selection admits {selected} edges, above the ceiling of {}",
        selected - 1
    );
    [
        (
            "nodes",
            GraphAnalysisLimits::new(nodes - 1, u32::MAX, u32::MAX, u64::MAX),
            refused_nodes.clone(),
        ),
        (
            "selected edges",
            GraphAnalysisLimits::new(u32::MAX, selected - 1, u32::MAX, u64::MAX),
            refused_edges,
        ),
        (
            "nodes before edges",
            GraphAnalysisLimits::new(nodes - 1, selected - 1, u32::MAX, u64::MAX),
            refused_nodes,
        ),
    ]
}
