//! The derived evidence answers the same for one library, however it was
//! written.
//!
//! [`super::analysis_determinism`] proves it for the selection, traversal,
//! metric, and component answers. This proves it for the partition, the
//! divergence evidence, and the layout metadata built on top of them.
//!
//! Two renderings answer two different questions. A repeated run over an equal
//! graph must state the same records in the same places, so that leg compares
//! [`ordered`] text, which sorts nothing and writes every score as its exact
//! bits: a reordering inside any stored answer fails there rather than washing
//! out. Reordered declarations mint identities in another order, so that leg
//! compares [`derived`] text, which is sorted and carries only integer counts
//! and per-record divisions.
//!
//! Modularity is the one derived value summed across records. A repeated run
//! sums it in the same order, so [`ordered`] compares its exact bits; reordered
//! declarations may sum it in another order, so that leg compares it within a
//! tolerance instead.

use pedant_graph::{
    BoundaryCrossingComponent, CodeGraph, GraphAnalysis, GraphComponents, GraphEdgeSelection,
};

use super::analysis_divergence as divergence;
use super::analysis_divergence_model as model;
use super::analysis_fixture as given;
use super::analysis_perturbation::{
    assert_perturbation_reaches_minted_identities, created_in_reverse, declared_in_reverse,
};
use super::corpus::FixtureFile;
use super::corpus_analysis::{
    ANALYSIS_COMPONENT_CORPUS, ANALYSIS_DIVERGENCE_CORPUS, ANALYSIS_TRAVERSAL_CORPUS,
};

/// Equal graphs produce identical partition, divergence, and layout answers, and
/// reordered declarations produce the same answers about the same partitions.
pub fn assert_divergence_and_layout_are_deterministic() {
    for corpus in [
        ANALYSIS_TRAVERSAL_CORPUS,
        ANALYSIS_COMPONENT_CORPUS,
        ANALYSIS_DIVERGENCE_CORPUS,
    ] {
        let written = given::graph_of(corpus);
        let repeated = given::graph_of(corpus);
        let reversed = given::graph_of(&created_in_reverse(corpus));
        assert_eq!(
            written, reversed,
            "the order a repository's files are created in is not part of its graph"
        );
        for (label, selection) in given::metric_selections() {
            let answers = ordered(&written, selection);
            assert!(
                !answers.is_empty(),
                "{label}: a rendering compares something"
            );
            assert_eq!(
                answers,
                ordered(&repeated, selection),
                "{label}: a repeated run changes no derived answer, and moves \
                 none"
            );
        }
        assert_declaration_order_changes_no_derived_answer(corpus);
    }
}

/// The same declarations, stated in the opposite order, derive the same
/// evidence.
fn assert_declaration_order_changes_no_derived_answer(corpus: &[FixtureFile]) {
    let written = given::graph_of(corpus);
    let reordered = given::generated_graph(&declared_in_reverse(corpus));
    assert_perturbation_reaches_minted_identities(&written, &reordered);
    for (label, selection) in given::metric_selections() {
        assert_eq!(
            named_partition(&written, selection),
            named_partition(&reordered, selection),
            "{label}: the order declarations are stated in changes no owner"
        );
        assert_eq!(
            derived(&written, selection),
            derived(&reordered, selection),
            "{label}: the order declarations are stated in changes no derived answer"
        );
        model::assert_close(
            modularity(&written, selection),
            modularity(&reordered, selection),
            &format!("{label}: directed modularity"),
        );
    }
}

/// Every divergence and layout answer one selection derives, as sorted text.
///
/// Modularity is the one derived value summed across records, so it is compared
/// by itself rather than through this text; everything rendered here is a count
/// or one record's own division.
fn derived(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<String> {
    divergence::rendered(graph, &finite_analysis(graph, selection))
}

/// Every divergence and layout answer one selection derives, each in the exact
/// place the answer holding it states it.
///
/// Nothing is sorted and every score is written as its exact bits, so a repeated
/// run that stated the same records in another order fails here.
fn ordered(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<String> {
    families(graph, selection)
        .into_iter()
        .flat_map(|(label, texts)| texts.into_iter().map(move |text| format!("{label}|{text}")))
        .collect()
}

/// Every family of derived answers one selection states, each family in the
/// order the answer holding it stores its records.
fn families(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<(&'static str, Vec<String>)> {
    let analysis = finite_analysis(graph, selection);
    let evidence = analysis.divergence();
    let components = analysis.strongly_connected_components();
    let layout = analysis
        .layout_assist()
        .expect("the fixture graph is far below every ceiling");
    vec![
        (
            "cohesion",
            given::cohesion_texts(graph, evidence.cohesion()),
        ),
        (
            "modularity",
            vec![given::optional_bits(evidence.modularity())],
        ),
        (
            "candidate",
            given::candidate_texts(graph, evidence.candidates()),
        ),
        (
            "boundary",
            ordered_boundaries(graph, &components, evidence.boundary_components()),
        ),
        (
            "layout node",
            given::layout_node_texts(graph, layout.nodes()),
        ),
        (
            "layout edge",
            given::layout_edge_texts(graph, layout.edges()),
        ),
    ]
}

/// Every boundary-crossing cycle as the component it names, the members that
/// component holds, and the partitions those members are declared in.
///
/// Each of the three is written in the order the answer states it, so a cycle
/// that moved, or members or partitions that changed places inside one, fails.
fn ordered_boundaries(
    graph: &CodeGraph,
    components: &GraphComponents,
    crossing: &[BoundaryCrossingComponent],
) -> Vec<String> {
    crossing
        .iter()
        .map(|record| {
            let held = components
                .component(record.component())
                .unwrap_or_else(|| panic!("no component {}", record.component().index()));
            format!(
                "{}|{}|{}",
                record.component().index(),
                given::names(graph, held.members()).join(","),
                given::names(graph, record.partitions()).join(",")
            )
        })
        .collect()
}

/// One analysis over `graph`, with every floating-point value it derives proved
/// finite before anything renders one.
fn finite_analysis(graph: &CodeGraph, selection: GraphEdgeSelection) -> GraphAnalysis<'_> {
    let analysis = given::analysis(graph, selection);
    assert!(
        derives_finite_values(&analysis),
        "every derived floating-point value is finite"
    );
    analysis
}

/// Whether every floating-point value one analysis derives is finite.
fn derives_finite_values(analysis: &GraphAnalysis<'_>) -> bool {
    let evidence = analysis.divergence();
    let layout = analysis
        .layout_assist()
        .expect("the fixture graph is far below every ceiling");
    let weights = layout
        .nodes()
        .iter()
        .flat_map(|node| [node.raw_betweenness(), node.normalized_betweenness()]);
    evidence
        .cohesion()
        .iter()
        .filter_map(|record| record.score())
        .chain(evidence.candidates().iter().map(|record| record.affinity()))
        .chain(evidence.modularity())
        .chain(weights)
        .all(f64::is_finite)
}

/// One graph's directed modularity under one selection.
fn modularity(graph: &CodeGraph, selection: GraphEdgeSelection) -> Option<f64> {
    given::analysis(graph, selection).divergence().modularity()
}

/// Every node beside the partition that owns it, named.
fn named_partition(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<String> {
    let analysis = given::analysis(graph, selection);
    let partition = analysis.declared_partition();
    let mut owners: Vec<String> = graph
        .nodes()
        .iter()
        .map(|node| {
            let owner = partition
                .owner(node.id())
                .unwrap_or_else(|| panic!("{} belongs to no partition", node.name()));
            format!("{}|{}", node.name(), given::name(graph, owner))
        })
        .collect();
    owners.sort();
    owners
}
