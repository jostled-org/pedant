//! Every derived answer, compared with the graph crate's own.
//!
//! The snippet layer runs no algorithm. Each mode below is asked twice — once
//! through the public index and once of `pedant-graph` directly, over the same
//! graph, selection, and ceilings — and the two must agree on every identity and
//! every number. A projection that ranked, rounded, filtered, or reordered
//! anything fails here.

use pedant_snippet::{
    AnalysisAnswer, AnalysisMode, AnalysisQuery, CodeIntelligenceIndex, CodeIntelligenceState,
    CohesionRecord, GraphAnalysis, GraphComponentId, GraphNodeId, MisplacementRecord,
    NavigationEntity, ProjectHandle, ProjectSlice,
};

use super::fixture::{GO_UNIT, LIBRARY_UNIT, indexed_graph, project};
use super::selection::{admitted, everything};

/// The declarations `RUST_LIBRARY` states that the Rust vocabulary maps to a
/// graph node: `Job`, `Run`, the two `run` methods, `make`, `build`, `ping`, the
/// `relay` module, `relay::forward`, and `relay::pong`.
///
/// The `impl` block is not one of them — it declares no name and joins no node,
/// which `join::an_impl_block_states_no_definition_and_joins_nothing` states.
/// The library graph holds a file node and the crate-root container beside
/// these, so this is the floor rather than the whole count.
const LIBRARY_DECLARATIONS: usize = 10;

/// The declarations `GO_MAIN` states that the Go vocabulary maps to a graph
/// node: the `Job` type, `New`, the `Run` method, and `main`.
///
/// The Go graph holds file and container nodes beside these, so this is the
/// floor rather than the whole count.
const GO_DECLARATIONS: usize = 4;

/// Every projected analysis equals the direct `pedant-graph` answer.
///
/// One oracle, built once and lent to every library row. `GraphAnalysis::new`
/// indexes the whole adjacency, and five rows asking the same question of the
/// same graph, selection, and ceilings would pay for five identical builds of
/// it. The Go row owns its own because it asks about another graph.
#[test]
fn graph_analysis_projection_matches_direct_and_cached_oracles() {
    let (_repository, state) = indexed_graph();
    let library = project(&state, LIBRARY_UNIT);
    let index = state.index();
    let slice = index.project(library).expect("the project is retained");
    let direct = direct_analysis(index, slice);

    degree_matches_the_direct_answer(&state, library, slice, &direct);
    betweenness_matches_the_direct_answer(&state, library, slice, &direct);
    components_match_the_direct_answer(&state, library, slice, &direct);
    condensation_matches_the_direct_answer(&state, library, slice, &direct);
    divergence_matches_the_direct_answer(&state, library, &direct);
    the_go_module_answers_through_the_same_route(&state);
}

/// One oracle measured the whole graph it was asked about, and that graph
/// states at least the declarations its source writes down.
///
/// Every comparison in this file is an equality between a projection and an
/// oracle, and an empty graph satisfies all of them: two zero-length sides are
/// equal, and the loop that would have compared them never runs. So each row
/// states how many nodes its own oracle accounted for and hands that count
/// here, where it is held against the graph the oracle ran over and against the
/// floor the fixture writes down.
///
/// One guard rather than a copy per row. A row holding its own version is a row
/// that can be given a weaker one, which is exactly how an oracle stops being
/// asked whether it measured anything at all.
fn assert_accounts_for_every_node(
    accounted: usize,
    slice: &ProjectSlice,
    floor: usize,
    what: &str,
) {
    assert_eq!(
        accounted,
        slice.graph().nodes().len(),
        "{what} accounts for every node the graph retained"
    );
    assert!(
        accounted >= floor,
        "and the graph states at least the {floor} declarations its source writes down: \
         {accounted}"
    );
}

/// How many nodes one component set accounts for.
///
/// Every node of a selected topology sits in exactly one strongly connected
/// component, so the members summed across the components are the graph's whole
/// node population — which is what makes a component oracle answerable by the
/// same guard a per-node oracle is.
///
/// Takes the member slices rather than the components, because the component
/// record is not a name this crate publishes and a guard is not a reason to
/// widen a product's surface.
fn members_accounted<'held>(members: impl Iterator<Item = &'held [GraphNodeId]>) -> usize {
    members.map(|held| held.len()).sum()
}

/// One analysis answer for one project and mode.
pub fn analyzed(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    mode: AnalysisMode,
) -> AnalysisAnswer {
    state
        .analyze_graph(&AnalysisQuery {
            project,
            edges: everything(),
            mode,
            limits: pedant_snippet::AnalysisLimitRequest::default(),
        })
        .unwrap_or_else(|error| panic!("{}: the analysis answers: {error}", mode.token()))
        .into_result()
}

/// The direct analysis of one retained graph, over the same selection and the
/// same host ceilings the projection ran under.
///
/// Every oracle in this tree asks its question of `pedant-graph` this way, so
/// the selection and the ceilings are stated once. A second copy is how one row
/// starts comparing the projection against a differently bounded answer and
/// keeps passing.
pub fn direct_analysis<'index>(
    index: &'index CodeIntelligenceIndex,
    slice: &'index ProjectSlice,
) -> GraphAnalysis<'index> {
    GraphAnalysis::new(slice.graph(), admitted(), index.limits().graph_analysis)
        .expect("the direct analysis is admitted")
}

/// Degree centrality projects every measured node and both of its counts.
fn degree_matches_the_direct_answer(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    slice: &ProjectSlice,
    direct: &GraphAnalysis<'_>,
) {
    let AnalysisAnswer::DegreeCentrality(measured) =
        analyzed(state, project, AnalysisMode::DegreeCentrality)
    else {
        panic!("the degree mode answers with degrees");
    };
    let expected = direct.degree_centrality();
    assert_accounts_for_every_node(
        expected.len(),
        slice,
        LIBRARY_DECLARATIONS,
        "the degree oracle",
    );
    assert_eq!(measured.len(), expected.len(), "one row per measured node");
    for (held, stated) in measured.iter().zip(expected.iter()) {
        assert_eq!(held.entity().node(), stated.node(), "the same node");
        assert_eq!(held.incoming(), stated.incoming(), "the same in-degree");
        assert_eq!(held.outgoing(), stated.outgoing(), "the same out-degree");
    }
}

/// Betweenness projects every measured node and both of its scores, unrounded.
fn betweenness_matches_the_direct_answer(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    slice: &ProjectSlice,
    direct: &GraphAnalysis<'_>,
) {
    let AnalysisAnswer::BetweennessCentrality(measured) =
        analyzed(state, project, AnalysisMode::BetweennessCentrality)
    else {
        panic!("the betweenness mode answers with betweenness");
    };
    let expected = direct
        .betweenness_centrality()
        .expect("the direct betweenness is admitted");
    assert_accounts_for_every_node(
        expected.len(),
        slice,
        LIBRARY_DECLARATIONS,
        "the betweenness oracle",
    );
    assert_eq!(measured.len(), expected.len(), "one row per measured node");
    for (held, stated) in measured.iter().zip(expected.iter()) {
        assert_eq!(held.entity().node(), stated.node(), "the same node");
        assert_eq!(
            held.raw().to_bits(),
            stated.raw().to_bits(),
            "the same score"
        );
        assert_eq!(
            held.normalized().to_bits(),
            stated.normalized().to_bits(),
            "and the same normalized score, bit for bit"
        );
    }
}

/// Components project every component, every member, and its cyclic flag.
fn components_match_the_direct_answer(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    slice: &ProjectSlice,
    direct: &GraphAnalysis<'_>,
) {
    let AnalysisAnswer::Components(measured) = analyzed(state, project, AnalysisMode::Components)
    else {
        panic!("the components mode answers with components");
    };
    let expected = direct.strongly_connected_components();
    assert_accounts_for_every_node(
        members_accounted(expected.components().iter().map(|held| held.members())),
        slice,
        LIBRARY_DECLARATIONS,
        "the component oracle",
    );
    assert_eq!(
        measured.len(),
        expected.components().len(),
        "one row per component"
    );
    for (held, stated) in measured.iter().zip(expected.components().iter()) {
        assert_eq!(held.id(), stated.id(), "the same component identity");
        assert_eq!(held.cyclic(), stated.is_cyclic(), "the same cyclic flag");
        assert_eq!(
            members(held.members()),
            stated.members().to_vec(),
            "the same members"
        );
    }
}

/// The condensation projects every component, edge, and the whole order.
fn condensation_matches_the_direct_answer(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    slice: &ProjectSlice,
    direct: &GraphAnalysis<'_>,
) {
    let AnalysisAnswer::Condensation(measured) =
        analyzed(state, project, AnalysisMode::Condensation)
    else {
        panic!("the condensation mode answers with a condensation");
    };
    let expected = direct.condensation();
    assert_accounts_for_every_node(
        members_accounted(
            expected
                .components()
                .components()
                .iter()
                .map(|held| held.members()),
        ),
        slice,
        LIBRARY_DECLARATIONS,
        "the condensation oracle",
    );
    assert_eq!(
        measured
            .components()
            .iter()
            .map(|component| (component.id(), members(component.members())))
            .collect::<Vec<_>>(),
        expected
            .components()
            .components()
            .iter()
            .map(|component| (component.id(), component.members().to_vec()))
            .collect::<Vec<_>>(),
        "every component survives"
    );
    assert_eq!(
        measured
            .edges()
            .iter()
            .map(|edge| (edge.source(), edge.target(), edge.edges().to_vec()))
            .collect::<Vec<_>>(),
        expected
            .edges()
            .iter()
            .map(|edge| (edge.source(), edge.target(), edge.edges().to_vec()))
            .collect::<Vec<_>>(),
        "every condensation edge survives, with the raw edges behind it"
    );
    assert_eq!(
        measured.topological_order().to_vec(),
        expected.topological_order().to_vec(),
        "and the order survives whole"
    );
    assert_eq!(
        measured
            .topological_order()
            .iter()
            .collect::<std::collections::BTreeSet<&GraphComponentId>>()
            .len(),
        measured.topological_order().len(),
        "no component is ordered twice"
    );
}

/// One projected module measurement, as graph identities and numbers.
///
/// The projection side of each divergence comparison is named; the oracle side
/// is spelled out where it is compared. One mapper serving both would be one
/// statement handed to both sides, and a field it forgot would be a field
/// neither side carried.
fn projected_module(module: &CohesionRecord) -> (GraphNodeId, u32, u32, Option<u64>) {
    (
        module.root().node(),
        module.internal_edges(),
        module.boundary_edges(),
        module.score().map(f64::to_bits),
    )
}

/// One projected misplacement candidate, as graph identities and numbers.
fn projected_misplacement(
    candidate: &MisplacementRecord,
) -> (GraphNodeId, GraphNodeId, GraphNodeId, u32, u32, u64) {
    (
        candidate.symbol().node(),
        candidate.declared_partition().node(),
        candidate.candidate_partition().node(),
        candidate.foreign_edges(),
        candidate.total_outgoing_edges(),
        candidate.affinity().to_bits(),
    )
}

/// Divergence projects every measurement, unranked and unrounded.
fn divergence_matches_the_direct_answer(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    direct: &GraphAnalysis<'_>,
) {
    let AnalysisAnswer::ModuleDivergence(measured) =
        analyzed(state, project, AnalysisMode::ModuleDivergence)
    else {
        panic!("the divergence mode answers with divergence evidence");
    };
    let expected = direct.divergence();
    assert!(
        expected.cohesion().len() > 1,
        "the library graph states the two declared partitions this measurement is over, or \
         two empty cohesion lists would compare equal: {}",
        expected.cohesion().len()
    );
    assert_eq!(
        measured
            .cohesion()
            .iter()
            .map(projected_module)
            .collect::<Vec<_>>(),
        expected
            .cohesion()
            .iter()
            .map(|module| {
                (
                    module.root(),
                    module.internal_edges(),
                    module.boundary_edges(),
                    module.score().map(f64::to_bits),
                )
            })
            .collect::<Vec<_>>(),
        "every measured module survives"
    );
    assert_eq!(
        measured.modularity().map(f64::to_bits),
        expected.modularity().map(f64::to_bits),
        "and the modularity survives bit for bit"
    );
    assert!(
        !expected.candidates().is_empty(),
        "the library graph states a misplacement candidate for the projection to carry"
    );
    assert_eq!(
        measured
            .candidates()
            .iter()
            .map(projected_misplacement)
            .collect::<Vec<_>>(),
        expected
            .candidates()
            .iter()
            .map(|candidate| (
                candidate.symbol(),
                candidate.declared_partition(),
                candidate.candidate_partition(),
                candidate.foreign_edges(),
                candidate.total_outgoing_edges(),
                candidate.affinity().to_bits(),
            ))
            .collect::<Vec<_>>(),
        "every misplacement candidate survives, both partitions and every number"
    );
    assert!(
        !expected.boundary_components().is_empty(),
        "and the library graph states a cycle that crosses a declared boundary"
    );
    assert_eq!(
        measured
            .boundary_components()
            .iter()
            .map(|crossing| (crossing.component(), members(crossing.partitions())))
            .collect::<Vec<_>>(),
        expected
            .boundary_components()
            .iter()
            .map(|crossing| (crossing.component(), crossing.partitions().to_vec()))
            .collect::<Vec<_>>(),
        "and every boundary-crossing component survives"
    );
}

/// The Go module, whose graph the direct builder produced, answers through the
/// same route and agrees with its own oracle.
///
/// The floor is stated here for the same reason it is stated for the Rust graph:
/// the comparison below is an equality between two mapped lists, and an empty Go
/// graph would satisfy it while proving nothing about a graph the direct builder
/// produced.
fn the_go_module_answers_through_the_same_route(state: &CodeIntelligenceState) {
    let module = project(state, GO_UNIT);
    let AnalysisAnswer::DegreeCentrality(measured) =
        analyzed(state, module, AnalysisMode::DegreeCentrality)
    else {
        panic!("the degree mode answers with degrees");
    };
    let index = state.index();
    let slice = index.project(module).expect("the Go project is retained");
    let expected = direct_analysis(index, slice).degree_centrality();
    assert_accounts_for_every_node(
        expected.len(),
        slice,
        GO_DECLARATIONS,
        "the Go degree oracle",
    );
    assert_eq!(
        measured
            .iter()
            .map(|held| (held.entity().node(), held.incoming(), held.outgoing()))
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|stated| (stated.node(), stated.incoming(), stated.outgoing()))
            .collect::<Vec<_>>(),
        "a directly built graph projects exactly as a reused one does"
    );
}

/// The graph identity behind each projected member.
///
/// Every member carries one, whichever kind it is: an answer whose declarations
/// lost their node identity would leave a caller holding edges whose endpoints
/// match nothing in the same answer.
pub fn members(entities: &[NavigationEntity]) -> Vec<GraphNodeId> {
    entities.iter().map(NavigationEntity::node).collect()
}
