//! One divergence answer, taken apart so two of them can be compared.
//!
//! [`super::analysis_divergence`] states what is true by hand; this module says
//! what "the same answer" means — identities and counts exactly, ratios within
//! [`TOLERANCE`] — and models the same four answers independently, from the raw
//! edge slice and the partition Step 1 already proved.
//!
//! Nothing here reads a divergence result to build a model: the cohesion counts
//! are scanned, the modularity is the literal double sum over same-partition
//! node pairs, and the affinity records are grouped from the raw edges.

use std::collections::{BTreeMap, BTreeSet};

use pedant_graph::{
    CodeGraph, GraphAnalysis, GraphEdgeSelection, GraphNodeKind, MisplacementCandidate,
};

use super::analysis_fixture as given;
use super::analysis_oracle::{self as oracle, SelectedEdge};

/// How far a modelled or hand-calculated ratio may sit from the answer.
const TOLERANCE: f64 = 1e-12;

/// One divergence answer, named and taken apart into comparable pieces.
///
/// The hand-written case and the modelled case both produce one of these, so one
/// comparison decides how each piece is compared: identities and counts exactly,
/// ratios within [`TOLERANCE`].
pub struct DivergenceModel {
    /// Every partition's cohesion, named.
    pub cohesion: Vec<(String, u32, u32, Option<f64>)>,
    /// The directed modularity of the whole partition.
    pub modularity: Option<f64>,
    /// Every affinity record, named.
    pub candidates: Vec<(String, String, String, u32, u32, f64)>,
    /// Every boundary-crossing cycle, named.
    pub boundary: Vec<(String, String)>,
}

/// The answer one analysis states, named through the graph it borrows.
pub fn observed(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> DivergenceModel {
    let divergence = analysis.divergence();
    let components = analysis.strongly_connected_components();
    DivergenceModel {
        cohesion: divergence
            .cohesion()
            .iter()
            .map(|record| {
                (
                    given::name(graph, record.root()),
                    record.internal_edges(),
                    record.boundary_edges(),
                    record.score(),
                )
            })
            .collect(),
        modularity: divergence.modularity(),
        candidates: divergence
            .candidates()
            .iter()
            .map(|record| named_candidate(graph, record))
            .collect(),
        boundary: divergence
            .boundary_components()
            .iter()
            .map(|record| {
                let held = components
                    .component(record.component())
                    .unwrap_or_else(|| panic!("no component {}", record.component().index()));
                (
                    given::sorted_names(graph, held.members()),
                    given::sorted_names(graph, record.partitions()),
                )
            })
            .collect(),
    }
}

/// One affinity record, named.
fn named_candidate(
    graph: &CodeGraph,
    record: &MisplacementCandidate,
) -> (String, String, String, u32, u32, f64) {
    (
        given::name(graph, record.symbol()),
        given::name(graph, record.declared_partition()),
        given::name(graph, record.candidate_partition()),
        record.foreign_edges(),
        record.total_outgoing_edges(),
        record.affinity(),
    )
}

/// Every name in sorted order, joined.
///
/// Which identity the builder minted first decides the order a member list is
/// written in; that a cycle holds exactly these members is the fact under test,
/// and the orders themselves are proved by the component and cohesion cases.
fn sorted_join(names: Vec<String>) -> String {
    let mut ordered = names;
    ordered.sort();
    ordered.join(",")
}

/// Two divergence answers agree: identities and counts exactly, ratios within
/// [`TOLERANCE`].
pub fn assert_matches(observed: &DivergenceModel, expected: &DivergenceModel, subject: &str) {
    assert_eq!(
        counted_cohesion(observed),
        counted_cohesion(expected),
        "{subject}: every cohesion count"
    );
    for (left, right) in sorted_cohesion(observed)
        .iter()
        .zip(sorted_cohesion(expected))
    {
        assert_close(left.3, right.3, &format!("{subject}: {} cohesion", left.0));
    }
    assert_close(
        observed.modularity,
        expected.modularity,
        &format!("{subject}: directed modularity"),
    );
    assert_eq!(
        counted_candidates(observed),
        counted_candidates(expected),
        "{subject}: every affinity record"
    );
    for (left, right) in sorted_candidates(observed)
        .iter()
        .zip(sorted_candidates(expected))
    {
        assert_close(
            Some(left.5),
            Some(right.5),
            &format!("{subject}: {} affinity for {}", left.0, left.2),
        );
    }
    assert_eq!(
        sorted_boundary(observed),
        sorted_boundary(expected),
        "{subject}: every boundary-crossing cycle"
    );
}

/// Every cohesion record by root name, with its ratio held aside.
fn sorted_cohesion(model: &DivergenceModel) -> Vec<(String, u32, u32, Option<f64>)> {
    let mut ordered = model.cohesion.clone();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    ordered
}

/// Every cohesion record by root name, without its ratio.
fn counted_cohesion(model: &DivergenceModel) -> Vec<(String, u32, u32, bool)> {
    sorted_cohesion(model)
        .into_iter()
        .map(|(root, internal, boundary, score)| (root, internal, boundary, score.is_some()))
        .collect()
}

/// Every affinity record by symbol then candidate name.
fn sorted_candidates(model: &DivergenceModel) -> Vec<(String, String, String, u32, u32, f64)> {
    let mut ordered = model.candidates.clone();
    ordered.sort_by(|left, right| (&left.0, &left.2).cmp(&(&right.0, &right.2)));
    ordered
}

/// Every affinity record by symbol then candidate name, without its ratio.
fn counted_candidates(model: &DivergenceModel) -> Vec<(String, String, String, u32, u32)> {
    sorted_candidates(model)
        .into_iter()
        .map(|(symbol, declared, candidate, foreign, total, _)| {
            (symbol, declared, candidate, foreign, total)
        })
        .collect()
}

/// Every boundary-crossing cycle, in sorted order.
fn sorted_boundary(model: &DivergenceModel) -> Vec<(String, String)> {
    let mut ordered = model.boundary.clone();
    ordered.sort();
    ordered
}

/// Two optional ratios agree, or neither states one.
pub fn assert_close(observed: Option<f64>, expected: Option<f64>, subject: &str) {
    match (observed, expected) {
        (Some(left), Some(right)) => assert!(
            left.is_finite() && (left - right).abs() <= TOLERANCE,
            "{subject}: {left} is not {right} within {TOLERANCE}"
        ),
        (None, None) => (),
        (left, right) => panic!("{subject}: {left:?} does not answer as {right:?}"),
    }
}

/// The divergence one selection implies, modelled from the raw edge slice and
/// the partition Step 1 proved.
///
/// Nothing here reads a divergence result: the cohesion counts are scanned, the
/// modularity is the literal double sum over same-partition node pairs, and the
/// affinity records are grouped from the raw edges.
pub fn modelled(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    selection: GraphEdgeSelection,
) -> DivergenceModel {
    let edges = oracle::selected(graph, selection);
    let owners = modelled_owners(graph, analysis);
    let roots = modelled_roots(analysis);
    DivergenceModel {
        cohesion: modelled_cohesion(graph, (&owners, &roots), &edges),
        modularity: modelled_modularity(&owners, &edges),
        candidates: modelled_candidates(graph, &owners, &edges),
        boundary: modelled_boundary(graph, &owners, &edges),
    }
}

/// Each node's owning partition, by dense position.
fn modelled_owners(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> Vec<usize> {
    let partition = analysis.declared_partition();
    graph
        .nodes()
        .iter()
        .map(|node| {
            partition
                .owner(node.id())
                .unwrap_or_else(|| panic!("{} belongs to no partition", node.name()))
                .index() as usize
        })
        .collect()
}

/// Every partition root, by dense position.
fn modelled_roots(analysis: &GraphAnalysis<'_>) -> Vec<usize> {
    analysis
        .declared_partition()
        .roots()
        .iter()
        .map(|root| root.index() as usize)
        .collect()
}

/// Each root's internal and boundary counts, scanned from the raw selected
/// edges.
fn modelled_cohesion(
    graph: &CodeGraph,
    partition: (&[usize], &[usize]),
    edges: &[SelectedEdge],
) -> Vec<(String, u32, u32, Option<f64>)> {
    let (owners, roots) = partition;
    roots
        .iter()
        .map(|root| {
            let leaving = edges.iter().filter(|edge| owners[edge.source] == *root);
            let internal = leaving
                .clone()
                .filter(|edge| owners[edge.target] == *root)
                .count() as u32;
            let boundary = leaving.count() as u32 - internal;
            (
                named_position(graph, *root),
                internal,
                boundary,
                ratio(internal, internal + boundary),
            )
        })
        .collect()
}

/// One share of a total, or nothing at all when there is no total.
fn ratio(part: u32, total: u32) -> Option<f64> {
    match total {
        0 => None,
        _ => Some(f64::from(part) / f64::from(total)),
    }
}

/// Directed Newman modularity, as the literal sum over same-partition node
/// pairs.
fn modelled_modularity(owners: &[usize], edges: &[SelectedEdge]) -> Option<f64> {
    let stated = edges.len();
    match stated {
        0 => None,
        _ => Some(paired_sum(owners, edges, stated as f64) / stated as f64),
    }
}

/// The sum of `A_ij - k_out(i) * k_in(j) / m` over every same-partition pair.
fn paired_sum(owners: &[usize], edges: &[SelectedEdge], stated: f64) -> f64 {
    let degrees = oracle::degrees(owners.len(), edges);
    let mut summed = 0.0;
    for (source, target) in same_partition_pairs(owners) {
        let adjacency = edges
            .iter()
            .filter(|edge| edge.source == source && edge.target == target)
            .count() as f64;
        let expected = f64::from(degrees[source].1) * f64::from(degrees[target].0) / stated;
        summed += adjacency - expected;
    }
    summed
}

/// Every ordered pair of nodes declared in one partition.
fn same_partition_pairs(owners: &[usize]) -> Vec<(usize, usize)> {
    (0..owners.len())
        .flat_map(|source| (0..owners.len()).map(move |target| (source, target)))
        .filter(|(source, target)| owners[*source] == owners[*target])
        .collect()
}

/// Every symbol's foreign-partition calls, grouped by the partition they reach.
fn modelled_candidates(
    graph: &CodeGraph,
    owners: &[usize],
    edges: &[SelectedEdge],
) -> Vec<(String, String, String, u32, u32, f64)> {
    (0..owners.len())
        .filter(|at| is_symbol(graph, *at))
        .flat_map(|at| foreign_records(graph, (owners, edges), at))
        .collect()
}

/// Whether one node is a symbol an affinity record may name.
fn is_symbol(graph: &CodeGraph, at: usize) -> bool {
    let node = graph
        .node(given::node_at(graph, at))
        .unwrap_or_else(|| panic!("this graph holds no node at {at}"));
    matches!(
        node.kind(),
        GraphNodeKind::Function { .. } | GraphNodeKind::Type { .. } | GraphNodeKind::Value { .. }
    )
}

/// One symbol's records, one per foreign partition it calls into.
fn foreign_records(
    graph: &CodeGraph,
    selected: (&[usize], &[SelectedEdge]),
    at: usize,
) -> Vec<(String, String, String, u32, u32, f64)> {
    let (owners, edges) = selected;
    let leaving: Vec<&SelectedEdge> = edges.iter().filter(|edge| edge.source == at).collect();
    let mut foreign: BTreeMap<usize, u32> = BTreeMap::new();
    for edge in leaving
        .iter()
        .filter(|edge| owners[edge.target] != owners[at])
    {
        *foreign.entry(owners[edge.target]).or_default() += 1;
    }
    foreign
        .into_iter()
        .map(|(partition, count)| {
            (
                named_position(graph, at),
                named_position(graph, owners[at]),
                named_position(graph, partition),
                count,
                leaving.len() as u32,
                f64::from(count) / leaving.len() as f64,
            )
        })
        .collect()
}

/// Every component whose members are declared in more than one partition.
fn modelled_boundary(
    graph: &CodeGraph,
    owners: &[usize],
    edges: &[SelectedEdge],
) -> Vec<(String, String)> {
    oracle::components(owners.len(), edges)
        .into_iter()
        .filter_map(|members| crossing(graph, owners, &members))
        .collect()
}

/// One component's members and partitions, unless it sits in one partition.
fn crossing(graph: &CodeGraph, owners: &[usize], members: &[usize]) -> Option<(String, String)> {
    let partitions: BTreeSet<usize> = members.iter().map(|member| owners[*member]).collect();
    match partitions.len() > 1 {
        false => None,
        true => Some((
            named_positions(graph, members.iter().copied()),
            named_positions(graph, partitions.into_iter()),
        )),
    }
}

/// Every named node at the supplied dense positions, sorted and joined.
fn named_positions(graph: &CodeGraph, positions: impl Iterator<Item = usize>) -> String {
    sorted_join(positions.map(|at| named_position(graph, at)).collect())
}

/// The name of the node at one dense position.
fn named_position(graph: &CodeGraph, at: usize) -> String {
    given::name(graph, given::node_at(graph, at))
}
