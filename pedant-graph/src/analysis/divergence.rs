//! Where the declared module tree and the selected topology disagree.
//!
//! Every answer here is evidence rather than judgment: how much of a partition's
//! traffic stays inside it, how far the whole partition sits from what the
//! selected edges suggest, which symbols call somewhere else, and which cycles
//! run through more than one partition. No threshold is applied, no verdict is
//! stated, and no other partition is searched for.
//!
//! The partition is derived once, during analysis construction. The counts come
//! from the same shared adjacency lists every other query reads, the degrees
//! from the one module that measures them, and the cycles from the one module
//! that discovers them.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::CodeGraph;
use crate::id::{GraphNodeId, position};
use crate::node::GraphNodeKind;

use super::components::{self, GraphComponent, GraphComponentId, GraphComponents};
use super::degree::{self, DegreeCentrality};
use super::index::{GraphAnalysis, SelectedAdjacency, SelectedIndexes};
use super::partition::DeclaredModulePartition;

/// How much of one partition's outgoing traffic stays inside it.
#[derive(Clone, Copy, Debug)]
pub struct ModuleCohesion {
    root: GraphNodeId,
    internal: u32,
    boundary: u32,
    score: Option<f64>,
}

impl ModuleCohesion {
    /// The partition root these counts describe.
    pub fn root(self) -> GraphNodeId {
        self.root
    }

    /// How many selected edges leave a member for another member.
    pub fn internal_edges(self) -> u32 {
        self.internal
    }

    /// How many selected edges leave a member for another partition.
    pub fn boundary_edges(self) -> u32 {
        self.boundary
    }

    /// The internal share of both counts, or nothing at all when no selected
    /// edge leaves this partition.
    pub fn score(self) -> Option<f64> {
        self.score
    }
}

/// One symbol's selected edges into one partition other than its own.
///
/// Evidence, not a verdict: the record states how many of the symbol's selected
/// edges reach that partition and how many leave it at all, and leaves what to
/// do about it to a consumer that owns a policy.
///
/// Which relations count is the caller's selection to state, so every edge the
/// selection admitted is counted rather than calls alone.
#[derive(Clone, Copy, Debug)]
pub struct MisplacementCandidate {
    symbol: GraphNodeId,
    declared: GraphNodeId,
    candidate: GraphNodeId,
    foreign: u32,
    total: u32,
    affinity: f64,
}

impl MisplacementCandidate {
    /// The symbol whose selected edges this record counts.
    pub fn symbol(self) -> GraphNodeId {
        self.symbol
    }

    /// The partition that declares it.
    pub fn declared_partition(self) -> GraphNodeId {
        self.declared
    }

    /// The other partition its selected edges reach.
    pub fn candidate_partition(self) -> GraphNodeId {
        self.candidate
    }

    /// How many of its selected edges reach that partition.
    pub fn foreign_edges(self) -> u32 {
        self.foreign
    }

    /// How many selected edges leave it at all.
    pub fn total_outgoing_edges(self) -> u32 {
        self.total
    }

    /// The share of its selected edges that partition takes.
    pub fn affinity(self) -> f64 {
        self.affinity
    }
}

/// One cycle whose members are declared in more than one partition.
#[derive(Debug)]
pub struct BoundaryCrossingComponent {
    component: GraphComponentId,
    partitions: Box<[GraphNodeId]>,
}

impl BoundaryCrossingComponent {
    /// The component this evidence names.
    pub fn component(&self) -> GraphComponentId {
        self.component
    }

    /// Every partition its members are declared in, in root-id order.
    pub fn partitions(&self) -> &[GraphNodeId] {
        &self.partitions
    }
}

/// What one selected topology says about the partition its graph declares.
#[derive(Debug)]
pub struct GraphDivergence {
    cohesion: Box<[ModuleCohesion]>,
    modularity: Option<f64>,
    candidates: Box<[MisplacementCandidate]>,
    boundary: Box<[BoundaryCrossingComponent]>,
}

impl GraphDivergence {
    /// Every partition's cohesion, in root-id order.
    pub fn cohesion(&self) -> &[ModuleCohesion] {
        &self.cohesion
    }

    /// The directed Newman modularity of the declared partition, or nothing at
    /// all when the selection admits no edge.
    pub fn modularity(&self) -> Option<f64> {
        self.modularity
    }

    /// Every symbol's foreign-partition calls, by symbol then candidate.
    pub fn candidates(&self) -> &[MisplacementCandidate] {
        &self.candidates
    }

    /// Every cycle that runs through more than one partition, in component
    /// order.
    pub fn boundary_components(&self) -> &[BoundaryCrossingComponent] {
        &self.boundary
    }
}

/// What the selected topology says about the declared partition.
///
/// Infallible for an admitted analysis: every count is bounded by the admitted
/// edge count, and the modularity converts those bounded counts to `f64` before
/// it multiplies them.
pub(crate) fn divergence(analysis: &GraphAnalysis<'_>) -> GraphDivergence {
    let indexes = analysis.indexes();
    let partition = analysis.declared_partition();
    let cohesion = measured(indexes, partition);
    let summed = totals(&degree::degree(analysis), partition);
    GraphDivergence {
        modularity: modularity(&cohesion, &summed, indexes.selected_edges()),
        candidates: candidates(analysis.graph(), indexes, partition),
        boundary: crossings(&components::discover(analysis), partition),
        cohesion,
    }
}

/// Each partition's internal and boundary counts, in root-id order.
fn measured(
    indexes: &SelectedIndexes,
    partition: &DeclaredModulePartition,
) -> Box<[ModuleCohesion]> {
    let mut counted: BTreeMap<GraphNodeId, (u32, u32)> = empty_counts(partition.roots());
    for (at, owner) in partition.owners().iter().enumerate() {
        let node = GraphNodeId::new(position(at));
        if let Some(pair) = counted.get_mut(owner) {
            record(pair, *owner, indexes.outgoing(node), partition);
        }
    }
    counted.into_iter().map(stated_cohesion).collect()
}

/// One zeroed count per partition root.
fn empty_counts(roots: &[GraphNodeId]) -> BTreeMap<GraphNodeId, (u32, u32)> {
    roots.iter().map(|root| (*root, (0, 0))).collect()
}

/// Count one node's selected edges inside its own partition, or leaving it.
///
/// The partition's counter is resolved once per node rather than once per edge,
/// because every edge leaving one node leaves the same partition.
fn record(
    counted: &mut (u32, u32),
    owner: GraphNodeId,
    leaving: &[SelectedAdjacency],
    partition: &DeclaredModulePartition,
) {
    for entry in leaving {
        match partition.owner(entry.node()) == Some(owner) {
            true => counted.0 += 1,
            false => counted.1 += 1,
        }
    }
}

/// One partition's counts as its cohesion record.
fn stated_cohesion(counted: (GraphNodeId, (u32, u32))) -> ModuleCohesion {
    let (root, (internal, boundary)) = counted;
    ModuleCohesion {
        root,
        internal,
        boundary,
        score: share(internal, internal + boundary),
    }
}

/// One share of a total, or nothing at all when there is no total.
fn share(part: u32, total: u32) -> Option<f64> {
    match total {
        0 => None,
        _ => Some(f64::from(part) / f64::from(total)),
    }
}

/// Each partition's total outgoing and incoming selected degree, in root-id
/// order.
///
/// Both are summed as `f64` before anything multiplies them, so a partition of a
/// repository-sized graph cannot overflow the product the modularity takes.
fn totals(degrees: &[DegreeCentrality], partition: &DeclaredModulePartition) -> Box<[(f64, f64)]> {
    let mut summed: BTreeMap<GraphNodeId, (f64, f64)> = partition
        .roots()
        .iter()
        .map(|root| (*root, (0.0, 0.0)))
        .collect();
    for (owner, degree) in partition.owners().iter().zip(degrees) {
        accumulate(&mut summed, *owner, *degree);
    }
    summed.into_values().collect()
}

/// Add one node's degrees to the partition that declares it.
fn accumulate(
    summed: &mut BTreeMap<GraphNodeId, (f64, f64)>,
    owner: GraphNodeId,
    degree: DegreeCentrality,
) {
    if let Some(pair) = summed.get_mut(&owner) {
        pair.0 += f64::from(degree.outgoing());
        pair.1 += f64::from(degree.incoming());
    }
}

/// The directed modularity of the declared partition, or nothing at all when no
/// edge was selected.
fn modularity(cohesion: &[ModuleCohesion], summed: &[(f64, f64)], edges: u32) -> Option<f64> {
    match edges {
        0 => None,
        _ => Some(newman(cohesion, summed, f64::from(edges))),
    }
}

/// `Q = (1 / m) * sum(A_ij - k_out(i) * k_in(j) / m)` over same-partition pairs.
///
/// Every same-partition pair with an edge between it is counted by that
/// partition's internal count, and the expected term factors into one product
/// per partition, so the sum is taken over the partitions rather than over every
/// pair of nodes.
fn newman(cohesion: &[ModuleCohesion], summed: &[(f64, f64)], edges: f64) -> f64 {
    let internal: f64 = cohesion
        .iter()
        .map(|stated| f64::from(stated.internal))
        .sum();
    let expected: f64 = summed
        .iter()
        .map(|(leaving, arriving)| leaving * arriving)
        .sum();
    internal / edges - expected / (edges * edges)
}

/// Every symbol's foreign-partition calls, by symbol then candidate partition.
fn candidates(
    graph: &CodeGraph,
    indexes: &SelectedIndexes,
    partition: &DeclaredModulePartition,
) -> Box<[MisplacementCandidate]> {
    graph
        .nodes()
        .iter()
        .filter(|node| is_symbol(node.kind()))
        .flat_map(|node| foreign(indexes, partition, node.id()))
        .collect()
}

/// Whether one node is a symbol an affinity record may name.
///
/// A file, a unit root, or a module is where symbols are declared rather than
/// something that could be declared somewhere else. The match names every kind
/// the vocabulary states, so a kind added to it has to be classified here rather
/// than silently falling out of every affinity answer.
fn is_symbol(kind: &GraphNodeKind) -> bool {
    match kind {
        GraphNodeKind::Function { .. }
        | GraphNodeKind::Type { .. }
        | GraphNodeKind::Value { .. } => true,
        GraphNodeKind::File | GraphNodeKind::Container { .. } => false,
    }
}

/// One symbol's records, one per partition its selected calls reach beyond its
/// own.
fn foreign<'a>(
    indexes: &'a SelectedIndexes,
    partition: &'a DeclaredModulePartition,
    symbol: GraphNodeId,
) -> impl Iterator<Item = MisplacementCandidate> + 'a {
    partition
        .owner(symbol)
        .into_iter()
        .flat_map(move |declared| reaching(indexes, partition, (symbol, declared)))
}

/// One declared symbol's records, one per partition its selected calls reach
/// beyond its own.
///
/// The count of calls it makes at all is read once, before the records that
/// divide by it.
fn reaching(
    indexes: &SelectedIndexes,
    partition: &DeclaredModulePartition,
    declaration: (GraphNodeId, GraphNodeId),
) -> impl Iterator<Item = MisplacementCandidate> {
    let (symbol, declared) = declaration;
    let leaving = indexes.outgoing(symbol);
    let total = position(leaving.len());
    let mut reached: BTreeMap<GraphNodeId, u32> = BTreeMap::new();
    for entry in leaving {
        claim(&mut reached, partition.owner(entry.node()), declared);
    }
    reached
        .into_iter()
        .map(move |found| stated_candidate((symbol, declared), found, total))
}

/// Count one selected edge that leaves its symbol's own partition.
fn claim(
    reached: &mut BTreeMap<GraphNodeId, u32>,
    owner: Option<GraphNodeId>,
    declared: GraphNodeId,
) {
    match owner {
        Some(found) if found != declared => *reached.entry(found).or_insert(0) += 1,
        _ => (),
    }
}

/// One symbol's calls into one other partition, as its affinity record.
fn stated_candidate(
    declaration: (GraphNodeId, GraphNodeId),
    reached: (GraphNodeId, u32),
    total: u32,
) -> MisplacementCandidate {
    let (symbol, declared) = declaration;
    let (candidate, foreign) = reached;
    MisplacementCandidate {
        symbol,
        declared,
        candidate,
        foreign,
        total,
        affinity: f64::from(foreign) / f64::from(total),
    }
}

/// Every component whose members are declared in more than one partition.
fn crossings(
    components: &GraphComponents,
    partition: &DeclaredModulePartition,
) -> Box<[BoundaryCrossingComponent]> {
    components
        .components()
        .iter()
        .filter_map(|component| crossing(component, partition))
        .collect()
}

/// One component's evidence, unless every member is declared in one partition.
fn crossing(
    component: &GraphComponent,
    partition: &DeclaredModulePartition,
) -> Option<BoundaryCrossingComponent> {
    let partitions: BTreeSet<GraphNodeId> = component
        .members()
        .iter()
        .filter_map(|member| partition.owner(*member))
        .collect();
    match partitions.len() > 1 {
        false => None,
        true => Some(BoundaryCrossingComponent {
            component: component.id(),
            partitions: partitions.into_iter().collect(),
        }),
    }
}
