//! How much of the selected topology's shortest routing passes through each
//! node.
//!
//! One bounded directed Brandes pass over the shared selected indexes. It is the
//! only superlinear operation this crate offers, so it proves its own work bound
//! before it allocates any state, and it walks iteratively so a repository's own
//! depth cannot reach the stack.
//!
//! The selected topology is a multigraph: two parallel edges are two distinct
//! shortest routes, and both contribute to the share of every node they pass
//! through.

use std::collections::VecDeque;

use crate::id::{GraphNodeId, index_of, position};

use super::error::GraphAnalysisError;
use super::index::{GraphAnalysis, SelectedIndexes};
use super::limits::GraphAnalysisLimits;

/// How much of the selected topology's shortest routing passes through one
/// node.
///
/// The raw score sums, over every ordered pair of other nodes, the fraction of
/// that pair's shortest routes this node sits inside. The normalized score
/// divides it by how many such pairs a graph this size can state at all.
#[derive(Clone, Copy, Debug)]
pub struct BetweennessCentrality {
    node: GraphNodeId,
    raw: f64,
    normalized: f64,
}

impl BetweennessCentrality {
    /// The node this score describes.
    pub fn node(self) -> GraphNodeId {
        self.node
    }

    /// The summed share of shortest routes passing through it.
    pub fn raw(self) -> f64 {
        self.raw
    }

    /// That share against every ordered pair a graph this size can state, or
    /// zero when it can state none.
    pub fn normalized(self) -> f64 {
        self.normalized
    }
}

/// The buffers one bounded pass mutates from its first source to its last.
///
/// Each round clears what it needs rather than allocating again, so a pass over
/// an admitted graph pays for its state once. Every node-indexed table is sized
/// once and only its elements move, so only `order`, `queue`, and one node's
/// predecessor list are `Vec`; the scores the pass produces are sealed on the
/// way out.
struct Brandes {
    totals: Box<[f64]>,
    distance: Box<[Option<u32>]>,
    routes: Box<[f64]>,
    predecessors: Box<[Vec<GraphNodeId>]>,
    share: Box<[f64]>,
    order: Vec<GraphNodeId>,
    queue: VecDeque<GraphNodeId>,
}

impl Brandes {
    /// One pass's state over a topology of `width` nodes.
    fn empty(width: usize) -> Self {
        Self {
            totals: vec![0.0; width].into_boxed_slice(),
            distance: vec![None; width].into_boxed_slice(),
            routes: vec![0.0; width].into_boxed_slice(),
            predecessors: vec![Vec::new(); width].into_boxed_slice(),
            share: vec![0.0; width].into_boxed_slice(),
            order: Vec::with_capacity(width),
            queue: VecDeque::new(),
        }
    }

    /// Run one round per source, in raw node-id order.
    fn walk(&mut self, indexes: &SelectedIndexes) {
        for at in 0..self.totals.len() {
            self.round(indexes, GraphNodeId::new(position(at)));
        }
    }

    /// Measure one source's shortest routes, then credit what they pass
    /// through.
    fn round(&mut self, indexes: &SelectedIndexes, source: GraphNodeId) {
        self.restart(source);
        self.measure(indexes);
        self.credit(source);
    }

    /// Clear every round-local buffer and settle the source at distance zero.
    ///
    /// A source reaches itself by exactly one route and arrives from nothing,
    /// which is what makes every later count a count of routes from it.
    fn restart(&mut self, source: GraphNodeId) {
        self.distance.iter_mut().for_each(|steps| *steps = None);
        self.routes.iter_mut().for_each(|routes| *routes = 0.0);
        self.share.iter_mut().for_each(|share| *share = 0.0);
        self.predecessors.iter_mut().for_each(Vec::clear);
        self.order.clear();
        self.queue.clear();
        self.settle(source, 0);
        add(&mut self.routes, source, 1.0);
    }

    /// Follow every settled node's edges until nothing is left to settle.
    fn measure(&mut self, indexes: &SelectedIndexes) {
        while let Some(node) = self.queue.pop_front() {
            self.relax(indexes, node);
        }
    }

    /// Extend one settled node's routes along every selected edge leaving it.
    fn relax(&mut self, indexes: &SelectedIndexes, node: GraphNodeId) {
        let next = match self.steps(node) {
            Some(steps) => steps + 1,
            None => return,
        };
        for entry in indexes.outgoing(node) {
            self.follow((node, entry.node()), next);
        }
    }

    /// Follow one selected edge into the node it reaches.
    ///
    /// A node reached for the first time settles here. A node already settled at
    /// this distance gains another route, which is how a parallel edge and a
    /// merging branch each count once. Anything nearer is already behind.
    fn follow(&mut self, step: (GraphNodeId, GraphNodeId), next: u32) {
        let (from, reached) = step;
        match self.steps(reached) {
            None => self.settle(reached, next),
            Some(steps) if steps == next => (),
            Some(_) => return,
        }
        self.join(reached, from);
    }

    /// Record one node as first reached, at `steps` steps, and queue it.
    ///
    /// A node this pass does not address settles nowhere: recording it would put
    /// it on the walk once per arriving edge, because nothing would ever answer
    /// that it had already been reached.
    fn settle(&mut self, node: GraphNodeId, steps: u32) {
        match self.distance.get_mut(index_of(node.index())) {
            Some(slot) => *slot = Some(steps),
            None => return,
        }
        self.order.push(node);
        self.queue.push_back(node);
    }

    /// Record every route into `node` that arrives from `from`.
    fn join(&mut self, node: GraphNodeId, from: GraphNodeId) {
        let arriving = held(&self.routes, from);
        add(&mut self.routes, node, arriving);
        if let Some(list) = self.predecessors.get_mut(index_of(node.index())) {
            list.push(from);
        }
    }

    /// How many selected steps reach one node in the current round.
    fn steps(&self, node: GraphNodeId) -> Option<u32> {
        self.distance.get(index_of(node.index())).copied().flatten()
    }

    /// Credit every node the current round's shortest routes pass through.
    ///
    /// Nodes settle in reverse discovery order, so a node's own share is
    /// complete before it is passed back to the nodes its routes arrive from.
    fn credit(&mut self, source: GraphNodeId) {
        let Self {
            totals,
            routes,
            predecessors,
            share,
            order,
            ..
        } = self;
        for node in order.iter().rev() {
            pass_back((&routes[..], &predecessors[..]), share, *node);
            award((totals, &share[..]), source, *node);
        }
    }

    /// Every accumulated score beside its normalization, in raw node-id order.
    fn scored(self) -> Box<[BetweennessCentrality]> {
        let pairs = ordered_pairs(self.totals.len());
        self.totals
            .iter()
            .enumerate()
            .map(|(at, score)| BetweennessCentrality {
                node: GraphNodeId::new(position(at)),
                raw: *score,
                normalized: against(*score, pairs),
            })
            .collect()
    }
}

/// Every node's betweenness over the selected topology, in raw node-id order.
///
/// The work bound is proved first, so a graph beyond the caller's budget costs
/// two counts rather than a table for every node.
pub(crate) fn betweenness(
    analysis: &GraphAnalysis<'_>,
) -> Result<Box<[BetweennessCentrality]>, GraphAnalysisError> {
    let indexes = analysis.indexes();
    admitted_work(indexes, analysis.limits())?;
    let mut pass = Brandes::empty(indexes.node_count());
    pass.walk(indexes);
    Ok(pass.scored())
}

/// The work one pass would cost, proved against the stated ceiling.
///
/// One breadth-first round per node costs the node and selected-edge counts
/// together. Both are admitted fixed-width counts, so their product can still
/// overshoot the width it is counted in; the arithmetic is checked and refuses
/// rather than wrapping into a bound that would pass.
fn admitted_work(
    indexes: &SelectedIndexes,
    limits: GraphAnalysisLimits,
) -> Result<(), GraphAnalysisError> {
    let nodes = u64::from(position(indexes.node_count()));
    let required = nodes
        .checked_add(u64::from(indexes.selected_edges()))
        .and_then(|round| nodes.checked_mul(round))
        .ok_or(GraphAnalysisError::BetweennessWorkOverflow)?;
    match required <= limits.max_betweenness_work() {
        true => Ok(()),
        false => Err(GraphAnalysisError::BetweennessWorkLimitExceeded {
            required,
            limit: limits.max_betweenness_work(),
        }),
    }
}

/// Pass one node's share back to every node its shortest routes arrive from.
fn pass_back(reached: (&[f64], &[Vec<GraphNodeId>]), share: &mut [f64], node: GraphNodeId) {
    let (routes, predecessors) = reached;
    let carried = (1.0 + held(share, node)) / held(routes, node);
    for from in entering(predecessors, node) {
        add(share, *from, held(routes, *from) * carried);
    }
}

/// Credit one node with its own share, unless it is the source it came from.
fn award(state: (&mut [f64], &[f64]), source: GraphNodeId, node: GraphNodeId) {
    let (totals, share) = state;
    match node == source {
        true => (),
        false => add(totals, node, held(share, node)),
    }
}

/// The nodes one node's shortest routes arrive from, one entry per route.
fn entering(predecessors: &[Vec<GraphNodeId>], node: GraphNodeId) -> &[GraphNodeId] {
    match predecessors.get(index_of(node.index())) {
        Some(list) => list,
        None => &[],
    }
}

/// The value one node holds, or nothing at all for a node outside the table.
fn held(values: &[f64], node: GraphNodeId) -> f64 {
    values
        .get(index_of(node.index()))
        .copied()
        .unwrap_or_default()
}

/// Add one amount to the value a node holds.
fn add(values: &mut [f64], node: GraphNodeId, amount: f64) {
    if let Some(slot) = values.get_mut(index_of(node.index())) {
        *slot += amount;
    }
}

/// How many ordered pairs a graph this size states that a third node could sit
/// between, or nothing at all when it states none.
fn ordered_pairs(nodes: usize) -> Option<f64> {
    match nodes > 2 {
        true => Some((nodes - 1) as f64 * (nodes - 2) as f64),
        false => None,
    }
}

/// One raw score against the ordered pairs it could have come from.
fn against(raw: f64, pairs: Option<f64>) -> f64 {
    match pairs {
        Some(count) => raw / count,
        None => 0.0,
    }
}
