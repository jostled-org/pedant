//! Independent models of every derived answer, computed from the raw graph.
//!
//! Nothing here reads an analysis index, a component table, or a centrality
//! result. Each model is a second, slower statement of the same rule taken
//! straight from `CodeGraph::edges()`, so a case that compares the two is
//! comparing two implementations rather than one implementation with itself.
//!
//! The betweenness model enumerates shortest routes one edge at a time and
//! divides by how many it found. That is the definition Brandes accelerates,
//! written without its predecessor stacks or dependency accumulation, and it is
//! affordable only because every corpus compared against it is small.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pedant_graph::{CodeGraph, GraphEdgeId, GraphEdgeSelection};

/// One selected edge as the models read it: dense endpoints and raw identity.
#[derive(Clone, Copy, Debug)]
pub struct SelectedEdge {
    /// The node the edge leaves.
    pub source: usize,
    /// The node the edge reaches.
    pub target: usize,
    /// The raw identity the graph minted for it.
    pub id: GraphEdgeId,
}

/// One coalesced pair of components and the raw edges between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondensationPair {
    /// The component the edges leave.
    pub source: usize,
    /// The component the edges reach.
    pub target: usize,
    /// Every raw edge between that ordered pair, in raw id order.
    pub edges: Vec<GraphEdgeId>,
}

/// Every edge one selection admits, scanned straight from the raw graph.
pub fn selected(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<SelectedEdge> {
    graph
        .edges()
        .iter()
        .filter(|edge| selection.allows(edge))
        .map(|edge| SelectedEdge {
            source: edge.source().index() as usize,
            target: edge.target().index() as usize,
            id: edge.id(),
        })
        .collect()
}

/// Each node's incoming and outgoing selected edge counts, in node order.
///
/// Every edge is counted once at each end, so parallel edges count separately
/// and a self-loop counts once incoming and once outgoing.
pub fn degrees(nodes: usize, edges: &[SelectedEdge]) -> Vec<(u32, u32)> {
    let mut counted = vec![(0u32, 0u32); nodes];
    for edge in edges {
        counted[edge.target].0 += 1;
        counted[edge.source].1 += 1;
    }
    counted
}

/// Every node's raw betweenness, by enumerating shortest routes.
///
/// For each ordered pair of distinct nodes the model lists every shortest route
/// between them, one entry per distinct edge sequence, and credits each interior
/// node with its share. Endpoints are never credited.
pub fn raw_betweenness(nodes: usize, edges: &[SelectedEdge]) -> Vec<f64> {
    let adjacency = outgoing(nodes, edges);
    let mut scores = vec![0.0f64; nodes];
    for source in 0..nodes {
        let distance = distances(&adjacency, nodes, source);
        credit_routes(&adjacency, &distance, source, &mut scores);
    }
    scores
}

/// Credit every interior node of every shortest route leaving one source.
fn credit_routes(
    adjacency: &[Vec<usize>],
    distance: &[Option<usize>],
    source: usize,
    scores: &mut [f64],
) {
    for target in 0..scores.len() {
        let steps = match (target == source, distance[target]) {
            (false, Some(steps)) => steps,
            _ => continue,
        };
        let routes = shortest_routes(adjacency, distance, source, (target, steps));
        let share = 1.0 / routes.len() as f64;
        for route in &routes {
            credit_interior(route, share, scores);
        }
    }
}

/// Credit every node one route passes through, which is every node but its two
/// endpoints.
fn credit_interior(route: &[usize], share: f64, scores: &mut [f64]) {
    for node in &route[1..route.len() - 1] {
        scores[*node] += share;
    }
}

/// Every shortest route from one source to one target, as node sequences.
///
/// A route grows one edge at a time and only along edges that shorten the
/// remaining distance, so a walk of exactly the measured length that ends at the
/// target is a shortest route and every such route is listed once per distinct
/// edge sequence.
fn shortest_routes(
    adjacency: &[Vec<usize>],
    distance: &[Option<usize>],
    source: usize,
    reached: (usize, usize),
) -> Vec<Vec<usize>> {
    let (target, steps) = reached;
    let mut routes: Vec<Vec<usize>> = vec![vec![source]];
    for _ in 0..steps {
        routes = routes
            .iter()
            .flat_map(|route| extended(adjacency, distance, route))
            .collect();
    }
    routes.retain(|route| route.last() == Some(&target));
    routes
}

/// Every one-edge extension of one route that stays on a shortest path.
fn extended(
    adjacency: &[Vec<usize>],
    distance: &[Option<usize>],
    route: &[usize],
) -> Vec<Vec<usize>> {
    let last = route[route.len() - 1];
    let next = distance[last].map(|steps| steps + 1);
    adjacency[last]
        .iter()
        .filter(|reached| distance[**reached] == next)
        .map(|reached| {
            let mut grown = route.to_vec();
            grown.push(*reached);
            grown
        })
        .collect()
}

/// The directed normalization divisor's answer for one raw score.
///
/// Fewer than three nodes leaves no ordered pair a third node could sit
/// between, so the normalized score is zero rather than a division.
pub fn normalized(nodes: usize, raw: f64) -> f64 {
    match nodes > 2 {
        true => raw / ((nodes - 1) as f64 * (nodes - 2) as f64),
        false => 0.0,
    }
}

/// Every strongly connected component, members sorted, ordered by smallest
/// member.
///
/// Membership is read from mutual reachability alone, which is the definition
/// rather than any particular traversal, so a component result computed by a
/// different algorithm can be compared against it.
pub fn components(nodes: usize, edges: &[SelectedEdge]) -> Vec<Vec<usize>> {
    let forward = outgoing(nodes, edges);
    let backward = incoming(nodes, edges);
    let mut assigned: Vec<bool> = vec![false; nodes];
    let mut found: Vec<Vec<usize>> = Vec::new();
    for node in 0..nodes {
        let members = match assigned[node] {
            true => continue,
            false => mutual(&forward, &backward, nodes, node),
        };
        for member in &members {
            assigned[*member] = true;
        }
        found.push(members);
    }
    found
}

/// Every node mutually reachable with one node, including itself, sorted.
fn mutual(
    forward: &[Vec<usize>],
    backward: &[Vec<usize>],
    nodes: usize,
    node: usize,
) -> Vec<usize> {
    let ahead = distances(forward, nodes, node);
    let behind = distances(backward, nodes, node);
    (0..nodes)
        .filter(|other| ahead[*other].is_some() && behind[*other].is_some())
        .collect()
}

/// Whether one component is cyclic: more than one member, or a self-loop.
pub fn is_cyclic(members: &[usize], edges: &[SelectedEdge]) -> bool {
    members.len() > 1
        || edges
            .iter()
            .any(|edge| edge.source == edge.target && members.contains(&edge.source))
}

/// Each node's component position, indexed by node.
pub fn assignment(nodes: usize, components: &[Vec<usize>]) -> Vec<usize> {
    let mut placed = vec![0usize; nodes];
    for (at, members) in components.iter().enumerate() {
        for member in members {
            placed[*member] = at;
        }
    }
    placed
}

/// Every inter-component edge, coalesced by ordered component pair and sorted.
pub fn condensation(assignment: &[usize], edges: &[SelectedEdge]) -> Vec<CondensationPair> {
    let mut coalesced: BTreeMap<(usize, usize), Vec<GraphEdgeId>> = BTreeMap::new();
    for edge in edges {
        let pair = (assignment[edge.source], assignment[edge.target]);
        match pair.0 == pair.1 {
            true => continue,
            false => coalesced.entry(pair).or_default().push(edge.id),
        }
    }
    coalesced
        .into_iter()
        .map(|((source, target), mut edges)| {
            edges.sort_unstable();
            CondensationPair {
                source,
                target,
                edges,
            }
        })
        .collect()
}

/// The topological order of one condensation, least ready component first.
pub fn topological_order(count: usize, pairs: &[CondensationPair]) -> Vec<usize> {
    let mut indegree = vec![0usize; count];
    for pair in pairs {
        indegree[pair.target] += 1;
    }
    let mut ready: BTreeSet<usize> = (0..count).filter(|at| indegree[*at] == 0).collect();
    let mut ordered: Vec<usize> = Vec::new();
    while let Some(least) = ready.iter().copied().next() {
        ready.remove(&least);
        ordered.push(least);
        release(pairs, least, (&mut indegree, &mut ready));
    }
    ordered
}

/// Drop the indegree of every component one consumed component points at.
fn release(
    pairs: &[CondensationPair],
    consumed: usize,
    state: (&mut [usize], &mut BTreeSet<usize>),
) {
    let (indegree, ready) = state;
    for pair in pairs.iter().filter(|pair| pair.source == consumed) {
        indegree[pair.target] -= 1;
        match indegree[pair.target] == 0 {
            true => ready.insert(pair.target),
            false => false,
        };
    }
}

/// The selected edges leaving each node, as the nodes they reach.
fn outgoing(nodes: usize, edges: &[SelectedEdge]) -> Vec<Vec<usize>> {
    let mut lists = vec![Vec::new(); nodes];
    for edge in edges {
        lists[edge.source].push(edge.target);
    }
    lists
}

/// The selected edges entering each node, as the nodes they leave.
fn incoming(nodes: usize, edges: &[SelectedEdge]) -> Vec<Vec<usize>> {
    let mut lists = vec![Vec::new(); nodes];
    for edge in edges {
        lists[edge.target].push(edge.source);
    }
    lists
}

/// How many steps reach each node from one seed, over one adjacency.
fn distances(adjacency: &[Vec<usize>], nodes: usize, seed: usize) -> Vec<Option<usize>> {
    let mut measured: Vec<Option<usize>> = vec![None; nodes];
    let mut queue: VecDeque<usize> = VecDeque::new();
    measured[seed] = Some(0);
    queue.push_back(seed);
    while let Some(node) = queue.pop_front() {
        let step = measured[node].unwrap_or(0) + 1;
        for reached in &adjacency[node] {
            match measured[*reached] {
                Some(_) => continue,
                None => measured[*reached] = Some(step),
            }
            queue.push_back(*reached);
        }
    }
    measured
}
