//! The arguments a cached-analysis case asks over, and the text every answer is
//! compared as.
//!
//! A borrowed analysis and a cached handle own their answers differently and
//! must answer identically. The operations, the order they are asked in, and
//! the rendering each answer is compared through are written down once here, so
//! a case states only what it is comparing and two readings differ exactly
//! where an answer does.

use pedant_graph::{
    CachedGraphAnalysis, CodeGraph, CondensationGraph, DeclaredModulePartition, GraphAnalysis,
    GraphAnalysisError, GraphComponents, GraphDirection, GraphDivergence, GraphNodeId, GraphPath,
    GraphSubgraph, LayoutAssistMetadata,
};

use super::analysis_fixture::{
    betweenness_texts, boundary_texts, candidate_texts, cohesion_texts, component_texts,
    condensation_texts, degree_texts, edge_texts, layout_edge_texts, layout_node_texts,
    membership_texts, name, names, neighbor_texts, optional_bits, optional_name,
};

/// One traversal, stated once and asked of both analyses.
#[derive(Clone, Copy)]
pub struct Walk {
    node: GraphNodeId,
    depth: u32,
    direction: GraphDirection,
}

impl Walk {
    /// One walk leaving `node`, taking `depth` selected steps along
    /// `direction`.
    pub fn new(node: GraphNodeId, depth: u32, direction: GraphDirection) -> Self {
        Self {
            node,
            depth,
            direction,
        }
    }

    /// This walk, named by its arguments.
    fn label(self, operation: &str) -> String {
        format!(
            "{operation}|{}|{}|{:?}",
            self.node.index(),
            self.depth,
            self.direction
        )
    }
}

/// Every argument the traversal operations are exercised over.
pub struct Asked {
    walks: Box<[Walk]>,
    routes: Box<[(GraphNodeId, GraphNodeId)]>,
}

impl Asked {
    /// Walks and routes spanning the first nodes of one graph, at every
    /// direction and at three depths.
    pub fn over(graph: &CodeGraph) -> Self {
        let held: Box<[GraphNodeId]> = graph.nodes().iter().map(|node| node.id()).take(6).collect();
        let directions = [
            GraphDirection::Outgoing,
            GraphDirection::Incoming,
            GraphDirection::Both,
        ];
        let walks = held
            .iter()
            .flat_map(|node| {
                directions.iter().flat_map(move |direction| {
                    [0_u32, 1, 3]
                        .iter()
                        .map(move |depth| Walk::new(*node, *depth, *direction))
                })
            })
            .collect();
        let routes = ordered_pairs(&held).collect();
        Self { walks, routes }
    }

    /// One walk and one route, as the arguments of a single-row comparison.
    pub fn one(walk: Walk, route: (GraphNodeId, GraphNodeId)) -> Self {
        Self {
            walks: Box::new([walk]),
            routes: Box::new([route]),
        }
    }
}

/// One analysis, however it owns the answers it gives.
///
/// The seam that lets one reading serve both analyses. Every method renders one
/// operation, so the owning type an answer arrives in stays inside the
/// implementation and never reaches a case.
pub trait AnalysisReading {
    /// The graph every identity an answer states indexes back into.
    fn read_graph(&self) -> &CodeGraph;

    /// The declared module partition this analysis settled.
    fn read_partition(&self) -> &DeclaredModulePartition;

    /// One bounded neighborhood, or the refusal it took.
    fn neighbor_row(&self, walk: Walk) -> String;

    /// One induced selection, or the refusal it took.
    fn subgraph_row(&self, walk: Walk) -> String;

    /// One shortest route, the proven absence of one, or the refusal it took.
    fn route_row(&self, route: (GraphNodeId, GraphNodeId)) -> String;

    /// The components, the condensation, and the divergence this analysis
    /// states.
    fn derived_rows(&self) -> Vec<(String, String)>;

    /// Every node's selected degrees.
    fn degree_row(&self) -> String;

    /// Every node's directed betweenness, or the refusal it took.
    fn betweenness_row(&self) -> String;

    /// The coordinate-free layout metadata, or the refusal it took.
    fn layout_row(&self) -> String;
}

impl AnalysisReading for GraphAnalysis<'_> {
    fn read_graph(&self) -> &CodeGraph {
        self.graph()
    }

    fn read_partition(&self) -> &DeclaredModulePartition {
        self.declared_partition()
    }

    fn neighbor_row(&self, walk: Walk) -> String {
        answered(
            self.neighbors(walk.node, walk.depth, walk.direction),
            |held| neighbor_texts(self.graph(), &held).join(","),
        )
    }

    fn subgraph_row(&self, walk: Walk) -> String {
        answered(
            self.subgraph(walk.node, walk.depth, walk.direction),
            |held| subgraph_text(self.graph(), &held),
        )
    }

    fn route_row(&self, route: (GraphNodeId, GraphNodeId)) -> String {
        answered(self.path(route.0, route.1), |held| {
            optional_route_text(self.graph(), held.as_ref())
        })
    }

    fn derived_rows(&self) -> Vec<(String, String)> {
        derived_rows(
            self.graph(),
            (
                &self.strongly_connected_components(),
                &self.condensation(),
                &self.divergence(),
            ),
        )
    }

    fn degree_row(&self) -> String {
        degree_texts(self.graph(), &self.degree_centrality()).join(",")
    }

    fn betweenness_row(&self) -> String {
        answered(self.betweenness_centrality(), |held| {
            betweenness_texts(self.graph(), &held).join(",")
        })
    }

    fn layout_row(&self) -> String {
        answered(self.layout_assist(), |held| {
            layout_text(self.graph(), &held)
        })
    }
}

impl AnalysisReading for CachedGraphAnalysis {
    fn read_graph(&self) -> &CodeGraph {
        self.graph()
    }

    fn read_partition(&self) -> &DeclaredModulePartition {
        self.declared_partition()
    }

    fn neighbor_row(&self, walk: Walk) -> String {
        answered(
            self.neighbors(walk.node, walk.depth, walk.direction),
            |held| neighbor_texts(self.graph(), &held).join(","),
        )
    }

    fn subgraph_row(&self, walk: Walk) -> String {
        answered(
            self.subgraph(walk.node, walk.depth, walk.direction),
            |held| subgraph_text(self.graph(), &held),
        )
    }

    fn route_row(&self, route: (GraphNodeId, GraphNodeId)) -> String {
        answered(self.path(route.0, route.1), |held| {
            optional_route_text(self.graph(), held.as_deref())
        })
    }

    fn derived_rows(&self) -> Vec<(String, String)> {
        derived_rows(
            self.graph(),
            (
                &self.strongly_connected_components(),
                &self.condensation(),
                &self.divergence(),
            ),
        )
    }

    fn degree_row(&self) -> String {
        degree_texts(self.graph(), &self.degree_centrality()).join(",")
    }

    fn betweenness_row(&self) -> String {
        answered(self.betweenness_centrality(), |held| {
            betweenness_texts(self.graph(), &held).join(",")
        })
    }

    fn layout_row(&self) -> String {
        answered(self.layout_assist(), |held| {
            layout_text(self.graph(), &held)
        })
    }
}

/// Every answer one analysis gives, in the one order both analyses are read in.
pub fn rows(analysis: &impl AnalysisReading, asked: &Asked) -> Vec<(String, String)> {
    let mut rows = vec![(
        "partition".to_owned(),
        partition_text(analysis.read_graph(), analysis.read_partition()),
    )];
    for walk in &asked.walks {
        rows.push((walk.label("neighbors"), analysis.neighbor_row(*walk)));
        rows.push((walk.label("subgraph"), analysis.subgraph_row(*walk)));
    }
    for route in &asked.routes {
        rows.push((route_label(*route), analysis.route_row(*route)));
    }
    rows.extend(analysis.derived_rows());
    rows.push(("degree".to_owned(), analysis.degree_row()));
    rows.push(("betweenness".to_owned(), analysis.betweenness_row()));
    rows.push(("layout".to_owned(), analysis.layout_row()));
    rows
}

/// Every derived answer of one analysis around `seed`, rendered.
pub fn readings(analysis: &impl AnalysisReading, seed: GraphNodeId) -> Vec<(String, String)> {
    rows(
        analysis,
        &Asked::one(Walk::new(seed, 2, GraphDirection::Both), (seed, seed)),
    )
}

/// The first node of one graph.
pub fn first_node(graph: &CodeGraph) -> GraphNodeId {
    graph
        .nodes()
        .first()
        .unwrap_or_else(|| panic!("the corpus states nodes"))
        .id()
}

/// The node after `node`, wrapping to the first.
pub fn next_node(graph: &CodeGraph, node: GraphNodeId) -> GraphNodeId {
    let nodes = graph.nodes();
    let at = nodes
        .iter()
        .position(|found| found.id() == node)
        .unwrap_or_else(|| panic!("this graph holds no node {}", node.index()));
    nodes[(at + 1) % nodes.len()].id()
}

/// Every node identity one graph states, in the order the graph states them.
pub fn node_ids(graph: &CodeGraph) -> Box<[GraphNodeId]> {
    graph.nodes().iter().map(|node| node.id()).collect()
}

/// Every ordered pair drawn from `nodes`, source-major.
///
/// Shared: the route arguments one reading asks over and the search for a pair
/// with no route between them enumerate the same product, so the order the
/// pairs arrive in is written down once.
pub fn ordered_pairs(
    nodes: &[GraphNodeId],
) -> impl Iterator<Item = (GraphNodeId, GraphNodeId)> + '_ {
    nodes
        .iter()
        .flat_map(move |source| nodes.iter().map(move |target| (*source, *target)))
}

/// One refusal, or the rendering of the answer it gave.
pub fn answered<T>(
    answer: Result<T, GraphAnalysisError>,
    render: impl FnOnce(T) -> String,
) -> String {
    match answer {
        Ok(held) => render(held),
        Err(refused) => format!("refused|{refused}"),
    }
}

/// The rows the three infallible derived answers state.
fn derived_rows(
    graph: &CodeGraph,
    derived: (&GraphComponents, &CondensationGraph, &GraphDivergence),
) -> Vec<(String, String)> {
    let (components, condensation, divergence) = derived;
    vec![
        (
            "components".to_owned(),
            format!(
                "{}|{}",
                component_texts(graph, components.components()).join(","),
                membership_texts(graph, components).join(",")
            ),
        ),
        (
            "condensation".to_owned(),
            format!(
                "{}|{}",
                condensation_texts(graph, condensation.edges()).join(","),
                condensation
                    .topological_order()
                    .iter()
                    .map(|component| component.index().to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            ),
        ),
        (
            "divergence".to_owned(),
            format!(
                "{}|{}|{}|{}",
                cohesion_texts(graph, divergence.cohesion()).join(","),
                optional_bits(divergence.modularity()),
                candidate_texts(graph, divergence.candidates()).join(","),
                boundary_texts(graph, components, divergence.boundary_components()).join(",")
            ),
        ),
    ]
}

/// One route, named by both of its ends.
fn route_label(route: (GraphNodeId, GraphNodeId)) -> String {
    let (source, target) = route;
    format!("path|{}>{}", source.index(), target.index())
}

/// One declared partition, as every root beside its members and every node
/// beside its owner.
fn partition_text(graph: &CodeGraph, partition: &DeclaredModulePartition) -> String {
    let grouped: Vec<String> = partition
        .roots()
        .iter()
        .map(|root| {
            let members = partition
                .members(*root)
                .unwrap_or_else(|| panic!("root {} owns no members", root.index()));
            format!("{}:{}", name(graph, *root), names(graph, members).join("+"))
        })
        .collect();
    let owners: Vec<String> = graph
        .nodes()
        .iter()
        .map(|node| optional_name(graph, partition.owner(node.id())))
        .collect();
    format!("{}|{}", grouped.join(","), owners.join(","))
}

/// One induced selection, as its nodes, its edges, and its containment.
fn subgraph_text(graph: &CodeGraph, held: &GraphSubgraph) -> String {
    let containment: Vec<String> = held
        .containment()
        .iter()
        .map(|edge| {
            format!(
                "{}>{}",
                name(graph, edge.parent()),
                name(graph, edge.child())
            )
        })
        .collect();
    format!(
        "{}|{}|{}",
        names(graph, held.nodes()).join(","),
        edge_texts(graph, held.edges()).join(","),
        containment.join(",")
    )
}

/// One route, or the absence of one.
fn optional_route_text(graph: &CodeGraph, held: Option<&GraphPath>) -> String {
    match held {
        Some(route) => format!(
            "{}|{}",
            names(graph, route.nodes()).join(","),
            edge_texts(graph, route.edges()).join(",")
        ),
        None => "unreachable".to_owned(),
    }
}

/// One layout projection, as its nodes and its edges.
fn layout_text(graph: &CodeGraph, held: &LayoutAssistMetadata) -> String {
    format!(
        "{}|{}",
        layout_node_texts(graph, held.nodes()).join(","),
        layout_edge_texts(graph, held.edges()).join(",")
    )
}
