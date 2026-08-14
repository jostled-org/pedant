//! The written-down model of what the analysis family publishes.
//!
//! Every table here is stated by hand rather than read back from the source.
//! A model derived from the code it checks can only agree with whatever it
//! finds, so a field, an export, or a signature added to the crate has to be
//! added here too before [`super::analysis_ownership`] will admit it.

/// The exact vocabulary the analysis family publishes.
pub const ANALYSIS_EXPORTS: &[&str] = &[
    "BetweennessCentrality",
    "BoundaryCrossingComponent",
    "ComponentIdKind",
    "CondensationEdge",
    "CondensationGraph",
    "DeclaredModulePartition",
    "DegreeCentrality",
    "GraphAnalysis",
    "GraphAnalysisError",
    "GraphAnalysisLimits",
    "GraphComponent",
    "GraphComponentId",
    "GraphComponents",
    "GraphDirection",
    "GraphDivergence",
    "GraphEdgeSelection",
    "GraphNeighbor",
    "GraphPath",
    "GraphSubgraph",
    "LayoutAssistMetadata",
    "LayoutEdgeMetadata",
    "LayoutNodeMetadata",
    "MisplacementCandidate",
    "ModuleCohesion",
];

/// The vocabulary a coordinate, a route, or any other renderer state would be
/// named with.
///
/// Layout metadata is a typed projection for a renderer to consume, not a
/// layout: the moment one of these appears, the crate has started deciding how a
/// graph looks rather than describing what it is.
pub const RENDERER_STATE: &[&str] = &[
    "coordinate",
    "viewport",
    "render",
    "colour",
    "color",
    "style",
    "layer",
    "rank",
    "canvas",
];

/// Every field the layout projection states, beside the record that states it.
///
/// Written down rather than derived: a coordinate, a size, or a colour added to
/// one of these records must fail here, and a model read from the source could
/// only agree with whatever it found.
pub const LAYOUT_FIELDS: &[(&str, &[&str])] = &[
    (
        "LayoutNodeMetadata",
        &[
            "node",
            "parent",
            "partition",
            "incoming",
            "outgoing",
            "raw",
            "normalized",
        ],
    ),
    (
        "LayoutEdgeMetadata",
        &["edge", "source", "target", "kind", "certainty"],
    ),
    ("LayoutAssistMetadata", &["nodes", "edges"]),
];

/// The exact keys the version-1 graph object states, in order.
pub const WIRE_KEYS: &[&str] = &[
    "schema_version",
    "tier",
    "nodes",
    "containment",
    "references",
    "edges",
];

/// The exact public function surface each analysis module declares.
pub const ANALYSIS_SIGNATURES: &[(&str, &[&str])] = &[
    (
        "src/analysis/betweenness.rs",
        &[
            "BetweennessCentrality::node(self) -> GraphNodeId",
            "BetweennessCentrality::raw(self) -> f64",
            "BetweennessCentrality::normalized(self) -> f64",
        ],
    ),
    (
        "src/analysis/components.rs",
        &[
            "GraphComponent::id(&self) -> GraphComponentId",
            "GraphComponent::members(&self) -> &[GraphNodeId]",
            "GraphComponent::is_cyclic(&self) -> bool",
            "GraphComponents::components(&self) -> &[GraphComponent]",
            "GraphComponents::component(&self, id: GraphComponentId) -> Option<&GraphComponent>",
            "GraphComponents::component_of(&self, node: GraphNodeId) -> Option<GraphComponentId>",
            "CondensationEdge::source(&self) -> GraphComponentId",
            "CondensationEdge::target(&self) -> GraphComponentId",
            "CondensationEdge::edges(&self) -> &[GraphEdgeId]",
            "CondensationGraph::components(&self) -> &GraphComponents",
            "CondensationGraph::edges(&self) -> &[CondensationEdge]",
            "CondensationGraph::topological_order(&self) -> &[GraphComponentId]",
        ],
    ),
    (
        "src/analysis/degree.rs",
        &[
            "DegreeCentrality::node(self) -> GraphNodeId",
            "DegreeCentrality::incoming(self) -> u32",
            "DegreeCentrality::outgoing(self) -> u32",
        ],
    ),
    (
        "src/analysis/divergence.rs",
        &[
            "ModuleCohesion::root(self) -> GraphNodeId",
            "ModuleCohesion::internal_edges(self) -> u32",
            "ModuleCohesion::boundary_edges(self) -> u32",
            "ModuleCohesion::score(self) -> Option<f64>",
            "MisplacementCandidate::symbol(self) -> GraphNodeId",
            "MisplacementCandidate::declared_partition(self) -> GraphNodeId",
            "MisplacementCandidate::candidate_partition(self) -> GraphNodeId",
            "MisplacementCandidate::foreign_edges(self) -> u32",
            "MisplacementCandidate::total_outgoing_edges(self) -> u32",
            "MisplacementCandidate::affinity(self) -> f64",
            "BoundaryCrossingComponent::component(&self) -> GraphComponentId",
            "BoundaryCrossingComponent::partitions(&self) -> &[GraphNodeId]",
            "GraphDivergence::cohesion(&self) -> &[ModuleCohesion]",
            "GraphDivergence::modularity(&self) -> Option<f64>",
            "GraphDivergence::candidates(&self) -> &[MisplacementCandidate]",
            "GraphDivergence::boundary_components(&self) -> &[BoundaryCrossingComponent]",
        ],
    ),
    ("src/analysis/error.rs", &[]),
    (
        "src/analysis/index.rs",
        &[
            "GraphAnalysis::new(graph: &'graph CodeGraph, selection: GraphEdgeSelection, limits: GraphAnalysisLimits) -> Result<GraphAnalysis<'graph>, GraphAnalysisError>",
            "GraphAnalysis::graph(&self) -> &'graph CodeGraph",
            "GraphAnalysis::selection(&self) -> GraphEdgeSelection",
            "GraphAnalysis::limits(&self) -> GraphAnalysisLimits",
            "GraphAnalysis::declared_partition(&self) -> &DeclaredModulePartition",
            "GraphAnalysis::neighbors(&self, node: GraphNodeId, depth: u32, direction: GraphDirection) -> Result<Box<[GraphNeighbor]>, GraphAnalysisError>",
            "GraphAnalysis::path(&self, source: GraphNodeId, target: GraphNodeId) -> Result<Option<GraphPath>, GraphAnalysisError>",
            "GraphAnalysis::subgraph(&self, seed: GraphNodeId, depth: u32, direction: GraphDirection) -> Result<GraphSubgraph, GraphAnalysisError>",
            "GraphAnalysis::degree_centrality(&self) -> Box<[DegreeCentrality]>",
            "GraphAnalysis::betweenness_centrality(&self) -> Result<Box<[BetweennessCentrality]>, GraphAnalysisError>",
            "GraphAnalysis::strongly_connected_components(&self) -> GraphComponents",
            "GraphAnalysis::condensation(&self) -> CondensationGraph",
            "GraphAnalysis::divergence(&self) -> GraphDivergence",
            "GraphAnalysis::layout_assist(&self) -> Result<LayoutAssistMetadata, GraphAnalysisError>",
        ],
    ),
    (
        "src/analysis/layout.rs",
        &[
            "LayoutNodeMetadata::node(self) -> GraphNodeId",
            "LayoutNodeMetadata::containment_parent(self) -> Option<GraphNodeId>",
            "LayoutNodeMetadata::partition(self) -> GraphNodeId",
            "LayoutNodeMetadata::incoming_degree(self) -> u32",
            "LayoutNodeMetadata::outgoing_degree(self) -> u32",
            "LayoutNodeMetadata::raw_betweenness(self) -> f64",
            "LayoutNodeMetadata::normalized_betweenness(self) -> f64",
            "LayoutEdgeMetadata::edge(self) -> GraphEdgeId",
            "LayoutEdgeMetadata::source(self) -> GraphNodeId",
            "LayoutEdgeMetadata::target(self) -> GraphNodeId",
            "LayoutEdgeMetadata::kind(self) -> GraphEdgeKind",
            "LayoutEdgeMetadata::certainty(self) -> GraphCertainty",
            "LayoutAssistMetadata::nodes(&self) -> &[LayoutNodeMetadata]",
            "LayoutAssistMetadata::edges(&self) -> &[LayoutEdgeMetadata]",
        ],
    ),
    (
        "src/analysis/limits.rs",
        &[
            "GraphAnalysisLimits::new(max_nodes: u32, max_selected_edges: u32, max_depth: u32, max_betweenness_work: u64) -> Self",
            "GraphAnalysisLimits::max_nodes(self) -> u32",
            "GraphAnalysisLimits::max_selected_edges(self) -> u32",
            "GraphAnalysisLimits::max_depth(self) -> u32",
            "GraphAnalysisLimits::max_betweenness_work(self) -> u64",
        ],
    ),
    ("src/analysis/mod.rs", &[]),
    (
        "src/analysis/partition.rs",
        &[
            "DeclaredModulePartition::owner(&self, node: GraphNodeId) -> Option<GraphNodeId>",
            "DeclaredModulePartition::roots(&self) -> &[GraphNodeId]",
            "DeclaredModulePartition::members(&self, root: GraphNodeId) -> Option<&[GraphNodeId]>",
        ],
    ),
    (
        "src/analysis/selection.rs",
        &[
            "GraphEdgeSelection::new(kinds: &[GraphEdgeKind], certainties: &[GraphCertainty]) -> Self",
            "GraphEdgeSelection::all() -> Self",
            "GraphEdgeSelection::code_relations() -> Self",
            "GraphEdgeSelection::allows(self, edge: &GraphEdge) -> bool",
        ],
    ),
    (
        "src/analysis/traversal.rs",
        &[
            "GraphNeighbor::node(self) -> GraphNodeId",
            "GraphNeighbor::distance(self) -> u32",
            "GraphPath::nodes(&self) -> &[GraphNodeId]",
            "GraphPath::edges(&self) -> &[GraphEdgeId]",
            "GraphSubgraph::nodes(&self) -> &[GraphNodeId]",
            "GraphSubgraph::edges(&self) -> &[GraphEdgeId]",
            "GraphSubgraph::containment(&self) -> &[ContainmentEdge]",
        ],
    ),
];
