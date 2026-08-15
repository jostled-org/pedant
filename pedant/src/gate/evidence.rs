//! Projection from one analyzed code graph into graph-neutral gate evidence.
//!
//! The judgment library must never name a graph type, so this owner copies the
//! facts it needs and nothing else: a qualified label, a target-local ordinal,
//! an optional one-based source anchor, and the exact counts each rule
//! compares. Every missing node, containment parent, partition owner, or source
//! association is a concrete refusal rather than omitted evidence.

use std::collections::BTreeSet;
use std::sync::Arc;

use pedant_core::gate::{
    GateLocation, ModuleBoundaryEntity, ModuleBoundaryFact, ModuleBoundaryInput,
    ModuleBoundaryInputError,
};
use pedant_graph::{
    BoundaryCrossingComponent, CodeGraph, DeclaredModulePartition, GraphAnalysis, GraphComponent,
    GraphComponentId, GraphNode, GraphNodeId, GraphNodeLocation, MisplacementCandidate,
    ModuleCohesion,
};
use pedant_types::SourceSpan;

/// Why one target's topology could not become neutral evidence.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EvidenceError {
    /// An identity named no record in the analyzed graph.
    #[error("node {node} has no record in the analyzed graph")]
    UnknownNode {
        /// The identity that named nothing.
        node: u32,
    },
    /// A containment chain was longer than the graph has nodes.
    #[error("node {node} is contained by more parents than the graph holds nodes")]
    ContainmentDepth {
        /// The node whose chain never reached a root.
        node: u32,
    },
    /// A component member belongs to no declared partition.
    #[error("node {node} is owned by no declared partition")]
    MissingPartitionOwner {
        /// The member no partition root answers for.
        node: u32,
    },
    /// A span names a source node the graph holds no record for.
    #[error("node {node} names a source association the graph does not hold")]
    MissingSourceAssociation {
        /// The file identity the span named.
        node: u32,
    },
    /// The analysis and the projection disagree about which cycle crosses a
    /// declared boundary.
    #[error("the analysis names cycle {component}, which the projection does not")]
    MismatchedBoundaryComponent {
        /// The component identity only one side names.
        component: u32,
    },
    /// The analysis and the projection disagree about how many cycles cross a
    /// declared boundary.
    #[error("the analysis states {stated} boundary-crossing cycles, the projection {projected}")]
    BoundaryComponentCount {
        /// How many the analysis states.
        stated: usize,
        /// How many the projection derived.
        projected: usize,
    },
    /// The projected facts were not self-consistent for the core evaluator.
    #[error("the projected structural facts are not acceptable: {0}")]
    Neutral(#[from] ModuleBoundaryInputError),
}

/// The slice position one graph identity names.
fn position(node: GraphNodeId) -> usize {
    usize::try_from(node.index()).unwrap_or(usize::MAX)
}

/// Every node of one graph, already qualified, ordinal-tagged, and anchored.
struct EntityTable {
    entities: Box<[ModuleBoundaryEntity]>,
}

impl EntityTable {
    /// Derive one entity per node, in node-id order.
    ///
    /// One containment chain buffer serves every node, so the walk amortizes to
    /// a single allocation sized to the deepest container nesting rather than
    /// one per node under the node ceiling.
    fn derive(graph: &CodeGraph) -> Result<Self, EvidenceError> {
        let parents = parent_table(graph);
        let mut chain = Vec::new();
        let entities = graph
            .nodes()
            .iter()
            .map(|node| entity(graph, &parents, node, &mut chain))
            .collect::<Result<Box<[ModuleBoundaryEntity]>, EvidenceError>>()?;
        Ok(Self { entities })
    }

    /// The entity one identity names.
    fn get(&self, node: GraphNodeId) -> Result<ModuleBoundaryEntity, EvidenceError> {
        self.entities
            .get(position(node))
            .cloned()
            .ok_or(EvidenceError::UnknownNode { node: node.index() })
    }

    /// The entities a whole identity list names, in the order it states them.
    fn many(&self, nodes: &[GraphNodeId]) -> Result<Arc<[ModuleBoundaryEntity]>, EvidenceError> {
        nodes.iter().map(|node| self.get(*node)).collect()
    }
}

/// Which node contains each node, in node-id order.
fn parent_table(graph: &CodeGraph) -> Box<[Option<GraphNodeId>]> {
    let mut parents = vec![None; graph.nodes().len()].into_boxed_slice();
    for edge in graph.containment() {
        if let Some(slot) = parents.get_mut(position(edge.child())) {
            *slot = Some(edge.parent());
        }
    }
    parents
}

/// The container above one node, when the table holds it.
fn parent_of(parents: &[Option<GraphNodeId>], node: GraphNodeId) -> Option<GraphNodeId> {
    parents.get(position(node)).copied().flatten()
}

fn entity<'g>(
    graph: &'g CodeGraph,
    parents: &[Option<GraphNodeId>],
    node: &'g GraphNode,
    chain: &mut Vec<&'g str>,
) -> Result<ModuleBoundaryEntity, EvidenceError> {
    let label = qualified_label(graph, parents, node, chain)?;
    let location = source_location(graph, node)?;
    ModuleBoundaryEntity::try_new(node.id().index(), label, location).map_err(EvidenceError::from)
}

/// Join node names with `::`, from the unit container down to `node`.
///
/// The walk is iterative and bounded by the node count, so a containment
/// relation the graph did not prove acyclic refuses instead of looping. The
/// caller owns the chain buffer and it is cleared here, not reused across a
/// refusal.
fn qualified_label<'g>(
    graph: &'g CodeGraph,
    parents: &[Option<GraphNodeId>],
    node: &'g GraphNode,
    chain: &mut Vec<&'g str>,
) -> Result<Box<str>, EvidenceError> {
    chain.clear();
    chain.push(node.name());
    let mut above = parent_of(parents, node.id());
    while let Some(id) = above {
        let held = graph
            .node(id)
            .ok_or(EvidenceError::UnknownNode { node: id.index() })?;
        chain.push(held.name());
        above = match chain.len() > parents.len() {
            true => {
                return Err(EvidenceError::ContainmentDepth {
                    node: node.id().index(),
                });
            }
            false => parent_of(parents, id),
        };
    }
    chain.reverse();
    Ok(chain.join("::").into_boxed_str())
}

fn source_location(
    graph: &CodeGraph,
    node: &GraphNode,
) -> Result<Option<GateLocation>, EvidenceError> {
    match node.location() {
        None => Ok(None),
        Some(GraphNodeLocation::File { path }) => GateLocation::try_new_file(Arc::clone(path))
            .map(Some)
            .map_err(EvidenceError::from),
        Some(GraphNodeLocation::Span { file, span }) => span_anchor(graph, *file, span),
    }
}

/// A one-based span anchor, taken after the named source node is proved held.
fn span_anchor(
    graph: &CodeGraph,
    file: GraphNodeId,
    span: &SourceSpan,
) -> Result<Option<GateLocation>, EvidenceError> {
    match graph.node(file) {
        None => Err(EvidenceError::MissingSourceAssociation { node: file.index() }),
        Some(_) => GateLocation::try_new(
            span.file(),
            span.start().line().saturating_add(1),
            span.start().column().saturating_add(1),
        )
        .map(Some)
        .map_err(EvidenceError::from),
    }
}

/// Project one analyzed target into the validated facts core policy judges.
pub(crate) fn project_target(
    analysis: &GraphAnalysis<'_>,
    target: Arc<str>,
) -> Result<ModuleBoundaryInput, EvidenceError> {
    let entities = EntityTable::derive(analysis.graph())?;
    let facts = structural_facts(analysis, &entities)?;
    ModuleBoundaryInput::try_new(target, facts).map_err(EvidenceError::from)
}

/// Every component, misplacement, and cohesion row, in that fixed order.
fn structural_facts(
    analysis: &GraphAnalysis<'_>,
    entities: &EntityTable,
) -> Result<Box<[ModuleBoundaryFact]>, EvidenceError> {
    let components = analysis.strongly_connected_components();
    let divergence = analysis.divergence();
    let mut facts = Vec::with_capacity(
        components.components().len() + divergence.candidates().len() + divergence.cohesion().len(),
    );
    let crossing = component_facts(
        components.components(),
        analysis.declared_partition(),
        entities,
        &mut facts,
    )?;
    require_boundary_oracle(&crossing, divergence.boundary_components())?;
    misplacement_facts(divergence.candidates(), entities, &mut facts)?;
    cohesion_facts(divergence.cohesion(), entities, &mut facts)?;
    Ok(facts.into_boxed_slice())
}

/// One fact per component, returning the cycles that crossed a boundary.
fn component_facts(
    components: &[GraphComponent],
    partition: &DeclaredModulePartition,
    entities: &EntityTable,
    facts: &mut Vec<ModuleBoundaryFact>,
) -> Result<Box<[GraphComponentId]>, EvidenceError> {
    let mut crossing = Vec::new();
    for component in components {
        let roots = partition_roots(component.members(), partition)?;
        if component.is_cyclic() && roots.len() > 1 {
            crossing.push(component.id());
        }
        facts.push(ModuleBoundaryFact::component(
            component.is_cyclic(),
            entities.many(component.members())?,
            entities.many(&roots)?,
        )?);
    }
    Ok(crossing.into_boxed_slice())
}

/// Every distinct partition one component's members are declared in.
fn partition_roots(
    members: &[GraphNodeId],
    partition: &DeclaredModulePartition,
) -> Result<Box<[GraphNodeId]>, EvidenceError> {
    members
        .iter()
        .map(|member| {
            partition
                .owner(*member)
                .ok_or(EvidenceError::MissingPartitionOwner {
                    node: member.index(),
                })
        })
        .collect::<Result<BTreeSet<GraphNodeId>, EvidenceError>>()
        .map(|roots| roots.into_iter().collect())
}

/// The analysis's own boundary list is the oracle the projection must equal.
fn require_boundary_oracle(
    projected: &[GraphComponentId],
    stated: &[BoundaryCrossingComponent],
) -> Result<(), EvidenceError> {
    if projected.len() != stated.len() {
        return Err(EvidenceError::BoundaryComponentCount {
            stated: stated.len(),
            projected: projected.len(),
        });
    }
    match projected
        .iter()
        .zip(stated)
        .find(|(ours, theirs)| **ours != theirs.component())
    {
        Some((ours, _)) => Err(EvidenceError::MismatchedBoundaryComponent {
            component: ours.index(),
        }),
        None => Ok(()),
    }
}

fn misplacement_facts(
    candidates: &[MisplacementCandidate],
    entities: &EntityTable,
    facts: &mut Vec<ModuleBoundaryFact>,
) -> Result<(), EvidenceError> {
    for candidate in candidates {
        facts.push(ModuleBoundaryFact::misplaced_symbol(
            entities.get(candidate.symbol())?,
            entities.get(candidate.declared_partition())?,
            entities.get(candidate.candidate_partition())?,
            candidate.foreign_edges(),
            candidate.total_outgoing_edges(),
        )?);
    }
    Ok(())
}

fn cohesion_facts(
    cohesion: &[ModuleCohesion],
    entities: &EntityTable,
    facts: &mut Vec<ModuleBoundaryFact>,
) -> Result<(), EvidenceError> {
    for module in cohesion {
        facts.push(ModuleBoundaryFact::low_module_cohesion(
            entities.get(module.root())?,
            module.internal_edges(),
            module.boundary_edges(),
        ));
    }
    Ok(())
}
