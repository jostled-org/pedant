//! The one Rust projection path both public entry points delegate to.
//!
//! It consumes the supplied snapshot and resolution and nothing else: no
//! project is loaded, no snapshot is constructed, no source is parsed, no
//! semantic context is built, and neither resolver tier is run. Identifiers are
//! assigned in fixed passes — unit containers, each unit's sorted sources,
//! report definitions, report references, snapshot dependency edges, then
//! reference candidate edges — so equal inputs produce byte-identical output.

use std::sync::Arc;

use pedant_core::resolution::rust::{RustResolutionSnapshot, RustTargetResolution};
use pedant_types::{
    ResolutionRecord, ResolutionReport, ResolutionUnit, SymbolDefinition, SymbolReference,
};

use crate::edge::{DependencyEvidence, EdgeDraft, GraphEdgeKind, GraphEdgeOrigin};
use crate::error::GraphBuildError;
use crate::graph::CodeGraph;
use crate::id::{GraphNodeId, GraphReferenceId, position};
use crate::limits::GraphLimits;
use crate::node::{GraphNodeKind, GraphNodeLocation, NodeDraft};
use crate::reference::{GraphReferenceKind, ReferenceDraft};

use super::index::{ProjectionCapacity, ProjectionState};
use super::mapping::{self, Vocabulary};
use super::validation;

/// What one projected reference record needs from its candidates pass.
///
/// The record travels with the identity it produced, so the pairing between a
/// reference and its answer is proved once and never derived a second time.
struct ProjectedReference<'a> {
    id: GraphReferenceId,
    source: GraphNodeId,
    kind: GraphReferenceKind,
    record: &'a ResolutionRecord,
}

/// The values every pass reads, gathered once.
struct Inputs<'a> {
    snapshot: &'a RustResolutionSnapshot,
    report: &'a ResolutionReport,
    vocabulary: Vocabulary,
    /// Every report reference beside the record that answered it, paired by the
    /// one validator that proves the two slices agree in length.
    resolved: Box<[(&'a SymbolReference, &'a ResolutionRecord)]>,
}

/// Project one snapshot-bound resolution into a code graph.
pub(crate) fn project(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
    limits: GraphLimits,
) -> Result<CodeGraph, GraphBuildError> {
    validation::check_root_target(snapshot, resolution)?;
    validation::check_snapshot_identity(snapshot, resolution)?;
    let report = resolution.report();
    let inputs = Inputs {
        snapshot,
        report,
        vocabulary: Vocabulary::new(),
        resolved: validation::resolved_references(report)?,
    };
    let mut state = ProjectionState::new(limits, capacity(&inputs));
    let units = project_units(&mut state, &inputs, resolution)?;
    project_sources(&mut state, &inputs)?;
    project_definitions(&mut state, &inputs)?;
    project_containment(&mut state, &inputs)?;
    validation::check_containment_forest(&state, units)?;
    let references = project_references(&mut state, &inputs)?;
    project_dependencies(&mut state, &inputs)?;
    project_candidates(&mut state, &references)?;
    Ok(state.finish(inputs.report.tier()))
}

/// How many records the supplied inputs state, counted before one is allocated.
///
/// Every count is stated by the report or the snapshot. The store reserves no
/// more than the ceiling it refuses at, so a build the limits will refuse costs
/// no more memory than the graph it would have admitted.
fn capacity(inputs: &Inputs<'_>) -> ProjectionCapacity {
    ProjectionCapacity {
        units: inputs.report.units().len(),
        definitions: inputs.report.definitions().len(),
        references: inputs.resolved.len(),
        edges: inputs
            .resolved
            .iter()
            .fold(inputs.snapshot.edges().len(), |total, (_, record)| {
                total.saturating_add(record.candidates().len())
            }),
    }
}

/// One root container per report unit, in report order.
///
/// This is the first pass, so the containers take the first identities the
/// graph mints and the store's own node count is what later passes read
/// rootness from.
fn project_units(
    state: &mut ProjectionState,
    inputs: &Inputs<'_>,
    resolution: &RustTargetResolution,
) -> Result<usize, GraphBuildError> {
    for unit in inputs.report.units() {
        let reported = unit.id().index();
        let snapshot_unit = validation::stated_binding(resolution, unit)?;
        let instance = validation::snapshot_instance(inputs.snapshot, (snapshot_unit, reported))?;
        let container = state.insert_node(NodeDraft {
            language: unit.language(),
            name: Arc::from(unit.name()),
            kind: inputs.vocabulary.unit_root(instance.kind()),
            location: None,
        })?;
        validation::bind_unit(state, container, (snapshot_unit, reported))?;
    }
    Ok(state.node_count())
}

/// One file node per source the bound unit instantiates, in sorted path order.
fn project_sources(
    state: &mut ProjectionState,
    inputs: &Inputs<'_>,
) -> Result<(), GraphBuildError> {
    for unit in inputs.report.units() {
        let reported = unit.id().index();
        let snapshot_unit = validation::bound_snapshot_unit(state, reported)?;
        let container = validation::unit_container(state, reported)?;
        let instance = validation::snapshot_instance(inputs.snapshot, (snapshot_unit, reported))?;
        for path in instance.sources() {
            let node = validation::qualified_source(
                state,
                (snapshot_unit, reported),
                path,
                file_draft(unit, path),
            )?;
            state.contain(container, node);
        }
    }
    Ok(())
}

fn file_draft(unit: &ResolutionUnit, path: &Arc<str>) -> NodeDraft {
    NodeDraft {
        language: unit.language(),
        name: Arc::clone(path),
        kind: GraphNodeKind::File,
        location: Some(GraphNodeLocation::File {
            path: Arc::clone(path),
        }),
    }
}

/// One node per report definition, in report order.
fn project_definitions(
    state: &mut ProjectionState,
    inputs: &Inputs<'_>,
) -> Result<(), GraphBuildError> {
    for definition in inputs.report.definitions() {
        let reported = definition.unit().index();
        let snapshot_unit = validation::bound_snapshot_unit(state, reported)?;
        let file = validation::source_node(
            state,
            (snapshot_unit, reported),
            SymbolDefinition::span(definition).file(),
        )?;
        let node = state.insert_node(definition_draft(&inputs.vocabulary, definition, file))?;
        state.bind_definition(node);
    }
    Ok(())
}

fn definition_draft(
    vocabulary: &Vocabulary,
    definition: &SymbolDefinition,
    file: GraphNodeId,
) -> NodeDraft {
    NodeDraft {
        language: definition.language(),
        name: Arc::from(definition.name()),
        kind: vocabulary.definition(definition.kind()),
        location: Some(GraphNodeLocation::Span {
            file,
            span: SymbolDefinition::span(definition).clone(),
        }),
    }
}

/// Logical ownership: a report parent when there is one, the unit root
/// otherwise. Source location never becomes a containment parent.
fn project_containment(
    state: &mut ProjectionState,
    inputs: &Inputs<'_>,
) -> Result<(), GraphBuildError> {
    for definition in inputs.report.definitions() {
        let child = validation::definition_node(state, definition.id().index())?;
        let parent = match definition.parent() {
            Some(parent) => validation::definition_node(state, parent.index())?,
            None => validation::unit_container(state, definition.unit().index())?,
        };
        state.contain(parent, child);
    }
    Ok(())
}

/// One reference record per report reference, in report order.
fn project_references<'a>(
    state: &mut ProjectionState,
    inputs: &Inputs<'a>,
) -> Result<Box<[ProjectedReference<'a>]>, GraphBuildError> {
    let mut projected = Vec::with_capacity(inputs.resolved.len());
    for (reference, record) in inputs.resolved.iter().copied() {
        let source = reference_source(state, reference)?;
        let kind = mapping::reference_kind(reference.kind());
        let id = state.insert_reference(reference_draft((source, kind), reference, record))?;
        projected.push(ProjectedReference {
            id,
            source,
            kind,
            record,
        });
    }
    Ok(projected.into_boxed_slice())
}

fn reference_draft(
    site: (GraphNodeId, GraphReferenceKind),
    reference: &SymbolReference,
    record: &ResolutionRecord,
) -> ReferenceDraft {
    let (source, kind) = site;
    ReferenceDraft {
        source,
        language: reference.language(),
        kind,
        text: Arc::from(reference.text()),
        span: SymbolReference::span(reference).clone(),
        gaps: record.gaps().into(),
    }
}

/// The enclosing definition when the producer supplies one, otherwise the
/// unit-qualified file node the site sits in.
///
/// The span is joined to its unit-qualified file node either way. A site whose
/// span names a source only another unit instantiates is refused with the same
/// variant a definition in that state is, rather than admitted because it also
/// carries an enclosing definition.
fn reference_source(
    state: &ProjectionState,
    reference: &SymbolReference,
) -> Result<GraphNodeId, GraphBuildError> {
    let reported = reference.unit().index();
    let snapshot_unit = validation::bound_snapshot_unit(state, reported)?;
    let file = validation::source_node(
        state,
        (snapshot_unit, reported),
        SymbolReference::span(reference).file(),
    )?;
    match reference.enclosing_definition() {
        Some(enclosing) => validation::definition_node(state, enclosing.index()),
        None => Ok(file),
    }
}

/// One `DependsOn` edge per snapshot Cargo edge, in snapshot order.
fn project_dependencies(
    state: &mut ProjectionState,
    inputs: &Inputs<'_>,
) -> Result<(), GraphBuildError> {
    for (index, edge) in inputs.snapshot.edges().iter().enumerate() {
        let stated = (position(index), edge);
        let source = validation::snapshot_container(state, edge.source(), stated)?;
        let target = validation::snapshot_container(state, edge.target(), stated)?;
        let (certainty, predicate) = mapping::activation(edge.activation());
        state.insert_edge(EdgeDraft {
            source,
            target,
            kind: GraphEdgeKind::DependsOn,
            certainty,
            origin: GraphEdgeOrigin::Dependency {
                evidence: DependencyEvidence::new(
                    Arc::from(edge.name()),
                    mapping::dependency_kind(edge.kind()),
                    predicate,
                ),
            },
        })?;
    }
    Ok(())
}

/// One edge per resolution candidate, in reference then candidate order.
///
/// Each edge names the record that produced it, and the store links the two in
/// the same step it mints the identity, so no record can claim an edge the
/// graph does not hold.
fn project_candidates(
    state: &mut ProjectionState,
    references: &[ProjectedReference<'_>],
) -> Result<(), GraphBuildError> {
    for projected in references {
        for candidate in projected.record.candidates() {
            let target = validation::definition_node(state, candidate.definition().index())?;
            state.insert_edge(EdgeDraft {
                source: projected.source,
                target,
                kind: mapping::candidate_edge_kind(projected.kind),
                certainty: mapping::certainty(candidate.certainty()),
                origin: GraphEdgeOrigin::Reference {
                    reference: projected.id,
                },
            })?;
        }
    }
    Ok(())
}
