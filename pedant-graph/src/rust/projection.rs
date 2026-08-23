//! The one Rust planner both the direct and the cached path delegate to.
//!
//! It consumes the supplied snapshot and resolution and nothing else: no
//! project is loaded, no snapshot is constructed, no source is parsed, no
//! semantic context is built, and neither resolver tier is run. The plan it
//! produces holds no graph identity at all — every join travels as a stable
//! unit, source, or definition identity — so the same plan is what a later
//! build reuses and what [`super::assembly`] mints a complete graph from.
//!
//! Every source is decided before it is derived. The planner places the report's
//! records, states each source's key, and asks the store whether the projection
//! it retained still states what this report states. Derivation is the answer to
//! a miss, so a source whose claim still holds costs one key and one comparison.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::resolution::rust::{
    RustResolutionSnapshot, RustSnapshotUnitId, RustTargetResolution,
};
use pedant_types::{ResolutionRecord, ResolutionReport, SymbolReference};

use crate::edge::DependencyEvidence;
use crate::error::GraphBuildError;
use crate::graph::CodeGraph;
use crate::id::position;
use crate::limits::GraphLimits;
use crate::projection::assembly;
use crate::projection::draft::{
    DependencyProjection, PlacedFragment, ProjectionPlan, SourceFragment, StatedContainer, UnitPlan,
};
use crate::projection::placement::{DefinitionTable, RecordPlacement, SourceSet};
use crate::projection::state::ProjectionCapacity;
use crate::projection::validation as neutral;

use super::claim::SourceKey;
use super::mapping::{self, Vocabulary};
use super::reuse::ProjectionStore;
use super::source::{self, StatedSource};
use super::validation;

/// The values every planning pass reads, gathered once.
struct Inputs<'a> {
    snapshot: &'a RustResolutionSnapshot,
    report: &'a ResolutionReport,
    vocabulary: Vocabulary,
    /// Every report reference beside the record that answered it, paired by the
    /// one validator that proves the two slices agree in length.
    resolved: Box<[(&'a SymbolReference, &'a ResolutionRecord)]>,
}

/// Every planned unit beside the build units they were bound to.
struct PlannedUnits {
    units: Vec<UnitPlan>,
    bound: BTreeMap<RustSnapshotUnitId, u32>,
}

/// Project one snapshot-bound resolution into a code graph.
pub(crate) fn project(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
    limits: GraphLimits,
) -> Result<CodeGraph, GraphBuildError> {
    validate(snapshot, resolution)?;
    let planned = plan(snapshot, resolution, &mut ProjectionStore::unretained())?;
    assembly::assemble(&planned, limits)
}

/// Both identity checks, taken before anything is planned or observed.
pub(crate) fn validate(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
) -> Result<(), GraphBuildError> {
    validation::check_root_target(snapshot, resolution)?;
    validation::check_snapshot_identity(snapshot, resolution)
}

/// The complete graph-neutral projection one validated pairing states.
pub(crate) fn plan(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
    reuse: &mut ProjectionStore,
) -> Result<ProjectionPlan, GraphBuildError> {
    let report = resolution.report();
    let inputs = Inputs {
        snapshot,
        report,
        vocabulary: Vocabulary::new(),
        resolved: neutral::resolved_references(report)?,
    };
    let planned = plan_units(&inputs, resolution)?;
    let sources = SourceSet::new(planned.units.into_boxed_slice())?;
    let table = DefinitionTable::new(report, &sources)?;
    let placement = RecordPlacement::stated(report, &inputs.resolved, (&sources, &table))?;
    let fragments = plan_fragments(&inputs, (&sources, &table, &placement), reuse)?;
    let dependencies = plan_dependencies(&inputs, &planned.bound)?;
    let capacity = capacity(&inputs);
    Ok(ProjectionPlan {
        tier: report.tier(),
        units: sources.finish(),
        // Every Cargo target is declared by a manifest, so no Rust unit is
        // rooted at a definition of its own.
        declarations: Box::default(),
        fragments,
        definitions: placement.definitions,
        references: placement.references,
        dependencies,
        capacity,
    })
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

/// One container plan per report unit, in report order.
///
/// One build unit is bound by one report unit: two report units naming it would
/// give every source of that unit two owners, and the collision is named where
/// it is made.
fn plan_units(
    inputs: &Inputs<'_>,
    resolution: &RustTargetResolution,
) -> Result<PlannedUnits, GraphBuildError> {
    let mut planned = PlannedUnits {
        units: Vec::with_capacity(inputs.report.units().len()),
        bound: BTreeMap::new(),
    };
    for unit in inputs.report.units() {
        let reported = unit.id().index();
        let snapshot_unit = validation::stated_binding(resolution, unit)?;
        let instance = neutral::bound_instance(inputs.snapshot.unit(snapshot_unit), reported)?;
        validation::distinct_binding(planned.bound.get(&snapshot_unit).copied(), reported)?;
        planned.bound.insert(snapshot_unit, reported);
        planned.units.push(UnitPlan {
            key: Arc::from(unit.key()),
            language: unit.language(),
            // A Cargo target is declared by a manifest, so nothing inside the
            // sources it compiles names it and no report definition can be its
            // container. Rust units nest under no other unit either: the
            // package a target belongs to compiles none of its own sources.
            container: Some(StatedContainer {
                name: Arc::from(unit.name()),
                kind: inputs.vocabulary.unit_root(instance.kind()),
            }),
            parent: None,
            sources: instance.sources().into(),
        });
    }
    Ok(planned)
}

/// One projection per source, each decided before it is derived.
fn plan_fragments<'a>(
    inputs: &Inputs<'a>,
    placed: (&SourceSet, &DefinitionTable, &RecordPlacement<'a>),
    reuse: &mut ProjectionStore,
) -> Result<Box<[PlacedFragment]>, GraphBuildError> {
    let (sources, table, placement) = placed;
    let mut fragments = Vec::with_capacity(sources.placed().len());
    for (source, records) in sources.placed().iter().zip(placement.stated.iter()) {
        let stated = StatedSource {
            table,
            vocabulary: &inputs.vocabulary,
            placed: source,
            records,
        };
        fragments.push(placed_fragment(&stated, (inputs, sources.units()), reuse)?);
    }
    Ok(fragments.into_boxed_slice())
}

/// One source's projection, beside the unit that placed it.
///
/// The key is stated from the snapshot, the planned unit, and the source
/// identity alone, so it is known before anything has been derived for this
/// source.
fn placed_fragment(
    stated: &StatedSource<'_>,
    planned: (&Inputs<'_>, &[UnitPlan]),
    reuse: &mut ProjectionStore,
) -> Result<PlacedFragment, GraphBuildError> {
    let (inputs, units) = planned;
    let placed = stated.placed;
    let key = SourceKey::stated(
        inputs.snapshot,
        (units, placed.unit),
        (&placed.source, inputs.report.tier()),
    )?;
    Ok(PlacedFragment {
        unit: placed.unit,
        fragment: stated_projection(stated, key, reuse)?,
    })
}

/// The projection one source answers with.
///
/// The store is asked first and derivation is the answer to a miss, so a source
/// whose retained projection still states the current claim reaches no
/// derivation at all: the reused value is the one the assembler goes on to mint
/// dense identities from.
fn stated_projection(
    stated: &StatedSource<'_>,
    key: SourceKey,
    reuse: &mut ProjectionStore,
) -> Result<Arc<SourceFragment>, GraphBuildError> {
    match reuse.reused(&key, |held| source::states_current_claim(held, stated)) {
        Some(retained) => Ok(retained),
        None => Ok(reuse.retain(key, source::derived_projection(stated)?)),
    }
}

/// One dependency projection per snapshot Cargo edge, in snapshot order.
fn plan_dependencies(
    inputs: &Inputs<'_>,
    bound: &BTreeMap<RustSnapshotUnitId, u32>,
) -> Result<Box<[DependencyProjection]>, GraphBuildError> {
    inputs
        .snapshot
        .edges()
        .iter()
        .enumerate()
        .map(|(index, edge)| {
            let stated = (position(index), edge);
            let source = validation::dependency_unit(bound.get(&edge.source()).copied(), stated)?;
            let target = validation::dependency_unit(bound.get(&edge.target()).copied(), stated)?;
            let (certainty, predicate) = mapping::activation(edge.activation());
            Ok(DependencyProjection {
                source,
                target,
                certainty,
                evidence: DependencyEvidence::new(
                    Arc::from(edge.name()),
                    mapping::dependency_kind(edge.kind()),
                    predicate,
                ),
            })
        })
        .collect()
}
