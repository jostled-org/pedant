//! The one Go planner both public entry points delegate to.
//!
//! It consumes the supplied snapshot and resolution and nothing else: no
//! project is loaded, no snapshot is constructed, no directory is walked, no
//! source is read, and the resolver is not run. The plan it produces holds no
//! graph identity at all — every join travels as a stable unit, source, or
//! definition identity — so [`crate::projection::assembly`] mints a complete
//! graph from exactly the plan a Rust build hands it.
//!
//! Nothing is retained between builds. A Go graph is derived from the pairing
//! it was handed, so every source of every package context is projected once,
//! in report order, and no key selects a previous answer.

use std::sync::Arc;

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionSnapshot};
use pedant_types::{ResolutionRecord, ResolutionReport, SymbolDefinition, SymbolReference};

use crate::error::GraphBuildError;
use crate::graph::CodeGraph;
use crate::limits::GraphLimits;
use crate::projection::assembly;
use crate::projection::draft::{
    DefinitionProjection, PlacedFragment, ProjectionPlan, ReferenceProjection, SourceFragment,
};
use crate::projection::placement::{
    DefinitionTable, PlacedSource, RecordPlacement, SourceRecords, SourceSet,
};
use crate::projection::state::ProjectionCapacity;
use crate::projection::validation as neutral;

use super::mapping::{self, Vocabulary};
use super::placement::{self, PlannedUnits};
use super::validation;

/// The values every planning pass reads, gathered once.
struct Inputs<'a> {
    report: &'a ResolutionReport,
    vocabulary: Vocabulary,
    /// Every report reference beside the record that answered it, paired by the
    /// one validator that proves the two slices agree in length.
    resolved: Box<[(&'a SymbolReference, &'a ResolutionRecord)]>,
}

/// Everything one source's fragment is derived from.
struct StatedSource<'a> {
    /// The identities every join in this report travels through.
    table: &'a DefinitionTable,
    /// The unit and source identity this fragment answers for.
    placed: &'a PlacedSource,
    /// The records the current report places in this source.
    records: &'a SourceRecords<'a>,
}

/// Project one snapshot-bound Go resolution into a code graph.
///
/// The pairing is proved before the plan exists, and the plan exists before a
/// single record is allocated, so a stale resolution costs no graph memory at
/// all.
pub(crate) fn project(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
    limits: GraphLimits,
) -> Result<CodeGraph, GraphBuildError> {
    validation::check_snapshot_identity(snapshot, resolution)?;
    let planned = plan(snapshot, resolution)?;
    assembly::assemble(&planned, limits)
}

/// The complete graph-neutral projection one validated pairing states.
fn plan(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
) -> Result<ProjectionPlan, GraphBuildError> {
    let report = resolution.report();
    let inputs = Inputs {
        report,
        vocabulary: Vocabulary::new(),
        resolved: neutral::resolved_references(report)?,
    };
    let planned: PlannedUnits = placement::plan_units(snapshot, resolution, &inputs.vocabulary)?;
    let capacity = capacity(&inputs, (snapshot, planned.units.len()));
    let sources = SourceSet::new(planned.units)?;
    let table = DefinitionTable::new(report, &sources)?;
    let records = RecordPlacement::stated(report, &inputs.resolved, (&sources, &table))?;
    let fragments = plan_fragments(&inputs, (&sources, &table, &records))?;
    let dependencies = placement::plan_dependencies(snapshot, &planned.modules)?;
    Ok(ProjectionPlan {
        tier: report.tier(),
        units: sources.finish(),
        declarations: planned.declarations,
        fragments,
        definitions: records.definitions,
        references: records.references,
        dependencies,
        capacity,
    })
}

/// How many records the supplied inputs state, counted before one is allocated.
///
/// The unit count is the plan's own, not the report's: a Go plan states a
/// container for every admitted module beside every package context, and the
/// assembly tables are indexed by plan position.
fn capacity(inputs: &Inputs<'_>, planned: (&GoResolutionSnapshot, usize)) -> ProjectionCapacity {
    let (snapshot, units) = planned;
    ProjectionCapacity {
        units,
        definitions: inputs.report.definitions().len(),
        references: inputs.resolved.len(),
        edges: inputs
            .resolved
            .iter()
            .fold(snapshot.edges().len(), |total, (_, record)| {
                total.saturating_add(record.candidates().len())
            }),
    }
}

/// One fragment per placed source, in placement order.
fn plan_fragments<'a>(
    inputs: &Inputs<'a>,
    placed: (&SourceSet, &DefinitionTable, &RecordPlacement<'a>),
) -> Result<Box<[PlacedFragment]>, GraphBuildError> {
    let (sources, table, records) = placed;
    sources
        .placed()
        .iter()
        .zip(records.stated.iter())
        .map(|(placed, stated)| {
            let source = StatedSource {
                table,
                placed,
                records: stated,
            };
            Ok(PlacedFragment {
                unit: placed.unit,
                fragment: Arc::new(derived_fragment(inputs, &source)?),
            })
        })
        .collect()
}

/// Everything one source contributes to a graph, derived from the report.
fn derived_fragment(
    inputs: &Inputs<'_>,
    stated: &StatedSource<'_>,
) -> Result<SourceFragment, GraphBuildError> {
    Ok(SourceFragment {
        source: stated.placed.source.shared(),
        definitions: projected_definitions(inputs, stated)?,
        references: projected_references(stated)?,
    })
}

/// One projection per definition the report places in this source, in report
/// order.
fn projected_definitions(
    inputs: &Inputs<'_>,
    stated: &StatedSource<'_>,
) -> Result<Box<[DefinitionProjection]>, GraphBuildError> {
    stated
        .records
        .definitions
        .iter()
        .copied()
        .map(|(at, definition)| projected_definition(inputs, stated.table, (at, definition)))
        .collect()
}

/// One definition projection, at the report position that states it.
///
/// The holder's own kind decides which callable token a method takes, so the
/// report is read for it before the vocabulary is asked.
fn projected_definition(
    inputs: &Inputs<'_>,
    table: &DefinitionTable,
    reported: (u32, &SymbolDefinition),
) -> Result<DefinitionProjection, GraphBuildError> {
    let (at, definition) = reported;
    let holder = placement::holder_kind(inputs.report, definition)?;
    Ok(DefinitionProjection {
        identity: Arc::clone(neutral::definition_identity(table, at)?),
        language: definition.language(),
        kind: validation::definition_kind(&inputs.vocabulary, definition, holder)?,
        parent: neutral::optional_identity(
            table,
            definition.parent().map(|parent| parent.index()),
        )?,
    })
}

/// One projection per reference the report places in this source, in report
/// order.
fn projected_references(
    stated: &StatedSource<'_>,
) -> Result<Box<[ReferenceProjection]>, GraphBuildError> {
    stated
        .records
        .references
        .iter()
        .copied()
        .map(|reported| {
            let (reference, _) = reported;
            let named = mapping::reference_kind(reference.kind());
            ReferenceProjection::stated(
                stated.table,
                reported,
                neutral::stated_reference_kind(named, reference)?,
            )
        })
        .collect()
}
