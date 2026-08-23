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
use crate::node::GraphNodeKind;
use crate::projection::assembly;
use crate::projection::draft::{PlacedFragment, ProjectionPlan, SourceFragment};
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
///
/// One value, the way the Rust adapter's is: what a source contributes is
/// decided from the identities, the naming, the report, and the placed records
/// together, and splitting them across two arguments would let a pass read one
/// source's records under another source's naming.
struct StatedSource<'a> {
    /// The identities every join in this report travels through.
    table: &'a DefinitionTable,
    /// The graph naming the current build maps Go symbols into.
    vocabulary: &'a Vocabulary,
    /// The report the placed records were stated by.
    report: &'a ResolutionReport,
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
    // The unit count is the plan's own, not the report's: a Go plan states a
    // container for every admitted module beside every package context, and
    // every assembly table is indexed by plan position.
    let capacity = ProjectionCapacity::stated(
        planned.units.len(),
        report,
        &inputs.resolved,
        snapshot.edges().len(),
    );
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
                vocabulary: &inputs.vocabulary,
                report: inputs.report,
                placed,
                records: stated,
            };
            Ok(PlacedFragment {
                unit: placed.unit,
                fragment: Arc::new(derived_fragment(&source)?),
            })
        })
        .collect()
}

/// Everything one source contributes to a graph, derived from the report.
///
/// Both kind decisions are stated here and the neutral owner walks the placed
/// records, so the only Go in a Go fragment is the two answers this hands it.
fn derived_fragment(stated: &StatedSource<'_>) -> Result<SourceFragment, GraphBuildError> {
    SourceFragment::derived(
        (stated.placed, stated.table),
        stated.records,
        (
            |definition: &SymbolDefinition| definition_kind(stated, definition),
            mapping::reference_kind,
        ),
    )
}

/// The node kind one report definition takes in a Go projection.
///
/// The holder's own kind decides which callable token a method takes, so the
/// report is read for it before the naming is asked. The refusal names the
/// report-local definition whose kind this projection has no node for:
/// `GoProjectResolution` proves the Go subset before it publishes a report, so
/// it answers only for a report that reached the projection without that proof.
fn definition_kind(
    stated: &StatedSource<'_>,
    definition: &SymbolDefinition,
) -> Result<GraphNodeKind, GraphBuildError> {
    let holder = placement::holder_kind(stated.report, definition)?;
    neutral::stated_definition_kind(
        stated.vocabulary.definition(definition.kind(), holder),
        definition,
    )
}
