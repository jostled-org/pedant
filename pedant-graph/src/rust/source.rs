//! The complete local claim one source states.
//!
//! One module says what a source contributes to a graph, and it says it twice
//! because a projection is either derived or reused. Deriving states the claim
//! as records; comparing asks whether records already held still state it. Both
//! readings walk the same placed records in the same order, so a column one of
//! them reads and the other does not cannot exist without failing the structural
//! predicate that holds them to the same inventory.
//!
//! Nothing here is dense. Cross-source joins — logical parents, enclosing
//! definitions, candidate targets — are read out of the current report's own
//! identity table, so a projection stays true while the graph around it is
//! renumbered.

use std::sync::Arc;

use pedant_types::{ResolutionRecord, SymbolDefinition, SymbolReference};

use crate::edge::GraphEdgeKind;
use crate::error::GraphBuildError;
use crate::reference::GraphReferenceKind;

use crate::projection::draft::{
    CandidateProjection, DefinitionProjection, ReferenceProjection, SourceFragment,
};
use crate::projection::placement::{DefinitionIdentity, DefinitionTable, PlacedSource};
use crate::projection::validation as neutral;

use super::mapping::{self, Vocabulary};
use super::validation;

/// Every record one source states, in report order.
///
/// The records are borrowed from the report rather than copied out of it: this
/// is what one source's projection is compared against and what it is derived
/// from, and both readings must be over the one placement.
#[derive(Default)]
pub(crate) struct SourceRecords<'a> {
    /// Every definition declared in the source, beside its report position.
    pub(crate) definitions: Vec<(u32, &'a SymbolDefinition)>,
    /// Every reference stated in the source, beside the record that answered it.
    pub(crate) references: Vec<(&'a SymbolReference, &'a ResolutionRecord)>,
}

/// Everything one source's projection is decided from.
pub(crate) struct StatedSource<'a> {
    /// The identities every join in this report travels through.
    pub(crate) table: &'a DefinitionTable,
    /// The graph vocabulary the current build maps symbols into.
    pub(crate) vocabulary: &'a Vocabulary,
    /// The unit and source identity this projection answers for.
    pub(crate) placed: &'a PlacedSource,
    /// The records the current report places in this source.
    pub(crate) records: &'a SourceRecords<'a>,
}

/// Everything one source contributes to a graph, derived from the report.
pub(crate) fn derived_projection(
    stated: &StatedSource<'_>,
) -> Result<SourceFragment, GraphBuildError> {
    let definitions: Box<[DefinitionProjection]> = stated
        .records
        .definitions
        .iter()
        .copied()
        .map(|reported| projected_definition(stated, reported))
        .collect::<Result<_, GraphBuildError>>()?;
    let references: Box<[ReferenceProjection]> = stated
        .records
        .references
        .iter()
        .copied()
        .map(|reported| projected_reference(stated.table, reported))
        .collect::<Result<_, GraphBuildError>>()?;
    Ok(SourceFragment {
        source: stated.placed.source.shared(),
        definitions,
        references,
    })
}

/// One definition projection, at the report position that states it.
fn projected_definition(
    stated: &StatedSource<'_>,
    reported: (u32, &SymbolDefinition),
) -> Result<DefinitionProjection, GraphBuildError> {
    let (at, definition) = reported;
    Ok(DefinitionProjection {
        identity: Arc::clone(neutral::definition_identity(stated.table, at)?),
        language: definition.language(),
        kind: validation::definition_kind(stated.vocabulary, definition)?,
        parent: projected_join(
            stated.table,
            definition.parent().map(|parent| parent.index()),
        )?,
    })
}

/// The identity of the definition one stated join names, when it names one.
fn projected_join(
    table: &DefinitionTable,
    stated: Option<u32>,
) -> Result<Option<Arc<DefinitionIdentity>>, GraphBuildError> {
    match stated {
        None => Ok(None),
        Some(at) => Ok(Some(Arc::clone(neutral::definition_identity(table, at)?))),
    }
}

/// One reference and every candidate its answer offered.
fn projected_reference(
    table: &DefinitionTable,
    reported: (&SymbolReference, &ResolutionRecord),
) -> Result<ReferenceProjection, GraphBuildError> {
    let (reference, record) = reported;
    let kind = validation::reference_kind(reference)?;
    Ok(ReferenceProjection {
        language: reference.language(),
        kind,
        text: Arc::from(reference.text()),
        span: SymbolReference::span(reference).clone(),
        gaps: record.gaps().into(),
        enclosing: projected_join(
            table,
            reference
                .enclosing_definition()
                .map(|enclosing| enclosing.index()),
        )?,
        candidates: projected_candidates(table, (record, mapping::candidate_edge_kind(kind)))?,
    })
}

/// Every candidate one answer offered, in stated order.
fn projected_candidates(
    table: &DefinitionTable,
    answered: (&ResolutionRecord, GraphEdgeKind),
) -> Result<Box<[CandidateProjection]>, GraphBuildError> {
    let (record, kind) = answered;
    record
        .candidates()
        .iter()
        .map(|candidate| {
            let target = neutral::definition_identity(table, candidate.definition().index())?;
            Ok(CandidateProjection {
                target: Arc::clone(target),
                kind,
                certainty: mapping::certainty(candidate.certainty()),
            })
        })
        .collect()
}

/// Whether one retained projection states exactly what this report states for
/// its source.
///
/// Read column for column against the report itself. Comparing it with a
/// projection derived from that report would have done the work the retained
/// one exists to save, and a key narrow enough to skip the reading would answer
/// a changed claim with a stale projection.
pub(crate) fn states_current_claim(held: &SourceFragment, stated: &StatedSource<'_>) -> bool {
    held.source == stated.placed.source
        && states_definitions(&held.definitions, stated)
        && states_references(&held.references, stated.table, &stated.records.references)
}

/// Every retained definition is the definition the report states at its
/// position, and the report states no other.
fn states_definitions(held: &[DefinitionProjection], stated: &StatedSource<'_>) -> bool {
    let reported = &stated.records.definitions;
    held.len() == reported.len()
        && held
            .iter()
            .zip(reported.iter().copied())
            .all(|(projection, definition)| states_definition(projection, stated, definition))
}

/// One retained definition states the identity, language, vocabulary, and
/// logical owner the report states for it.
fn states_definition(
    held: &DefinitionProjection,
    stated: &StatedSource<'_>,
    reported: (u32, &SymbolDefinition),
) -> bool {
    let (at, definition) = reported;
    stated.table.identity(at) == Some(&held.identity)
        && held.language == definition.language()
        && stated
            .vocabulary
            .states_definition(&held.kind, definition.kind())
        && states_join(
            held.parent.as_ref(),
            stated.table,
            definition.parent().map(|parent| parent.index()),
        )
}

/// Every retained reference is the reference the report states at its position,
/// and the report states no other.
fn states_references(
    held: &[ReferenceProjection],
    table: &DefinitionTable,
    reported: &[(&SymbolReference, &ResolutionRecord)],
) -> bool {
    held.len() == reported.len()
        && held
            .iter()
            .zip(reported.iter().copied())
            .all(|(projection, reference)| states_reference(projection, table, reference))
}

/// One retained reference states the site, the answer, and every candidate the
/// report states for it.
fn states_reference(
    held: &ReferenceProjection,
    table: &DefinitionTable,
    reported: (&SymbolReference, &ResolutionRecord),
) -> bool {
    let (reference, record) = reported;
    // A kind this projection does not name is never a match: the source is
    // derived again, and the derivation states the refusal that kind earns.
    let Some(kind) = mapping::reference_kind(reference.kind()) else {
        return false;
    };
    held.language == reference.language()
        && held.kind == kind
        && *held.text == *reference.text()
        && held.span == *SymbolReference::span(reference)
        && *held.gaps == *record.gaps()
        && states_join(
            held.enclosing.as_ref(),
            table,
            reference
                .enclosing_definition()
                .map(|enclosing| enclosing.index()),
        )
        && states_candidates(&held.candidates, table, (record, kind))
}

/// One retained join names the definition the report states, whether or not the
/// report states one at all.
///
/// A join the current table cannot answer for is not a match: the source is
/// derived again, and the derivation states the refusal that join earns.
fn states_join(
    held: Option<&Arc<DefinitionIdentity>>,
    table: &DefinitionTable,
    stated: Option<u32>,
) -> bool {
    match (held, stated) {
        (None, None) => true,
        (Some(identity), Some(at)) => table.identity(at) == Some(identity),
        (None, Some(_)) | (Some(_), None) => false,
    }
}

/// Every retained candidate names the target, edge kind, and certainty the
/// answer states, in the order it states them.
fn states_candidates(
    held: &[CandidateProjection],
    table: &DefinitionTable,
    answered: (&ResolutionRecord, GraphReferenceKind),
) -> bool {
    let (record, kind) = answered;
    let edge = mapping::candidate_edge_kind(kind);
    held.len() == record.candidates().len()
        && held
            .iter()
            .zip(record.candidates())
            .all(|(candidate, stated)| {
                candidate.kind == edge
                    && candidate.certainty == mapping::certainty(stated.certainty())
                    && table.identity(stated.definition().index()) == Some(&candidate.target)
            })
}
