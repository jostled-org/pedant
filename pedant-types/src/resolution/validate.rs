//! The one validator both construction boundaries reach.
//!
//! `finish` and custom deserialization call this, so a report built in process
//! and a report decoded from JSON are held to the same rules and refuse with
//! the same value. Nothing here reads the filesystem: coordinates are checked
//! against the report's own structure, and checking them against real source
//! belongs to the core snapshot boundary.

use std::cmp::Ordering;

use crate::Language;

use super::definition::SymbolDefinition;
use super::error::{ReportCollection, ResolutionReportError};
use super::id::{DefinitionId, ResolutionUnitId};
use super::record::{ResolutionCertainty, ResolutionRecord};
use super::reference::SymbolReference;
use super::report::ResolutionReport;
use super::span::SourceSpan;
use super::unit::ResolutionUnit;

/// Prove every structural rule the report contract states.
pub(crate) fn validate(report: &ResolutionReport) -> Result<(), ResolutionReportError> {
    validate_units(report.units())?;
    validate_definitions(report.units(), report.definitions())?;
    validate_parents(report.definitions())?;
    validate_references(report.units(), report.definitions(), report.references())?;
    validate_resolutions(
        report.definitions(),
        report.references(),
        report.resolutions(),
    )
}

/// A unit's key is its whole identity: it both orders and deduplicates the
/// slice, so one adjacent scan proves both rules and a consumer joins on one
/// column whatever language a unit carries.
fn validate_units(units: &[ResolutionUnit]) -> Result<(), ResolutionReportError> {
    let collection = ReportCollection::Units;
    ceiling(collection, units.len())?;
    for (position, unit) in units.iter().enumerate() {
        dense(collection, position, unit.id().index())?;
    }
    ordered_unique(
        units,
        |left, right| left.key().cmp(right.key()),
        |unit| ResolutionReportError::DuplicateUnitKey {
            key: Box::from(unit.key()),
        },
        |position| ResolutionReportError::UnsortedEntries {
            collection,
            position,
        },
    )
}

fn validate_definitions(
    units: &[ResolutionUnit],
    definitions: &[SymbolDefinition],
) -> Result<(), ResolutionReportError> {
    let collection = ReportCollection::Definitions;
    ceiling(collection, definitions.len())?;
    for (position, definition) in definitions.iter().enumerate() {
        dense(collection, position, definition.id().index())?;
        let unit = unit_of(units, definition.unit().index())?;
        same_language(collection, position, unit, definition.language())?;
        validate_span(definition.span())?;
        same_unit(
            definitions,
            definition.parent(),
            definition.unit(),
            |parent| ResolutionReportError::ForeignParentDefinition {
                definition: definition.id().index(),
                parent,
            },
        )?;
    }
    ensure_sorted(collection, definitions, |left, right| {
        let left = (left.unit(), left.span(), left.kind(), left.name());
        let right = (right.unit(), right.span(), right.kind(), right.name());
        left.cmp(&right)
    })
}

/// Prove the definition-parent forest has no cycle.
///
/// Each definition has at most one parent, so one walk per definition with a
/// shared visit state visits every edge once. Both the state and the walk's
/// chain buffer are allocated once for the whole forest.
fn validate_parents(definitions: &[SymbolDefinition]) -> Result<(), ResolutionReportError> {
    let mut state = vec![Visit::Pending; definitions.len()];
    let mut chain: Vec<usize> = Vec::new();
    for start in 0..definitions.len() {
        walk_parents(definitions, &mut state, &mut chain, start)?;
    }
    Ok(())
}

/// Where one definition stands in the ancestor walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    /// Not yet reached.
    Pending,
    /// On the chain currently being walked.
    Active,
    /// Proved acyclic by an earlier walk.
    Done,
}

fn walk_parents(
    definitions: &[SymbolDefinition],
    state: &mut [Visit],
    chain: &mut Vec<usize>,
    start: usize,
) -> Result<(), ResolutionReportError> {
    if visit_of(state, start)? != Visit::Pending {
        return Ok(());
    }
    chain.clear();
    let mut current = Some(start);
    let mut cycle = None;
    while let Some(index) = current {
        let visit = visit_of(state, index)?;
        cycle = (visit == Visit::Active).then_some(index);
        if visit != Visit::Pending {
            break;
        }
        state[index] = Visit::Active;
        chain.push(index);
        current = definitions
            .get(index)
            .and_then(SymbolDefinition::parent)
            .map(|parent| parent.index() as usize);
    }
    for index in chain.drain(..) {
        state[index] = Visit::Done;
    }
    match cycle {
        Some(index) => Err(ResolutionReportError::DefinitionParentCycle {
            definition: index_of(index),
        }),
        None => Ok(()),
    }
}

/// Where one definition stands, refusing an ancestor the report does not hold.
fn visit_of(state: &[Visit], index: usize) -> Result<Visit, ResolutionReportError> {
    state
        .get(index)
        .copied()
        .ok_or(ResolutionReportError::UnknownDefinition {
            definition: index_of(index),
        })
}

fn validate_references(
    units: &[ResolutionUnit],
    definitions: &[SymbolDefinition],
    references: &[SymbolReference],
) -> Result<(), ResolutionReportError> {
    let collection = ReportCollection::References;
    ceiling(collection, references.len())?;
    for (position, reference) in references.iter().enumerate() {
        dense(collection, position, reference.id().index())?;
        let unit = unit_of(units, reference.unit().index())?;
        same_language(collection, position, unit, reference.language())?;
        validate_span(reference.span())?;
        let enclosing = reference.enclosing_definition();
        same_unit(definitions, enclosing, reference.unit(), |enclosing| {
            ResolutionReportError::ForeignEnclosingDefinition {
                reference: reference.id().index(),
                enclosing,
            }
        })?;
    }
    ensure_sorted(collection, references, |left, right| {
        let left = (left.unit(), left.span(), left.kind(), left.text());
        let right = (right.unit(), right.span(), right.kind(), right.text());
        left.cmp(&right)
    })
}

/// A named definition exists and sits in the unit that named it.
///
/// The parent rule and the enclosing rule are one rule read through two
/// accessors, so a caller supplies only the refusal it owns.
///
/// A record naming no definition names nothing to refuse.
fn same_unit(
    definitions: &[SymbolDefinition],
    named: Option<DefinitionId>,
    unit: ResolutionUnitId,
    foreign: impl Fn(u32) -> ResolutionReportError,
) -> Result<(), ResolutionReportError> {
    let named = match named {
        Some(named) => named,
        None => return Ok(()),
    };
    let owner = definition_of(definitions, named.index())?;
    match owner.unit() == unit {
        true => Ok(()),
        false => Err(foreign(named.index())),
    }
}

fn validate_resolutions(
    definitions: &[SymbolDefinition],
    references: &[SymbolReference],
    records: &[ResolutionRecord],
) -> Result<(), ResolutionReportError> {
    let collection = ReportCollection::Resolutions;
    ceiling(collection, records.len())?;
    for record in records {
        reference_of(references, record.reference().index())?;
        validate_candidates(definitions, record)?;
        validate_gaps(record)?;
        validate_certainty(record)?;
    }
    ordered_unique(
        records,
        |left, right| left.reference().cmp(&right.reference()),
        |record| ResolutionReportError::DuplicateResolution {
            reference: record.reference().index(),
        },
        |position| ResolutionReportError::UnsortedEntries {
            collection,
            position,
        },
    )?;
    complete_records(references.len(), records)
}

fn validate_candidates(
    definitions: &[SymbolDefinition],
    record: &ResolutionRecord,
) -> Result<(), ResolutionReportError> {
    for candidate in record.candidates() {
        definition_of(definitions, candidate.definition().index())?;
    }
    let reference = record.reference().index();
    ordered_unique(
        record.candidates(),
        |left, right| left.definition().cmp(&right.definition()),
        |candidate| ResolutionReportError::DuplicateCandidate {
            reference,
            definition: candidate.definition().index(),
        },
        |position| ResolutionReportError::UnsortedCandidates {
            reference,
            position,
        },
    )
}

fn validate_gaps(record: &ResolutionRecord) -> Result<(), ResolutionReportError> {
    let reference = record.reference().index();
    ordered_unique(
        record.gaps(),
        |left, right| left.cmp(right),
        |gap| ResolutionReportError::DuplicateGap {
            reference,
            gap: *gap,
        },
        |position| ResolutionReportError::UnsortedGaps {
            reference,
            position,
        },
    )
}

/// A record is resolved to one definition, possible, or candidate-free.
fn validate_certainty(record: &ResolutionRecord) -> Result<(), ResolutionReportError> {
    let resolved = record
        .candidates()
        .iter()
        .filter(|candidate| candidate.certainty() == ResolutionCertainty::Resolved)
        .count();
    let possible = record.candidates().len() - resolved;
    match (resolved, possible) {
        (0, 0) => require_gap(record),
        (0, _) => Ok(()),
        (_, 0) => require_single_resolved(record),
        _ => Err(ResolutionReportError::MixedCandidateCertainty {
            reference: record.reference().index(),
        }),
    }
}

fn require_gap(record: &ResolutionRecord) -> Result<(), ResolutionReportError> {
    match record.gaps().is_empty() {
        true => Err(ResolutionReportError::EmptyResolution {
            reference: record.reference().index(),
        }),
        false => Ok(()),
    }
}

fn require_single_resolved(record: &ResolutionRecord) -> Result<(), ResolutionReportError> {
    let reference = record.reference().index();
    let candidates = index_of(record.candidates().len());
    match (candidates, record.gaps().is_empty()) {
        (1, true) => Ok(()),
        (1, false) => Err(ResolutionReportError::ResolvedWithGaps { reference }),
        _ => Err(ResolutionReportError::ResolvedCandidateCount {
            reference,
            candidates,
        }),
    }
}

/// Every reference carries exactly one record.
///
/// Records are already proved sorted, unique, and in range, so a count that
/// falls short names the first position whose record is not its own index.
fn complete_records(
    references: usize,
    records: &[ResolutionRecord],
) -> Result<(), ResolutionReportError> {
    match records.len() == references {
        true => Ok(()),
        false => Err(ResolutionReportError::MissingResolution {
            reference: first_uncovered(records),
        }),
    }
}

fn first_uncovered(records: &[ResolutionRecord]) -> u32 {
    records
        .iter()
        .enumerate()
        .find(|(position, record)| index_of(*position) != record.reference().index())
        .map(|(position, _)| index_of(position))
        .unwrap_or_else(|| index_of(records.len()))
}

fn validate_span(span: &SourceSpan) -> Result<(), ResolutionReportError> {
    normalized_path(span.file())?;
    match (span.start() < span.end(), span.start() == span.end()) {
        (true, _) => Ok(()),
        (false, true) => Err(ResolutionReportError::EmptySiteSpan {
            path: Box::from(span.file()),
        }),
        (false, false) => Err(ResolutionReportError::ReversedSiteSpan {
            path: Box::from(span.file()),
        }),
    }
}

/// A repository-relative `/`-separated path with no empty, `.`, or `..` part.
///
/// An empty path splits into one empty component, so the component rule already
/// owns it; a separate emptiness clause would be a branch no report could
/// reach on its own.
fn normalized_path(path: &str) -> Result<(), ResolutionReportError> {
    let rejected = path.contains('\\')
        || path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."));
    match rejected {
        true => Err(ResolutionReportError::InvalidSourcePath {
            path: Box::from(path),
        }),
        false => Ok(()),
    }
}

/// The first position that ties or falls below its predecessor, and whether it
/// was a tie. Every ordering rule the report states is one of those two
/// answers, so the scan is written once and each caller names what a tie means.
fn adjacent_conflict<T>(
    items: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
) -> Option<(usize, bool)> {
    let (position, pair) = items
        .windows(2)
        .enumerate()
        .find(|(_, pair)| compare(&pair[0], &pair[1]) != Ordering::Less)?;
    Some((position + 1, compare(&pair[0], &pair[1]) == Ordering::Equal))
}

/// A collection whose order is strict: a tie is a duplicate, not a near miss.
fn ordered_unique<T>(
    items: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
    duplicate: impl Fn(&T) -> ResolutionReportError,
    unsorted: impl Fn(u32) -> ResolutionReportError,
) -> Result<(), ResolutionReportError> {
    match adjacent_conflict(items, compare) {
        Some((position, true)) => Err(duplicate(&items[position])),
        Some((position, false)) => Err(unsorted(index_of(position))),
        None => Ok(()),
    }
}

/// A collection whose order admits ties, because its identity is not its key.
fn ensure_sorted<T>(
    collection: ReportCollection,
    items: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
) -> Result<(), ResolutionReportError> {
    match adjacent_conflict(items, compare) {
        Some((position, false)) => Err(ResolutionReportError::UnsortedEntries {
            collection,
            position: index_of(position),
        }),
        _ => Ok(()),
    }
}

fn dense(
    collection: ReportCollection,
    position: usize,
    id: u32,
) -> Result<(), ResolutionReportError> {
    let position = index_of(position);
    match position == id {
        true => Ok(()),
        false => Err(ResolutionReportError::NonDenseId {
            collection,
            position,
            id,
        }),
    }
}

/// A collection longer than the identifier width can hold no dense identifiers.
fn ceiling(collection: ReportCollection, len: usize) -> Result<(), ResolutionReportError> {
    match u32::try_from(len) {
        Ok(_) => Ok(()),
        Err(_) => Err(capacity_error(collection)),
    }
}

fn capacity_error(collection: ReportCollection) -> ResolutionReportError {
    match collection {
        ReportCollection::Units => ResolutionReportError::UnitCapacityExceeded { limit: u32::MAX },
        ReportCollection::Definitions => {
            ResolutionReportError::DefinitionCapacityExceeded { limit: u32::MAX }
        }
        ReportCollection::References => {
            ResolutionReportError::ReferenceCapacityExceeded { limit: u32::MAX }
        }
        ReportCollection::Resolutions => {
            ResolutionReportError::ResolutionCapacityExceeded { limit: u32::MAX }
        }
    }
}

fn unit_of(units: &[ResolutionUnit], unit: u32) -> Result<&ResolutionUnit, ResolutionReportError> {
    units
        .get(unit as usize)
        .ok_or(ResolutionReportError::UnknownUnit { unit })
}

fn definition_of(
    definitions: &[SymbolDefinition],
    definition: u32,
) -> Result<&SymbolDefinition, ResolutionReportError> {
    definitions
        .get(definition as usize)
        .ok_or(ResolutionReportError::UnknownDefinition { definition })
}

fn reference_of(
    references: &[SymbolReference],
    reference: u32,
) -> Result<&SymbolReference, ResolutionReportError> {
    references
        .get(reference as usize)
        .ok_or(ResolutionReportError::UnknownReference { reference })
}

/// A record carries its unit's language, named by where it sits.
///
/// The refusal names the offender's own coordinates, so a bad definition and a
/// bad reference against one unit are two values rather than one.
fn same_language(
    collection: ReportCollection,
    position: usize,
    unit: &ResolutionUnit,
    claimed: Language,
) -> Result<(), ResolutionReportError> {
    match claimed == unit.language() {
        true => Ok(()),
        false => Err(ResolutionReportError::UnitLanguageMismatch {
            collection,
            position: index_of(position),
            unit: unit.id().index(),
            claimed,
            unit_language: unit.language(),
        }),
    }
}

fn index_of(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
