//! Turning stated drafts into a sorted, densely identified, validated report.
//!
//! Insertion order is a property of how a producer walked the filesystem, so it
//! cannot decide identifiers. Every collection is sorted by a stable structural
//! key first, and identifiers are the positions that sort produced.
//!
//! The drafts are consumed rather than read: the writer is finished with them,
//! so every string, span, and gap set moves into the report instead of being
//! copied out of a slice the caller is about to drop.

use std::cmp::Ordering;
use std::iter;

use crate::Language;

use super::builder::{DraftDefinition, DraftReference, DraftResolution, DraftUnit};
use super::definition::SymbolDefinition;
use super::error::ResolutionReportError;
use super::id::{DefinitionId, ReferenceId, ResolutionUnitId};
use super::record::{ResolutionCandidate, ResolutionRecord};
use super::reference::SymbolReference;
use super::report::{ResolutionReport, ResolutionTier};
use super::unit::ResolutionUnit;
use super::validate::validate;

/// Sort every collection, remap local indices to dense identifiers, and hand
/// the result to the shared validator.
pub(crate) fn assemble(
    tier: ResolutionTier,
    units: Vec<DraftUnit>,
    definitions: Vec<DraftDefinition>,
    references: Vec<DraftReference>,
    resolutions: Vec<Option<DraftResolution>>,
) -> Result<ResolutionReport, ResolutionReportError> {
    let languages: Box<[Language]> = units.iter().map(|unit| unit.language).collect();
    let (units, unit_ids) = rank(units, |left, right| left.key.cmp(&right.key));
    let (definitions, definition_ids) = rank(definitions, |left, right| {
        definition_order(left, right, &unit_ids)
    });
    let (answered, _) = rank(pair(references, resolutions), |left, right| {
        reference_order(&left.0, &right.0, &unit_ids)
    });
    let (references, resolutions): (Vec<DraftReference>, Vec<Option<DraftResolution>>) =
        answered.into_iter().unzip();
    let report = ResolutionReport::new(
        tier,
        sorted_units(units),
        sorted_definitions(definitions, &languages, &unit_ids, &definition_ids),
        sorted_references(references, &languages, &unit_ids, &definition_ids),
        records(resolutions, &definition_ids)?,
    );
    validate(&report)?;
    Ok(report)
}

/// Every reference beside the answer stated for it.
///
/// A reference whose slot is absent pairs with `None`, so the record rule
/// refuses it by name rather than the reference disappearing from the report.
fn pair(
    references: Vec<DraftReference>,
    resolutions: Vec<Option<DraftResolution>>,
) -> Vec<(DraftReference, Option<DraftResolution>)> {
    references
        .into_iter()
        .zip(resolutions.into_iter().chain(iter::repeat_with(|| None)))
        .collect()
}

/// The sorted drafts, and the position each local index moved to.
///
/// The sort is stable, so drafts a comparator calls equal keep the order the
/// writer stated them in.
fn rank<T>(items: Vec<T>, compare: impl Fn(&T, &T) -> Ordering) -> (Vec<T>, Box<[u32]>) {
    let mut paired: Vec<(usize, T)> = items.into_iter().enumerate().collect();
    paired.sort_by(|left, right| compare(&left.1, &right.1));
    let mut positions = vec![0_u32; paired.len()];
    let sorted = paired
        .into_iter()
        .enumerate()
        .map(|(index, (local, item))| {
            positions[local] = index_of(index);
            item
        })
        .collect();
    (sorted, positions.into_boxed_slice())
}

fn definition_order(left: &DraftDefinition, right: &DraftDefinition, unit_ids: &[u32]) -> Ordering {
    let left = (
        unit_ids[left.unit as usize],
        &left.span,
        left.kind,
        &left.name,
    );
    let right = (
        unit_ids[right.unit as usize],
        &right.span,
        right.kind,
        &right.name,
    );
    left.cmp(&right)
}

fn reference_order(left: &DraftReference, right: &DraftReference, unit_ids: &[u32]) -> Ordering {
    let left = (
        unit_ids[left.unit as usize],
        &left.span,
        left.kind,
        &left.text,
    );
    let right = (
        unit_ids[right.unit as usize],
        &right.span,
        right.kind,
        &right.text,
    );
    left.cmp(&right)
}

fn sorted_units(units: Vec<DraftUnit>) -> Box<[ResolutionUnit]> {
    units
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            ResolutionUnit::new(
                ResolutionUnitId::new(index_of(index)),
                draft.language,
                draft.key,
                draft.name,
            )
        })
        .collect()
}

fn sorted_definitions(
    definitions: Vec<DraftDefinition>,
    languages: &[Language],
    unit_ids: &[u32],
    definition_ids: &[u32],
) -> Box<[SymbolDefinition]> {
    definitions
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let unit = draft.unit as usize;
            SymbolDefinition::new(
                DefinitionId::new(index_of(index)),
                ResolutionUnitId::new(unit_ids[unit]),
                languages[unit],
                draft.kind,
                draft.name,
                draft.span,
                draft
                    .parent
                    .map(|parent| DefinitionId::new(definition_ids[parent as usize])),
            )
        })
        .collect()
}

fn sorted_references(
    references: Vec<DraftReference>,
    languages: &[Language],
    unit_ids: &[u32],
    definition_ids: &[u32],
) -> Box<[SymbolReference]> {
    references
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let unit = draft.unit as usize;
            SymbolReference::new(
                ReferenceId::new(index_of(index)),
                ResolutionUnitId::new(unit_ids[unit]),
                languages[unit],
                draft.kind,
                draft.text,
                draft.span,
                draft
                    .enclosing
                    .map(|enclosing| DefinitionId::new(definition_ids[enclosing as usize])),
            )
        })
        .collect()
}

/// One record per reference, in the sorted reference order.
fn records(
    resolutions: Vec<Option<DraftResolution>>,
    definition_ids: &[u32],
) -> Result<Box<[ResolutionRecord]>, ResolutionReportError> {
    resolutions
        .into_iter()
        .enumerate()
        .map(|(index, stated)| {
            let reference = index_of(index);
            let stated = stated.ok_or(ResolutionReportError::MissingResolution { reference })?;
            Ok(record(reference, stated, definition_ids))
        })
        .collect()
}

fn record(reference: u32, stated: DraftResolution, definition_ids: &[u32]) -> ResolutionRecord {
    let mut candidates: Vec<ResolutionCandidate> = stated
        .candidates
        .into_vec()
        .into_iter()
        .map(|(definition, certainty)| {
            let definition = DefinitionId::new(definition_ids[definition as usize]);
            ResolutionCandidate::new(definition, certainty)
        })
        .collect();
    candidates.sort_by_key(ResolutionCandidate::definition);
    let mut gaps = stated.gaps;
    gaps.sort_unstable();
    let candidates = candidates.into_boxed_slice();
    ResolutionRecord::new(ReferenceId::new(reference), candidates, gaps)
}

fn index_of(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
