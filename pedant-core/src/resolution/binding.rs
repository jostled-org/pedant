//! Binding one report to the snapshot it claims to describe.
//!
//! A report states units by a stable key and sites by a kind from one closed
//! vocabulary, and proving both against a snapshot is the same walk whichever
//! language produced the report. One owner, because a copy per language is one
//! implementation a later fix reaches only half of.
//!
//! What stays per-language is the part that is genuinely per-language: which
//! kinds a language emits, what a snapshot unit's key spells, and what each
//! seam's refusal is called. Those are handed in; the walks are not.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{ReferenceKind, ResolutionReport, ResolutionUnit, SymbolKind};

use super::identity::position;

/// Why one report does not describe the snapshot it was bound against.
///
/// Crate-private and never published: each language's boundary maps it into the
/// typed error its own seam refuses through, so a caller still reads which
/// stage refused rather than one shared cause every stage returns.
pub(crate) enum BindingFault {
    /// The report and the snapshot state different numbers of units, so no
    /// report-local identifier is the one that failed to bind.
    UnitCountMismatch {
        /// How many units the report states.
        report: u32,
        /// How many units the snapshot holds.
        snapshot: u32,
    },
    /// One report unit's key names no unit the snapshot holds.
    UnknownKey {
        /// The report-local unit identifier that could not be bound.
        unit: u32,
    },
}

/// Every snapshot unit under its stable key.
///
/// Keyed once rather than searched per report unit, so binding a report of N
/// units formats N keys rather than one key per candidate per report unit.
pub(crate) fn keyed<U>(units: &[U], key: impl Fn(&U) -> Arc<str>) -> BTreeMap<Arc<str>, &U> {
    units.iter().map(|unit| (key(unit), unit)).collect()
}

/// Bind every report unit to the snapshot unit carrying its key.
pub(crate) fn bind_by_key<'units, U, B>(
    stated: &[ResolutionUnit],
    units: &'units [U],
    key: impl Fn(&U) -> Arc<str>,
    bind: impl Fn(&ResolutionUnit, &'units U) -> B,
) -> Result<Box<[B]>, BindingFault> {
    match stated.len() == units.len() {
        false => Err(BindingFault::UnitCountMismatch {
            report: position(stated.len()),
            snapshot: position(units.len()),
        }),
        true => {
            let table = keyed(units, key);
            stated
                .iter()
                .map(|unit| bound(&table, unit, &bind))
                .collect()
        }
    }
}

/// The first definition whose kind the language does not emit.
pub(crate) fn first_unsupported_definition(
    report: &ResolutionReport,
    emits: impl Fn(SymbolKind) -> bool,
) -> Option<(u32, SymbolKind)> {
    report
        .definitions()
        .iter()
        .find(|definition| !emits(definition.kind()))
        .map(|definition| (definition.id().index(), definition.kind()))
}

/// The first reference whose kind the language does not emit.
pub(crate) fn first_unsupported_reference(
    report: &ResolutionReport,
    emits: impl Fn(ReferenceKind) -> bool,
) -> Option<(u32, ReferenceKind)> {
    report
        .references()
        .iter()
        .find(|reference| !emits(reference.kind()))
        .map(|reference| (reference.id().index(), reference.kind()))
}

/// One report unit bound to the snapshot unit its key selects.
fn bound<'units, U, B>(
    table: &BTreeMap<Arc<str>, &'units U>,
    unit: &ResolutionUnit,
    bind: &impl Fn(&ResolutionUnit, &'units U) -> B,
) -> Result<B, BindingFault> {
    let found = table.get(unit.key()).ok_or(BindingFault::UnknownKey {
        unit: unit.id().index(),
    })?;
    Ok(bind(unit, found))
}
