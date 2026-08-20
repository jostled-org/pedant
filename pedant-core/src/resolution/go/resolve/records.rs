//! What each Go reference denotes, and how certain that answer is.
//!
//! Certainty is decided here rather than during lookup, because it depends on
//! the build predicates the reference and every definition it names inherit.
//! This tier evaluates no predicate: an unevaluated one anywhere along that
//! chain makes every candidate possible and adds the conditional-compilation
//! gap.

use std::sync::Arc;

use pedant_types::{
    CandidateInput, DefinitionHandle, ResolutionCertainty, ResolutionGap, ResolutionReportBuilder,
    ResolutionUnitHandle,
};

use crate::resolution::go::limits::GoResolutionLimits;

use super::error::GoResolutionError;
use super::index::Index;
use super::references::Denotation;

/// State one record per reference of one package context.
pub(super) fn write(
    builder: &mut ResolutionReportBuilder,
    index: &Index,
    stated: (&[Denotation], usize),
    limits: GoResolutionLimits,
) -> Result<(), GoResolutionError> {
    let (denotations, unit) = stated;
    for denotation in denotations {
        write_one(builder, index, (denotation, unit), limits)?;
    }
    Ok(())
}

/// State one reference and the answer it carries.
///
/// The ceiling is checked before the candidate list exists, so an overflowing
/// reference refuses the whole resolution rather than allocating an answer no
/// caller may read.
fn write_one(
    builder: &mut ResolutionReportBuilder,
    index: &Index,
    stated: (&Denotation, usize),
    limits: GoResolutionLimits,
) -> Result<(), GoResolutionError> {
    let (denotation, unit) = stated;
    check_candidate_capacity(denotation, limits)?;
    let conditional = is_conditional(index, denotation);
    let certainty = certainty_of(&denotation.candidates, conditional);
    let handle = builder.add_reference(
        &unit_handle(index, unit)?,
        denotation.kind,
        Arc::clone(&denotation.text),
        denotation.span.clone(),
        enclosing(index, denotation).as_ref(),
    )?;
    let retained = retained_candidates(index, denotation, certainty);
    builder.set_resolution(&handle, retained, gaps(denotation, conditional))?;
    Ok(())
}

/// Candidate fan-out is never truncated: an overflowing reference refuses the
/// whole resolution instead of reporting a misleadingly complete answer.
fn check_candidate_capacity(
    denotation: &Denotation,
    limits: GoResolutionLimits,
) -> Result<(), GoResolutionError> {
    let ceiling = limits.max_candidates_per_reference;
    let held = u64::try_from(denotation.candidates.len()).unwrap_or(u64::MAX);
    match held > u64::from(ceiling) {
        true => Err(GoResolutionError::CandidateLimitExceeded { limit: ceiling }),
        false => Ok(()),
    }
}

/// The candidates one record names, each carrying the record's own certainty.
fn retained_candidates(
    index: &Index,
    denotation: &Denotation,
    certainty: ResolutionCertainty,
) -> Box<[CandidateInput]> {
    denotation
        .candidates
        .iter()
        .filter_map(|slot| index.slot(*slot))
        .map(|slot| CandidateInput::new(slot.handle.clone(), certainty))
        .collect()
}

/// Whether an unevaluated build predicate governs this answer.
///
/// The reference's own source and every definition it names are read, because
/// either one being conditional leaves the active universe unknown.
fn is_conditional(index: &Index, denotation: &Denotation) -> bool {
    denotation.conditional
        || denotation
            .candidates
            .iter()
            .any(|slot| index.slot(*slot).is_some_and(|found| found.conditional))
}

fn certainty_of(candidates: &[usize], conditional: bool) -> ResolutionCertainty {
    match (candidates.len(), conditional) {
        (1, false) => ResolutionCertainty::Resolved,
        _ => ResolutionCertainty::Possible,
    }
}

/// Why one answer is incomplete, before the report sorts them.
fn gaps(denotation: &Denotation, conditional: bool) -> Box<[ResolutionGap]> {
    let ambiguous = (denotation.candidates.len() > 1).then_some(ResolutionGap::Ambiguous);
    let stated = conditional.then_some(ResolutionGap::ConditionalCompilation);
    denotation
        .gap
        .into_iter()
        .chain(ambiguous)
        .chain(stated)
        .collect()
}

/// The definition whose text holds one reference.
///
/// A site written outside every declaration — an import specification, a
/// package-level initializer — holds none, and states none.
fn enclosing(index: &Index, denotation: &Denotation) -> Option<DefinitionHandle> {
    index
        .slot(denotation.enclosing?)
        .map(|found| found.handle.clone())
}

/// The handle of the unit one reference is stated in.
fn unit_handle(index: &Index, unit: usize) -> Result<ResolutionUnitHandle, GoResolutionError> {
    index
        .unit(unit)
        .map(|found| found.handle.clone())
        .ok_or_else(|| GoResolutionError::UnitMapping {
            unit: u32::try_from(unit).unwrap_or(u32::MAX),
            reason: Box::from("no index was opened for this package context"),
        })
}
