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

use super::denotation::Denotation;
use super::error::GoResolutionError;
use super::index::{Index, Slot};

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
    let named = named_definitions(index, denotation)?;
    let conditional = is_conditional(&named, denotation);
    let certainty = certainty_of(denotation, conditional);
    let handle = builder.add_reference(
        &unit_handle(index, unit)?,
        denotation.kind,
        Arc::clone(&denotation.text),
        denotation.span.clone(),
        enclosing(index, denotation)?.as_ref(),
    )?;
    let retained = retained_candidates(&named, certainty);
    builder.set_resolution(&handle, retained, gaps(denotation, conditional))?;
    Ok(())
}

/// Every definition one reference's candidates name.
///
/// Read once, because certainty and retention ask the same question of the same
/// positions. A position the index does not answer for refuses here: filtering
/// it away would state fewer candidates than the ceiling counted, which is the
/// silent truncation this tier does not perform.
fn named_definitions<'index>(
    index: &'index Index,
    denotation: &Denotation,
) -> Result<Box<[&'index Slot]>, GoResolutionError> {
    denotation
        .candidates
        .iter()
        .map(|slot| recorded(index, *slot))
        .collect()
}

/// The definition one recorded position names.
fn recorded(index: &Index, slot: usize) -> Result<&Slot, GoResolutionError> {
    index
        .slot(slot)
        .ok_or_else(|| GoResolutionError::DefinitionMapping {
            slot: u32::try_from(slot).unwrap_or(u32::MAX),
            reason: Box::from("no definition was recorded at this position"),
        })
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
fn retained_candidates(named: &[&Slot], certainty: ResolutionCertainty) -> Box<[CandidateInput]> {
    named
        .iter()
        .map(|slot| CandidateInput::new(slot.handle.clone(), certainty))
        .collect()
}

/// Whether an unevaluated build predicate governs this answer.
///
/// The reference's own source and every definition it names are read, because
/// either one being conditional leaves the active universe unknown.
fn is_conditional(named: &[&Slot], denotation: &Denotation) -> bool {
    denotation.conditional || named.iter().any(|found| found.conditional)
}

/// How certain one answer is.
///
/// One candidate no predicate governs is the only resolved answer, and an
/// answer whose target is chosen at run time is never one however few
/// candidates it names.
fn certainty_of(denotation: &Denotation, conditional: bool) -> ResolutionCertainty {
    match (
        denotation.candidates.len(),
        conditional,
        denotation.possible_only,
    ) {
        (1, false, false) => ResolutionCertainty::Resolved,
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
fn enclosing(
    index: &Index,
    denotation: &Denotation,
) -> Result<Option<DefinitionHandle>, GoResolutionError> {
    denotation
        .enclosing
        .map(|slot| recorded(index, slot).map(|found| found.handle.clone()))
        .transpose()
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
