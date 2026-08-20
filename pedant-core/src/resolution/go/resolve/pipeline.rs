//! The one order a Go resolution is written in.
//!
//! Every package context is stated before any reference is classified, because
//! a call in one package names a definition in another and a report cannot
//! point at a definition it has not stated yet. Everything after that is a join
//! over tables already built.

use pedant_types::{ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier};

use crate::resolution::go::limits::GoResolutionLimits;
use crate::resolution::go::snapshot::GoResolutionSnapshot;

use super::corpus::Corpus;
use super::definitions;
use super::error::GoResolutionError;
use super::records;
use super::references;
use super::target::GoProjectResolution;

/// Resolve one snapshot into a validated, snapshot-bound report.
pub(super) fn resolve(
    snapshot: &GoResolutionSnapshot,
) -> Result<GoProjectResolution, GoResolutionError> {
    let report = write(snapshot, snapshot.limits())?;
    GoProjectResolution::try_new(snapshot, report)
}

/// State every unit, definition, reference, and record one snapshot denotes.
fn write(
    snapshot: &GoResolutionSnapshot,
    limits: GoResolutionLimits,
) -> Result<pedant_types::ResolutionReport, GoResolutionError> {
    let corpus = Corpus::of(snapshot);
    let mut builder =
        ResolutionReportBuilder::new(ResolutionTier::Syntactic, ResolutionReportLimits::default());
    let index = definitions::state(&mut builder, &corpus)?;
    for position in 0..corpus.units().len() {
        let Some(unit) = corpus.unit(position) else {
            continue;
        };
        let stated = references::of_unit(&index, &corpus, (position, unit));
        records::write(&mut builder, &index, (&stated, position), limits)?;
    }
    Ok(builder.finish()?)
}
