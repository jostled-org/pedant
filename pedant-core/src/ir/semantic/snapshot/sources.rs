//! Verification of unit source sets and source bytes.

use super::prelude::*;
use super::{
    SemanticSnapshotClaim, SemanticSnapshotMismatch, SemanticSourceClaim, SemanticUnitClaim,
    VerifiedSource, VerifiedUnit,
};

/// Every unit's module closure in the database must be the claimed source set.
pub(super) fn verify_units(
    context: &SemanticContext,
    claim: &SemanticSnapshotClaim,
    crates: &[Crate],
) -> Result<Box<[VerifiedUnit]>, SemanticSnapshotMismatch> {
    claim
        .units
        .iter()
        .zip(crates)
        .map(|(unit, krate)| verify_unit(context, unit, *krate))
        .collect()
}

fn verify_unit(
    context: &SemanticContext,
    unit: &SemanticUnitClaim,
    krate: Crate,
) -> Result<VerifiedUnit, SemanticSnapshotMismatch> {
    let owned = module_sources(context, krate);
    let held: BTreeSet<&str> = owned.iter().map(|path| &**path).collect();
    let claimed: BTreeSet<&str> = unit.sources.iter().map(|path| &**path).collect();
    let disagreement = claimed
        .symmetric_difference(&held)
        .next()
        .map(|path| Box::<str>::from(*path));
    match disagreement {
        Some(detail) => Err(SemanticSnapshotMismatch::PathSet {
            name: Box::from(&*unit.name),
            detail,
        }),
        None => Ok(VerifiedUnit {
            krate,
            sources: unit
                .sources
                .iter()
                .map(|path| VerifiedSource {
                    path: Arc::clone(path),
                    absolute: context.absolute(path),
                })
                .collect(),
        }),
    }
}

/// Every repository-relative source the database's module tree gives a crate.
fn module_sources(context: &SemanticContext, krate: Crate) -> BTreeSet<Box<str>> {
    let db = context.host.raw_database();
    krate
        .modules(db)
        .into_iter()
        .filter_map(|module| module.definition_source_file_id(db).file_id())
        .map(|file| file.file_id(db))
        .filter_map(|file| context.relative_path(file))
        .collect()
}

/// Every claimed source must hold the exact snapshotted bytes.
pub(super) fn check_digests(
    context: &SemanticContext,
    claim: &SemanticSnapshotClaim,
) -> Result<(), SemanticSnapshotMismatch> {
    let analysis = context.host.analysis();
    for source in &claim.sources {
        check_digest(context, &analysis, source)?;
    }
    Ok(())
}

/// One claimed source must hold the exact snapshotted bytes.
///
/// A source the database does not hold, and a source it will not hand over,
/// are each named for what they are: neither is a claim that the database
/// holds other bytes.
fn check_digest(
    context: &SemanticContext,
    analysis: &Analysis,
    source: &SemanticSourceClaim,
) -> Result<(), SemanticSnapshotMismatch> {
    let Some(file) = context.file_id(&context.absolute(&source.path)) else {
        return Err(SemanticSnapshotMismatch::SourceAbsent {
            path: Box::from(&*source.path),
        });
    };
    let Ok(text) = analysis.file_text(file) else {
        return Err(SemanticSnapshotMismatch::SourceUnreadable {
            path: Box::from(&*source.path),
        });
    };
    match crate::hash::digest_bytes(text.as_bytes()) == source.digest {
        true => Ok(()),
        false => Err(SemanticSnapshotMismatch::SourceDigest {
            path: Box::from(&*source.path),
        }),
    }
}
