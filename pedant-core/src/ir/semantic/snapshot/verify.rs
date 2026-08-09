//! Snapshot verification orchestration.

use super::edges::check_edges;
use super::prelude::*;
use super::sources::{check_digests, verify_units};
use super::units::{CrateIndex, bind_units};
use super::{SemanticSnapshotClaim, SemanticSnapshotMismatch, VerifiedSnapshot};

/// Prove the database holds exactly what `claim` states, or say what differs.
pub(in crate::ir::semantic) fn verify(
    context: &SemanticContext,
    claim: &SemanticSnapshotClaim,
) -> Result<VerifiedSnapshot, SemanticSnapshotMismatch> {
    if claim.root != context.root {
        return Err(SemanticSnapshotMismatch::Root {
            loaded: Box::from(context.root.to_string_lossy().as_ref()),
        });
    }
    let db = context.host.raw_database();
    ra_ap_hir::attach_db(db, || {
        let index = CrateIndex::build(context);
        let crates = bind_units(context, claim, &index)?;
        check_edges(context, claim, &crates)?;
        let units = verify_units(context, claim, &crates)?;
        check_digests(context, claim)?;
        Ok(VerifiedSnapshot {
            fingerprint: claim.fingerprint,
            units,
        })
    })
}
