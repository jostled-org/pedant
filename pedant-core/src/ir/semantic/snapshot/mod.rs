//! What a resolution snapshot claims, and the comparison a semantic database
//! must survive before it may answer for that snapshot.
//!
//! The claim is stated in pedant's own vocabulary — repository-relative paths,
//! crate names, activation, and SHA-256 digests — so no `ra_ap_*` value crosses
//! this boundary in either direction. Every difference is a refusal: there is
//! no fallback, and no query runs after one.

mod claims;
mod edges;
mod mismatch;
mod prelude;
mod sources;
mod units;
mod verified;
mod verify;

pub(crate) use claims::{
    SemanticEdgeClaim, SemanticSnapshotClaim, SemanticSourceClaim, SemanticUnitClaim,
};
pub(crate) use mismatch::SemanticSnapshotMismatch;
pub(crate) use verified::{VerifiedSnapshot, VerifiedSource, VerifiedUnit};
pub(super) use verify::verify;
