//! Tier 1: parse-only resolution over one snapshot's stored IR.
//!
//! Nothing here reads a path, spawns a process, or invokes a toolchain. Every
//! definition and reference comes from the `FileIr` the snapshot already
//! parsed, so a source shared by two units is parsed once and instantiated
//! twice.

use pedant_types::ResolutionTier;

use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use super::error::RustResolutionError;
use super::pipeline;
use super::promotion::NoPromotion;
use super::target::RustTargetResolution;

/// Resolve `snapshot` syntactically and bind the result to it.
pub(super) fn resolve(
    snapshot: &RustResolutionSnapshot,
) -> Result<RustTargetResolution, RustResolutionError> {
    let inventory = pipeline::inventory(snapshot, ResolutionTier::Syntactic)?;
    pipeline::finish(inventory, snapshot, &NoPromotion)
}
