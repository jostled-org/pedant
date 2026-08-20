//! The public Go resolver entry point.

use crate::resolution::go::snapshot::GoResolutionSnapshot;

use super::error::GoResolutionError;
use super::pipeline;
use super::target::GoProjectResolution;

/// Symbol resolution over one bounded Go resolution snapshot.
///
/// Every entry point returns a [`GoProjectResolution`], so a report is never
/// separated from the snapshot whose sources and coordinates it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoResolver;

impl GoResolver {
    /// Resolve `snapshot` from its stored fact inventories alone.
    ///
    /// This tier parses nothing a second time, reads no path, and invokes no
    /// toolchain. Names it cannot prove become possible candidates or explicit
    /// gaps rather than errors, and the one ceiling it owns — candidates per
    /// reference — refuses the whole resolution rather than truncating an
    /// answer.
    pub fn resolve_syntactic(
        snapshot: &GoResolutionSnapshot,
    ) -> Result<GoProjectResolution, GoResolutionError> {
        pipeline::resolve(snapshot)
    }
}
