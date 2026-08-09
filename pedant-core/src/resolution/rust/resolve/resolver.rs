//! The public resolver entry points.

#[cfg(feature = "semantic")]
use crate::ir::semantic::SemanticContext;
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use super::error::RustResolutionError;
#[cfg(feature = "semantic")]
use super::semantic;
use super::syntactic;
use super::target::RustTargetResolution;

/// Symbol resolution over one bounded Rust resolution snapshot.
///
/// Every entry point returns a [`RustTargetResolution`], so a report is never
/// separated from the snapshot whose sources and coordinates it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustResolver;

impl RustResolver {
    /// Resolve `snapshot` from its stored IR alone.
    ///
    /// This tier parses nothing a second time, reads no path, and invokes no
    /// toolchain. Names it cannot prove become possible candidates or explicit
    /// gaps rather than errors.
    pub fn resolve_syntactic(
        snapshot: &RustResolutionSnapshot,
    ) -> Result<RustTargetResolution, RustResolutionError> {
        syntactic::resolve(snapshot)
    }

    /// Resolve `snapshot` through the semantic database `context` holds.
    ///
    /// The database must already describe this exact snapshot: the same root,
    /// requested target, unit graph, activation, source set, and source bytes.
    /// Every difference is a `SemanticContextMismatch` refusal taken before a
    /// query runs, and there is no fallback to the parse-only tier. What the
    /// database does not prove keeps the answer Tier 1 gave it, so this tier
    /// changes candidates, gaps, and the report tier alone. A physical source
    /// instantiated under multiple snapshot units returns
    /// `SemanticSharedSourceMismatch` before the database is queried.
    #[cfg(feature = "semantic")]
    pub fn resolve_semantic(
        snapshot: &RustResolutionSnapshot,
        context: &SemanticContext,
    ) -> Result<RustTargetResolution, RustResolutionError> {
        semantic::resolve(snapshot, context)
    }
}
