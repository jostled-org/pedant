//! The two public Go entry points.
//!
//! Both delegate to the same private projection path over their supplied
//! arguments alone. Neither loads a project, walks a package directory, reads a
//! source, extracts a grammar fact, or runs the resolver.

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionSnapshot};

use crate::error::GraphBuildError;
use crate::graph::CodeGraph;
use crate::limits::GraphLimits;

use super::projection;

/// Project one snapshot-bound Go resolution under the default ceilings.
///
/// ```no_run
/// # use pedant_core::resolution::go::{GoProjectResolution, GoResolutionSnapshot};
/// # use pedant_graph::{CodeGraph, GraphBuildError};
/// # fn topology(
/// #     snapshot: &GoResolutionSnapshot,
/// #     resolution: &GoProjectResolution,
/// # ) -> Result<CodeGraph, GraphBuildError> {
/// pedant_graph::build_go_graph(snapshot, resolution)
/// # }
/// ```
///
/// The snapshot must be the one the resolution was validated against. A
/// resolution taken before a source-only edit is refused with
/// [`GraphBuildError::SnapshotFingerprintMismatch`] even though both values
/// name the same main module, and no graph record is allocated first.
///
/// # Errors
///
/// Returns [`GraphBuildError`] when the two values describe different
/// repository states, when a stated join names a module, package context,
/// source, or definition the graph holds no record for, when containment is not
/// one module-local forest, or when a collection reaches its ceiling.
pub fn build_go_graph(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
) -> Result<CodeGraph, GraphBuildError> {
    projection::project(snapshot, resolution, GraphLimits::default())
}

/// Project one snapshot-bound Go resolution under caller-chosen ceilings.
///
/// Lowering a [`GraphLimits`] field exercises the same insertion path the
/// default build uses, so a bounded caller and an unbounded one refuse
/// identically.
///
/// # Errors
///
/// The same refusals as [`build_go_graph`], plus
/// [`GraphBuildError::CapacityExceeded`] naming the collection that reached
/// `limits`.
pub fn build_go_graph_with_limits(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
    limits: GraphLimits,
) -> Result<CodeGraph, GraphBuildError> {
    projection::project(snapshot, resolution, limits)
}
