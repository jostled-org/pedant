//! The two public Rust entry points.
//!
//! Both delegate to the same private projection path over their supplied
//! arguments alone. Neither loads a project, constructs a snapshot, parses a
//! source, builds a semantic context, or runs a resolver tier.

use pedant_core::resolution::rust::{RustResolutionSnapshot, RustTargetResolution};

use crate::error::GraphBuildError;
use crate::graph::CodeGraph;
use crate::limits::GraphLimits;

use super::projection;

/// Project one snapshot-bound Rust resolution under the default ceilings.
///
/// The snapshot must be the one the resolution was validated against. A
/// resolution taken before a source-only edit is refused with
/// [`GraphBuildError::SnapshotFingerprintMismatch`] even though both values
/// name the same root target, and no graph record is allocated first.
///
/// # Errors
///
/// Returns [`GraphBuildError`] when the two values describe different root
/// targets or different repository states, when a stated join names a unit,
/// source, or definition the graph holds no record for, when containment is not
/// one unit-local forest, or when a collection reaches its ceiling.
pub fn build_rust_graph(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
) -> Result<CodeGraph, GraphBuildError> {
    projection::project(snapshot, resolution, GraphLimits::default())
}

/// Project one snapshot-bound Rust resolution under caller-chosen ceilings.
///
/// Lowering a [`GraphLimits`] field exercises the same insertion path the
/// default build uses, so a bounded caller and an unbounded one refuse
/// identically.
///
/// # Errors
///
/// The same refusals as [`build_rust_graph`], plus
/// [`GraphBuildError::CapacityExceeded`] naming the collection that reached
/// `limits`.
pub fn build_rust_graph_with_limits(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
    limits: GraphLimits,
) -> Result<CodeGraph, GraphBuildError> {
    projection::project(snapshot, resolution, limits)
}
