//! Proof-only access to resolution invariants ordinary callers cannot reach.
//!
//! Nothing here has a normal or build consumer edge: the feature that compiles
//! this tree is selected by proof configurations and dev dependencies alone.

/// Lexical path authority and defensively invalid target identities.
mod authority;
/// Deliberately restated unit bindings for downstream join refusals.
mod binding;
/// A controlled snapshot claim whose field families a proof can perturb.
mod claim;

pub use authority::{RelativePathNormalizationError, normalize_relative_path, unknown_target_id};
pub use binding::{
    resolution_with_shared_unit_binding, resolution_with_swapped_unit_sources,
    resolution_without_unit_binding,
};
pub use claim::{
    EdgeFingerprintClaim, SnapshotFingerprintClaim, SourceFingerprintClaim, UnitFingerprintClaim,
};
