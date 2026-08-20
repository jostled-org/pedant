//! Cargo project authority and the bounded snapshots taken from it: packages,
//! targets, dependencies, versions, module closures, and resolution units read
//! from the manifests and sources beneath one canonical repository root.
//!
//! The loader reads `Cargo.toml` files, directory listings, and the Rust
//! sources a requested target reaches. It never invokes Cargo.

mod dependency;
mod edition;
mod error;
mod fingerprint;
mod identity;
mod limits;
mod load;
mod manifest;
mod members;
mod package;
mod paths;
mod project;
mod resolve;
mod snapshot;
mod target;
#[cfg(feature = "resolution-test-support")]
mod test_support;
mod toml_view;
mod version;
mod warning;

pub use dependency::{CargoDependencyKind, DependencyActivation, RustDependency};
pub use edition::CargoEdition;
pub use error::RustProjectError;
pub use fingerprint::RustSnapshotFingerprint;
pub use identity::{PackageId, TargetId};
pub use limits::ResolutionLimits;
pub use package::RustPackage;
pub use project::RustProject;
pub use resolve::{RustResolutionError, RustResolver, RustTargetResolution, RustUnitBinding};
pub use snapshot::{
    ClosureSite, ResolutionLimit, RustModuleId, RustModuleInstance, RustPackageSnapshot,
    RustPackageSnapshotError, RustPrimaryTargetSnapshot, RustResolutionSnapshot,
    RustResolutionUnit, RustSnapshotEdge, RustSnapshotError, RustSnapshotUnitId, RustSource,
    RustTargetSnapshot, SourceClosureError, SourceClosureFailure, SourceClosureFailureKind,
};
pub use target::{CargoTargetKind, RustTarget};
pub use version::CargoPackageVersion;
pub use warning::RustResolutionWarning;

#[cfg(feature = "resolution-test-support")]
pub use test_support::{
    EdgeFingerprintClaim, RelativePathNormalizationError, SnapshotFingerprintClaim,
    SourceFingerprintClaim, UnitFingerprintClaim, normalize_relative_path,
    resolution_with_shared_unit_binding, resolution_with_swapped_unit_sources,
    resolution_without_unit_binding, unknown_target_id,
};
