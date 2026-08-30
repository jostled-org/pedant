//! Bounded snapshots over one loaded Cargo project.
//!
//! Both operations validate target authority before a Rust source is read.
//! `target` returns one target's module closure; `resolution` composes the
//! multi-unit closure name resolution consumes.

mod activation;
mod authority;
mod closure;
mod declaration;
mod error;
mod failure;
mod module;
mod primary;
mod resolution;
mod selection;
mod selection_chain;
mod selection_edge;
mod source;
mod store;
mod target;
mod unit;

pub use error::{
    ClosureSite, ResolutionLimit, RustSnapshotError, SourceClosureError, SourceClosureFailure,
    SourceClosureFailureKind,
};
pub use module::{RustModuleId, RustModuleInstance};
pub use primary::{RustPackageSnapshot, RustPackageSnapshotError, RustPrimaryTargetSnapshot};
pub use resolution::RustResolutionSnapshot;
pub use source::RustSource;
pub use target::RustTargetSnapshot;
pub use unit::{RustResolutionUnit, RustSnapshotEdge, RustSnapshotUnitId};

pub(super) use primary::build as build_package_snapshot;
pub(super) use resolution::build as build_resolution_snapshot;
pub(super) use target::build as build_target_snapshot;
