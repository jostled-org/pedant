//! Go module project authority: the main module, the local replacements it
//! requires, and every directive its root manifest states.
//!
//! The loader reads `go.mod` files beneath one canonical repository root. It
//! never invokes the Go command, a compiler, a code generator, a language
//! server, or a network client, and it consults no toolchain environment,
//! module cache, workspace file, or host selection state. The root manifest is
//! the sole `replace` and `exclude` authority, matching a single-main-module
//! build.

mod directive;
mod error;
mod exclusion;
mod identity;
mod limits;
mod load;
mod manifest;
mod module;
mod paths;
mod project;
mod replacement;
mod requirement;

pub use error::GoProjectError;
pub use exclusion::GoExclusion;
pub use identity::GoModuleId;
pub use limits::GoResolutionLimits;
pub use module::GoModule;
pub use project::GoProject;
pub use replacement::{GoReplacement, GoReplacementTarget};
pub use requirement::{GoRequirement, GoRequirementResolution};
