//! Language-scoped resolution models over a repository's declared structure.
//!
//! Every model here is substrate: it answers factual questions about how a
//! repository declares its build units, takes no policy input, and returns no
//! violation.

pub(crate) mod digest;
pub(crate) mod identity;
pub(crate) mod path_normalization;
pub(crate) mod paths;

/// Factual Go module project model for Go repositories.
#[cfg(feature = "go-resolution")]
pub mod go;
/// Factual Cargo project model for Rust repositories.
pub mod rust;

/// Proof-only observation of the production loaders, shared by every language.
#[cfg(feature = "resolution-test-support")]
pub use crate::observe::ResolutionProbe;
