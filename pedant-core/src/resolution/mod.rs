//! Language-scoped resolution models over a repository's declared structure.
//!
//! Every model here is substrate: it answers factual questions about how a
//! repository declares its build units, takes no policy input, and returns no
//! violation.

pub(crate) mod binding;
pub(crate) mod capacity;
pub(crate) mod confinement;
pub(crate) mod digest;
pub(crate) mod identity;
pub(crate) mod line_index;
pub(crate) mod path_normalization;
pub(crate) mod paths;
pub(crate) mod provider;
pub(crate) mod read;
pub(crate) mod record_cache;
pub(crate) mod sites;
pub(crate) mod snapshot_record;
pub(crate) mod snapshot_rules;
pub(crate) mod snapshot_store;
pub(crate) mod source_language;
pub(crate) mod supply;

/// Factual Go module project model for Go repositories, behind the default-off
/// `go-resolution` feature, which selects the Go grammar and nothing else.
#[cfg(feature = "go-resolution")]
pub mod go;
/// Factual Cargo project model for Rust repositories.
pub mod rust;

/// The facade every language's source provider is one instantiation of.
pub use provider::SourceProviderOf;

/// Proof-only observation of the production loaders, shared by every language.
#[cfg(feature = "resolution-test-support")]
pub use crate::observe::ResolutionProbe;
