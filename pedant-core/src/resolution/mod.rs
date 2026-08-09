//! Language-scoped resolution models over a repository's declared structure.
//!
//! Every model here is substrate: it answers factual questions about how a
//! repository declares its build units, takes no policy input, and returns no
//! violation.

pub(crate) mod path_normalization;

/// Factual Cargo project model for Rust repositories.
pub mod rust;
