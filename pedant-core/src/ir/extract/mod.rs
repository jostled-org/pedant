//! Single-pass AST extraction of a [`FileIr`](crate::ir::facts::FileIr).
//!
//! The traversal is split by responsibility: `extractor` owns fact storage
//! and traversal context, `visitor` is the `syn` dispatch that drives it,
//! `fn_scope` classifies bindings inside the function body under traversal,
//! and `use_paths` gathers qualified paths. `syn_helpers` holds the stateless
//! AST queries the others share. `fingerprint` and `enrich` are post-passes
//! over the finished IR.

#[cfg(feature = "semantic")]
mod enrich;
mod extractor;
mod fingerprint;
mod fn_scope;
mod syn_helpers;
mod use_paths;
mod visitor;

pub use extractor::extract;
pub use fingerprint::compute_fingerprints;
