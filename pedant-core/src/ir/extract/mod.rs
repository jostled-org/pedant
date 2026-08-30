//! Single-pass AST extraction of a [`FileIr`](crate::ir::facts::FileIr).
//!
//! The traversal is split by responsibility: `extractor` owns fact storage
//! and traversal context, `visitor` is the `syn` dispatch that drives it,
//! `fn_scope` classifies bindings inside the function body under traversal,
//! `sites` owns the authoritative definition and reference inventory, and
//! `site_visitor` turns syntax nodes into those sites. `imports` performs the
//! one `use`-tree walk, `use_paths` projects the flat capability path list from
//! the resulting sites, `paths` renders ranges and path spellings, and `extent`
//! reads the range one declaration occupies from its own boundary tokens.
//! `syn_helpers` holds the stateless AST queries the others share.
//! `unsafe_sites` records the three `unsafe` constructs and their callables.
//! `module_paths` reads the source a `mod` item selects, and `receivers` holds
//! the local binding types one function body established.
//! `impls`, `type_edges`, and `locals` are fact owners with no traversal state
//! of their own: what an `impl` block contributes, the pairwise type edges a
//! definition contributes, and what a `let` binding contributes.
//! `fingerprint` and `enrich` are post-passes over the finished IR. `parse` is
//! the one route into the traversal, so every production parse is observed
//! wherever it was requested from.

#[cfg(feature = "semantic")]
mod enrich;
mod extent;
mod extractor;
mod fingerprint;
mod fn_scope;
mod impls;
mod imports;
mod locals;
mod module_paths;
mod parse;
mod paths;
mod receivers;
mod site_visitor;
mod sites;
mod syn_helpers;
mod type_edges;
mod unsafe_sites;
mod use_paths;
mod visitor;

pub use extractor::extract;
pub use fingerprint::compute_fingerprints;
#[cfg(feature = "checks")]
pub(crate) use parse::parse_source;
pub(crate) use parse::{ParseCompatibility, parse_source_for_edition};
