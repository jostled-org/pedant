//! The Go adapter: one snapshot-bound Go resolution becomes one code graph.
//!
//! What is Go about a Go graph lives here — the snapshot and report claims, the
//! module and package vocabulary, where each module and package context sits,
//! and the planner that reads one report into drafts. Every identity, every
//! containment rule, and every ceiling belongs to [`crate::projection`], which
//! this adapter ends at and owns no copy of.
//!
//! Nothing here caches. The Go graph is built from the pairing it is handed and
//! nothing else, and the caller-owned reuse the Rust adapter offers names no Go
//! type at all.

/// The two public entry points.
mod entry;
/// The exact Go-to-graph vocabulary.
mod mapping;
/// Where each admitted module and package context sits in one plan.
mod placement;
/// The one planner both public entry points delegate to.
mod projection;
/// Every Go-specific join, checked before a graph exists.
mod validation;

pub use entry::{build_go_graph, build_go_graph_with_limits};
