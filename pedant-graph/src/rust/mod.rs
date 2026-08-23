//! The Rust adapter: one snapshot-bound resolution becomes one code graph.
//!
//! What is Rust about a Rust graph lives here — the snapshot and report claims,
//! the Cargo-target vocabulary, the key a retained projection is selected by,
//! and the planner that reads one report into drafts. Every identity, every
//! containment rule, and every ceiling belongs to [`crate::projection`], which
//! this adapter ends at and owns no copy of.

/// The caller-created cache of already built graphs.
mod cache;
/// The claim one retained source-unit projection answers for.
mod claim;
/// The two public entry points.
mod entry;
/// The exact Rust-to-graph vocabulary.
mod mapping;
/// The one planner both the direct and the cached path delegate to.
mod projection;
/// The retained source-unit projections one build may reuse.
mod reuse;
/// The complete local claim one source states.
mod source;
/// Every Rust-specific join, checked before a graph exists.
mod validation;

pub use cache::GraphCache;
pub use entry::{build_rust_graph, build_rust_graph_with_limits};
