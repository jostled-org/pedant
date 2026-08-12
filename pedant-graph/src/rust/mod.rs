//! The Rust adapter: one snapshot-bound resolution becomes one code graph.

/// The two public entry points.
mod entry;
/// The tables the projection resolves its joins through.
mod index;
/// The exact Rust-to-graph vocabulary.
mod mapping;
/// The one projection path both entry points delegate to.
mod projection;
/// Every join, checked before a graph exists.
mod validation;

pub use entry::{build_rust_graph, build_rust_graph_with_limits};
