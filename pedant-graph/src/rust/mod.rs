//! The Rust adapter: one snapshot-bound resolution becomes one code graph.

/// The one checked assembler every returned graph is minted by.
mod assembly;
/// The caller-created cache of already built graphs.
mod cache;
/// The claim one retained source-unit projection answers for.
mod claim;
/// Containment as one acyclic forest of unit-rooted trees.
mod containment_check;
/// The two public entry points.
mod entry;
/// The graph-neutral projection one plan is made of.
mod fragment;
/// The stable identities a projection states its joins through.
mod identity;
/// The tables one assembly resolves its symbolic joins through.
mod index;
/// The exact Rust-to-graph vocabulary.
mod mapping;
/// The one planner both the direct and the cached path delegate to.
mod projection;
/// The retained source-unit projections one build may reuse.
mod reuse;
/// The complete local claim one source states.
mod source;
/// Every join, checked before a graph exists.
mod validation;

pub use cache::GraphCache;
pub use entry::{build_rust_graph, build_rust_graph_with_limits};
