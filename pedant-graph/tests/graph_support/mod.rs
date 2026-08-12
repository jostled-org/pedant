//! Helper modules for the public graph boundary root.
//!
//! Every registered `#[test]` wrapper lives in `tests/graph.rs`; nothing below
//! declares one, so libtest identities equal the fixed owner inventory.

/// The public reading, identity, and lifecycle surface.
pub mod contract;
/// The temporary Cargo repositories every case projects.
pub mod corpus;
/// Refusals taken before a graph exists.
pub mod defensive;
/// Reference records, candidate edges, and dependency evidence.
pub mod evidence;
/// Real fixtures and the production path to a snapshot-bound resolution.
pub mod fixture;
/// Projection after the fixture repository is gone.
pub mod isolation;
/// Structural ownership of this crate's own production sources.
pub mod ownership;
/// One syntactic report restated at the semantic tier.
pub mod promotion;
/// Comparable text taken from the public reading surface.
pub mod render;
/// Readers over this crate's own production sources.
pub mod scan;
/// The declared items, derives, fields, and constructors those sources state.
pub mod surface;
/// Node inventory, source association, and the containment forest.
pub mod topology;
/// Tier propagation and the exact version-1 serialized contract.
pub mod wire;
