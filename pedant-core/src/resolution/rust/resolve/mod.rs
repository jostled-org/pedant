//! Symbol resolution over one bounded Rust resolution snapshot.
//!
//! The snapshot decides which sources exist and which units instantiate them;
//! this module decides what each name in them denotes. Every result is bound to
//! the snapshot it describes, so a report can never be read against sources it
//! was not produced from.

/// The names `use` items bind inside one module instance.
mod bindings;
/// What a snapshot claims a semantic database must hold.
#[cfg(feature = "semantic")]
mod claim;
/// Coordinate conversion and validation over one exact source text.
mod coordinates;
/// The borrowed reading surface name resolution works over.
mod corpus;
/// Typed resolution failures.
mod error;
/// The module-instance graph one snapshot describes.
mod graph;
/// Filling import bindings to a fixed point.
mod imports;
/// The definition inventory and the tables lookup reads it through.
mod index;
/// Rust path resolution over that inventory.
mod lookup;
/// The inventory both tiers state, and the records written over it.
mod pipeline;
/// What a later tier proves about one reference.
mod promotion;
/// Certainty, gaps, and the record written for each reference.
mod records;
/// Reference sites, stated once per module instance.
mod references;
/// The public resolver entry points.
mod resolver;
/// Tier 2: promotion bound to a verified semantic snapshot.
#[cfg(feature = "semantic")]
mod semantic;
/// Tier 1: parse-only resolution.
mod syntactic;
/// The snapshot-bound result and its validation boundary.
mod target;
/// The report units a snapshot's Cargo target instances become.
mod units;

pub use error::RustResolutionError;
pub use resolver::RustResolver;
pub use target::{RustTargetResolution, RustUnitBinding};
