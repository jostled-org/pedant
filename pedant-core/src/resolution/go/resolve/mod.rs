//! Symbol resolution over one bounded Go resolution snapshot.
//!
//! The snapshot decides which sources exist and which package contexts
//! instantiate them; this module decides what each name in them denotes. Every
//! result is bound to the snapshot it describes, so a report can never be read
//! against sources it was not produced from.
//!
//! Nothing here reads a path, parses a source, or invokes a toolchain: the
//! grammar facts a snapshot already retained are the only evidence, and what
//! they do not prove stays a possible candidate or an explicit gap.

/// The borrowed reading surface name resolution works over.
mod corpus;
/// The definitions a package context declares, stated once into each.
mod definitions;
/// Typed resolution failures.
mod error;
/// The names one file's import specifications bind.
mod imports;
/// The definition inventory and the tables lookup reads it through.
mod index;
/// Go name lookup over that inventory.
mod lookup;
/// The members a concrete type answers to, promotion included.
mod methods;
/// The one order a resolution is written in.
mod pipeline;
/// Certainty, gaps, and the record written for each reference.
mod records;
/// Reference sites, classified against the scopes that wrote them.
mod references;
/// The public resolver entry point.
mod resolver;
/// Which binding one occurrence sees.
mod scopes;
/// The snapshot-bound result and its validation boundary.
mod target;
/// What concrete named type a receiver expression has.
mod types;
/// Go's universe block.
mod universe;

pub use error::GoResolutionError;
pub use resolver::GoResolver;
pub use target::{GoProjectResolution, GoUnitBinding};
