//! Bounded, source-bound structure inventories.
//!
//! One source states one inventory: every logical structure it declares, in
//! source order, with exact byte and line extents, the name its grammar gives
//! it, and the nearest structure that owns it. The vocabulary is neutral, so a
//! consumer building an outline reads one model rather than one per grammar.
//!
//! Each language owner keeps its own authority. Go structures are projected
//! from [`GoFileFacts`](crate::go::GoFileFacts), the sole Go grammar inventory
//! in this workspace. JavaScript, TypeScript, Python, and Bash share one
//! bounded walk of a bound tree. Rust reaches `syn`. No source is walked twice
//! for one inventory, and no backend states a second declaration recognizer of
//! its own.
//!
//! An inventory exists only when its source states a complete structure set. A
//! parser that failed, a parser that recovered, an absent backend, and either
//! spent ceiling each return a [`StructureError`] and no inventory, because an
//! empty inventory is already the answer for a source that declares nothing.

#[cfg(any(feature = "rust", feature = "_ts"))]
mod builder;
mod dispatch;
mod error;
mod fact;
mod inventory;
/// The structure ceilings, and the one depth comparison every bounded walk in
/// this crate reads. Crate-visible because both walks take it: the builder
/// beside it, and the Go fact walk, which the structure route runs beneath this
/// contract's own depth ceiling.
pub(crate) mod limits;

#[cfg(feature = "_ts")]
mod bound;
#[cfg(feature = "ts-go")]
mod go;
/// The one `syn` item table for the two Rust walks. Crate-visible because both
/// readers take it: the structure walk beside it and the enclosing-unit
/// recognizer in `extract::rust`, which narrows the same recognition to the
/// kinds the unit model declares.
#[cfg(feature = "rust")]
pub(crate) mod items;
/// The one grammar-node table for every language a tree-sitter walk answers
/// for. Crate-visible because both readers take it: the structure walk beside it
/// and the enclosing-unit recognizer in `extract::ts`, which narrows the same
/// recognition to the kinds the unit model declares.
#[cfg(feature = "_ts_generic")]
pub(crate) mod recognize;
#[cfg(feature = "rust")]
mod rust;
#[cfg(feature = "_ts_generic")]
mod ts;

pub use dispatch::structure_inventory;
pub use error::StructureError;
pub use fact::StructureFact;
pub use inventory::StructureInventory;
pub use limits::StructureInventoryLimits;

#[cfg(feature = "_ts")]
pub(crate) use bound::inventory as bound_inventory;
#[cfg(feature = "ts-go")]
pub(crate) use go::{inventory as go_inventory, structure_kind as go_structure_kind};
