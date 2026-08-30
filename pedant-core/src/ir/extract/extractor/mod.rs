//! Fact storage and emit helpers for AST extraction.

mod entry;
mod gates;
mod state;
mod visited;

pub use entry::extract;
pub(super) use state::IrExtractor;
pub(super) use visited::{TypeDefinition, ValueItem};
