//! Fact storage and emit helpers for AST extraction.

mod entry;
mod state;

pub use entry::extract;
pub(super) use state::IrExtractor;
