//! Enclosing-declaration extraction.
//!
//! One checked index resolves the caller's location, one selector keeps the
//! narrowest recognized declaration containing it, and a backend does nothing
//! but recognize declarations. A build that links no parser compiles none of
//! the selection machinery, and every extraction is absent.

mod dispatch;

// Visible to the crate, not just to this module: a structure inventory states
// its line spans and resolves its parser positions through the same checked
// index every extraction does, so both read one definition of "line 3".
#[cfg(any(feature = "rust", feature = "_ts"))]
pub(crate) mod index;

// Visible to the crate, not just to this module: a bound parse session selects
// declarations through the same selector and the same recognizer, so both are
// shared rather than reimplemented beside the tree.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub(crate) mod select;

#[cfg(feature = "rust")]
mod rust;

#[cfg(feature = "_ts")]
pub(crate) mod ts;

pub use dispatch::enclosing_unit;
#[cfg(feature = "rust")]
pub use rust::invalidate_parser_cache;
