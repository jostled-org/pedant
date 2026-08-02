//! Enclosing-declaration extraction.
//!
//! One checked index resolves the caller's location, one selector keeps the
//! narrowest recognized declaration containing it, and a backend does nothing
//! but recognize declarations. A build that links no parser compiles none of
//! the selection machinery, and every extraction is absent.

mod dispatch;

#[cfg(any(feature = "rust", feature = "_ts"))]
mod index;

#[cfg(any(feature = "rust", feature = "_ts"))]
mod select;

#[cfg(feature = "rust")]
mod rust;

#[cfg(feature = "_ts")]
mod ts;

pub use dispatch::enclosing_unit;
#[cfg(feature = "rust")]
pub use rust::invalidate_parser_cache;
