//! Quality issue detection.
//!
//! Identifies dead stores, discarded results, partial error handling,
//! swallowed `.ok()` calls, and immutable growable bindings within function bodies.

mod dead_store;
mod detect;
mod discarded;
mod immutable;
mod partial;
mod prelude;
mod swallowed;

pub(super) use detect::detect;
