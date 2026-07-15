//! Clean module root: only declarations, re-exports, and attributes.
#![allow(clippy::module_inception)]

pub mod alpha;
mod beta;

pub use alpha::Widget;
pub use beta::gadget;

#[cfg(test)]
mod tests;
