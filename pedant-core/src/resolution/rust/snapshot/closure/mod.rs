//! Rust module closure for one resolution unit.
//!
//! The walk follows inline modules, ordinary external modules, and explicit
//! path alternatives while keeping traversal state separate from filesystem
//! candidate resolution.

mod entry;
mod path;
mod state;
mod walk;

pub(super) use entry::ClosureEntry;
pub(super) use state::{UnitClosure, UnitWalk};
pub(super) use walk::walk_unit;
