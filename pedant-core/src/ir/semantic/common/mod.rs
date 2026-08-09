//! Shared helpers for semantic analysis submodules.
//!
//! Contains the file parsing preamble (`with_parsed_file`) and utility
//! functions used across multiple detection domains.

mod analysis;
mod context;
mod file;
mod prelude;
mod sinks;

pub(super) use analysis::lock_receiver_name;
pub(super) use context::*;
pub(super) use file::*;
