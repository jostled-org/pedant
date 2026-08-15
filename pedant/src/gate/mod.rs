//! The gate subcommand: file, stdin, and Cargo-project input modes.
//!
//! Dispatch selects one owner and nothing is shared before it does. The file
//! and stdin owner analyzes independent sources exactly as before; the project
//! owner is the only place that loads a Cargo project, builds a code graph, or
//! projects topology into graph-neutral gate evidence.

mod command;
mod error;
mod evidence;
mod project;

pub(crate) use command::run;
