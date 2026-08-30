//! The tools the MCP transport serves: one module per public operation.
//!
//! One registry, read by listing, by lookup, and by dispatch. A tool a client
//! can see and not call, or call and not see, is the drift this shape makes
//! unrepresentable: the schema a client validates against and the parameters the
//! handler deserializes come from the same module.
//!
//! The three graph modules exist only in a build with a graph producer. A build
//! that resolves no project has no graph to answer about, and advertising a tool
//! that could only ever refuse would be worse than not advertising it.
//!
//! [`schema`] reaches past this registry. It owns every sentence describing a
//! question or an argument, and the command line states the same sentences — so
//! a command and the tool answering the identical question cannot describe it
//! two ways.

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod analyze_graph;
mod entries;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod find_path;
mod list_projects;
mod outline_file;
mod params;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod query_relations;
mod read_structure;
pub(crate) mod schema;
mod search_symbols;
mod structure_at;

pub(crate) use entries::{definitions, lookup, requested};
