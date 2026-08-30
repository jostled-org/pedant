//! The registry rows themselves: name, description, schema, and handler.
//!
//! Every entry is read-only, idempotent, and closed-world. The published
//! annotations are not decoration: an absent block means `readOnlyHint: false`,
//! `destructiveHint: true`, and `openWorldHint: true`, so a client would gate a
//! question about source text behind an approval prompt.

use std::sync::Arc;

use rmcp::ErrorData;
use rmcp::model::{JsonObject, Tool, ToolAnnotations};

use crate::operation::Operation;

use super::schema::{LIST_PROJECTS, OUTLINE_FILE, READ_STRUCTURE, SEARCH_SYMBOLS, STRUCTURE_AT};
use super::{list_projects, outline_file, read_structure, search_symbols, structure_at};

/// How one tool's schema is built.
///
/// Two variants because exactly one published property varies with the host: a
/// paged tool's `page_size` states the ceiling `--max-page-items` set, and every
/// other tool describes the same arguments under every ceiling. Written as two
/// variants rather than one signature every builder takes, so a tool that reads
/// no ceiling names no parameter it ignores.
enum SchemaBuilder {
    /// A schema no host ceiling reaches.
    Fixed(fn() -> JsonObject),
    /// A schema whose page property states the host's admitted page ceiling.
    Paged(fn(u32) -> JsonObject),
}

impl SchemaBuilder {
    /// The schema this tool publishes under one host's page ceiling.
    fn built(&self, max_page_items: u32) -> JsonObject {
        match self {
            Self::Fixed(build) => build(),
            Self::Paged(build) => build(max_page_items),
        }
    }
}

/// One served tool: what a client sees, and what answers it.
struct ToolEntry {
    /// The name listing, lookup, and dispatch all use.
    name: &'static str,
    /// What the tool does, as clients see it.
    ///
    /// The same sentence the command answering this question publishes, read
    /// from its one owner in [`super::schema`].
    description: &'static str,
    /// The JSON Schema a client validates its arguments against.
    schema: SchemaBuilder,
    /// The question one call states.
    requested: fn(JsonObject) -> Result<Operation, ErrorData>,
}

/// Every tool this build serves, in the order a listing states them.
static ENTRIES: &[ToolEntry] = &[
    ToolEntry {
        name: "list_projects",
        description: LIST_PROJECTS,
        schema: SchemaBuilder::Paged(list_projects::definition),
        requested: list_projects::requested,
    },
    ToolEntry {
        name: "search_symbols",
        description: SEARCH_SYMBOLS,
        schema: SchemaBuilder::Paged(search_symbols::definition),
        requested: search_symbols::requested,
    },
    ToolEntry {
        name: "outline_file",
        description: OUTLINE_FILE,
        schema: SchemaBuilder::Fixed(outline_file::definition),
        requested: outline_file::requested,
    },
    ToolEntry {
        name: "read_structure",
        description: READ_STRUCTURE,
        schema: SchemaBuilder::Fixed(read_structure::definition),
        requested: read_structure::requested,
    },
    ToolEntry {
        name: "structure_at",
        description: STRUCTURE_AT,
        schema: SchemaBuilder::Fixed(structure_at::definition),
        requested: structure_at::requested,
    },
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    ToolEntry {
        name: "query_relations",
        description: super::schema::QUERY_RELATIONS,
        schema: SchemaBuilder::Paged(super::query_relations::definition),
        requested: super::query_relations::requested,
    },
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    ToolEntry {
        name: "find_path",
        description: super::schema::FIND_PATH,
        schema: SchemaBuilder::Fixed(super::find_path::definition),
        requested: super::find_path::requested,
    },
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    ToolEntry {
        name: "analyze_graph",
        description: super::schema::ANALYZE_GRAPH,
        schema: SchemaBuilder::Fixed(super::analyze_graph::definition),
        requested: super::analyze_graph::requested,
    },
];

/// Every definition this server serves, under its own page ceiling.
///
/// Built once by the transport that will serve them rather than held in a
/// static, because `--max-page-items` is read at start and a static would have
/// to be filled from whichever host reached it first.
pub(crate) fn definitions(max_page_items: u32) -> Arc<[Tool]> {
    ENTRIES
        .iter()
        .map(|entry| {
            Tool::new(
                entry.name,
                entry.description,
                Arc::new(entry.schema.built(max_page_items)),
            )
            .annotate(
                ToolAnnotations::new()
                    .read_only(true)
                    .idempotent(true)
                    .open_world(false),
            )
        })
        .collect()
}

/// The definition of `name`, out of the set this server published.
///
/// Read from the served list rather than rebuilt, so a lookup cannot describe a
/// tool differently from the listing that offered it.
pub(crate) fn lookup(served: &[Tool], name: &str) -> Option<Tool> {
    served.iter().find(|tool| tool.name == name).cloned()
}

/// The question one call states.
///
/// A name this server does not serve and arguments that do not deserialize are
/// both protocol errors rather than tool results: `isError` says a tool ran and
/// failed, and in neither case did one run. A query that refuses is the
/// opposite — the question was well formed, the index answered it with a
/// refusal — so that stays a tool error.
pub(crate) fn requested(name: &str, arguments: Option<JsonObject>) -> Result<Operation, ErrorData> {
    match ENTRIES.iter().find(|entry| entry.name == name) {
        Some(entry) => (entry.requested)(arguments.unwrap_or_default()),
        None => Err(ErrorData::invalid_params(
            format!("unknown tool: {name}"),
            None,
        )),
    }
}
