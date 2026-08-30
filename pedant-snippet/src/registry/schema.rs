//! The shapes every tool schema is assembled from, and the sentences both
//! transports describe a question with.
//!
//! A schema here is an object with named properties, a required list, and no
//! room for an argument it does not name. That last part states the rule every
//! parameter struct enforces with `deny_unknown_fields`: an argument the schema
//! omits is a mistake, not a field to ignore, because a misspelled `column` that
//! was ignored would answer the line-only question instead of reporting the
//! typo.
//!
//! The properties several tools share — a page, a revision-bound identity, an
//! edge selection — are written once here, so two tools cannot describe the same
//! argument two ways.
//!
//! Every sentence below is written once for the same reason, and read by both
//! transports: the command line states it through `#[arg(help = …)]` and
//! `#[command(about = …)]`, and the registry states it as a tool description or
//! a schema property. Two hand-written copies of one sentence is how a command
//! and the tool that answers the identical question came to describe it
//! differently, and nothing compiled or asserted could see the difference.
//!
//! A closed vocabulary is never spelled here as prose. The schema is the only
//! place an MCP client learns which tokens a tool accepts, so a sentence listing
//! them by hand would be a second table beside the deserializer's — and adding a
//! variant would compile, leaving the one table a client can read stale in
//! silence. Every closed property takes the vocabulary's own `ALL` and states it
//! twice from that single source: once as the JSON Schema `enum` a client
//! validates against, and once as the sentence a reader gets.

use pedant_snippet::DEFAULT_PAGE_SIZE;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use pedant_snippet::{EdgeCertainty, EdgeKind};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

/// What `list-projects` and `list_projects` answer.
pub(crate) const LIST_PROJECTS: &str = "List every project the index resolved";

/// What `search` and `search_symbols` answer.
pub(crate) const SEARCH_SYMBOLS: &str = "Find every named structure a query selects";

/// What `outline` and `outline_file` answer.
pub(crate) const OUTLINE_FILE: &str =
    "Return one file's complete structure forest, in source order";

/// What `read` and `read_structure` answer.
pub(crate) const READ_STRUCTURE: &str = "Return one revision-bound structure and its exact source";

/// What `at` and `structure_at` answer.
pub(crate) const STRUCTURE_AT: &str =
    "Return the narrowest structure containing one point, and its source";

/// What `relations` and `query_relations` answer.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const QUERY_RELATIONS: &str = "Walk one declaration's graph neighborhood";

/// What `path` and `find_path` answer.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const FIND_PATH: &str =
    "Find the shortest route between two declarations, inside one project graph";

/// What `graph` and `analyze_graph` answer.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ANALYZE_GRAPH: &str = "State one derived answer about one project graph";

/// The text a search compares with each declared name.
pub(crate) const SEARCH_TEXT: &str = "The text to compare with each declared name";

/// How a search compares that text.
///
/// Stated by the caller rather than inferred, because a mode read out of the
/// text would change what the search returns whenever a query happened to look
/// like one.
pub(crate) const MATCH_MODE: &str = "How to compare it";

/// The language filter a search may add.
pub(crate) const LANGUAGE_FILTER: &str = "Keep only structures recognized in this language";

/// The kind filter a search may add.
pub(crate) const KIND_FILTER: &str = "Keep only structures of this kind";

/// The owner filter a search may add.
pub(crate) const OWNER_NAME_FILTER: &str = "Keep only structures whose nearest named owner is this";

/// The path filter a search may add.
pub(crate) const PATH_PREFIX_FILTER: &str =
    "Keep only structures declared beneath this normalized repository path";

/// The file an outline is taken of.
pub(crate) const OUTLINE_PATH: &str = "The normalized repository path to outline";

/// The dense half of every revision-bound identity.
pub(crate) const IDENTITY_POSITION: &str = "The dense position that identity names";

/// Whose identity a structure handle names.
pub(crate) const STRUCTURE_SUBJECT: &str = "structure";

/// Whose identity a route's opening endpoint names.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ROUTE_START_SUBJECT: &str = "starting";

/// Whose identity a route's closing endpoint names.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ROUTE_END_SUBJECT: &str = "ending";

/// Whose identity a project handle names.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const PROJECT_SUBJECT: &str = "project";

/// The file a point lookup reads.
pub(crate) const POINT_PATH: &str = "The normalized repository path to look in";

/// The line a point lookup names.
pub(crate) const POINT_LINE: &str = "The one-based line";

/// The column a point lookup may narrow to.
pub(crate) const POINT_COLUMN: &str = "The one-based UTF-8 byte offset within that line";

/// The continuation a paged answer is resumed from.
pub(crate) const PAGE_CURSOR: &str = "The cursor a previous page returned";

/// The one graph a neighborhood walk may be confined to.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const RELATIONS_PROJECT: &str =
    "The one project graph to walk; omitted, every graph the seed appears in";

/// Which way a neighborhood walk follows a selected edge.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const RELATION_DIRECTION: &str = "Which way to follow a selected edge";

/// How far a neighborhood walk may reach.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const RELATION_DEPTH: &str = "How many selected steps the walk may take";

/// The one graph a route search may be confined to.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const PATH_PROJECT: &str =
    "The one project graph to search; omitted, every graph holding both ends";

/// Which derived answer an analysis states.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ANALYSIS_MODE: &str = "Which derived answer to state";

/// The node ceiling an analysis may lower.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ANALYSIS_MAX_NODES: &str = "Lower the host's admitted node ceiling";

/// The selected-edge ceiling an analysis may lower.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ANALYSIS_MAX_SELECTED_EDGES: &str =
    "Lower the host's admitted selected-edge ceiling";

/// The depth ceiling an analysis may lower.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ANALYSIS_MAX_DEPTH: &str = "Lower the host's depth ceiling";

/// The betweenness work bound an analysis may lower.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const ANALYSIS_MAX_BETWEENNESS_WORK: &str = "Lower the host's betweenness work bound";

/// Which relations a graph question follows.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const EDGE_KINDS: &str = "Relations to follow";

/// Which certainties a graph question admits.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) const EDGE_CERTAINTIES: &str = "Certainties to admit";

/// What a page size means, and the two numbers a caller needs to state one.
///
/// The ceiling is a parameter because `--max-page-items` moves it: a sentence
/// holding a literal advertises a range the host refuses the moment an operator
/// lowers it, and a caller learns the real one by having a page rejected.
pub(crate) fn page_size_description(ceiling: u32) -> String {
    format!(
        "How many items the page carries, {DEFAULT_PAGE_SIZE} when omitted, and from 1 through {ceiling}"
    )
}

/// Whose identity one revision belongs to.
///
/// `subject` names the only part that differs: a structure's, a route
/// endpoint's, or a project's.
pub(crate) fn identity_revision(subject: &str) -> String {
    format!("The index revision the {subject} identity was issued by")
}

/// One property, typed and described.
pub(super) fn property(kind: &str, description: &str) -> Value {
    json!({ "type": kind, "description": description })
}

/// One closed string property: the tokens a caller may send, and nothing else.
pub(super) fn choice(description: &str, vocabulary: &[&str]) -> Value {
    json!({
        "type": "string",
        "enum": vocabulary,
        "description": sentence(description, vocabulary)
    })
}

/// One repeated closed property: a list whose members are those same tokens.
///
/// Only an edge selection states one, so a build with no graph producer has no
/// repeated property to describe.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(super) fn tokens(description: &str, vocabulary: &[&str]) -> Value {
    json!({
        "type": "array",
        "items": { "type": "string", "enum": vocabulary },
        "description": sentence(description, vocabulary)
    })
}

/// What a property does, followed by every token it admits.
fn sentence(description: &str, vocabulary: &[&str]) -> String {
    format!("{description}: {}", vocabulary.join(", "))
}

/// The schema one tool's named properties and required arguments state.
///
/// The properties are taken by value because every caller builds a list for this
/// call and drops it here. Borrowing them meant cloning each shape into the map
/// and then dropping the originals, which copied every schema this crate
/// publishes to hand back the one thing the caller had already given up.
pub(super) fn schema(
    properties: impl IntoIterator<Item = (&'static str, Value)>,
    required: &[&str],
) -> JsonObject {
    let named: serde_json::Map<String, Value> = properties
        .into_iter()
        .map(|(name, shape)| (name.to_owned(), shape))
        .collect();
    JsonObject::from_iter([
        ("type".to_owned(), json!("object")),
        ("properties".to_owned(), Value::Object(named)),
        ("required".to_owned(), json!(required)),
        ("additionalProperties".to_owned(), json!(false)),
    ])
}

/// The two properties every paged tool names.
///
/// The admitted range is read from the host's own ceiling rather than written
/// down, because `--max-page-items` moves it: a schema stating a fixed 200 would
/// advertise a range this server refuses the moment an operator lowers it, and a
/// client would learn the real one by having a page rejected.
pub(super) fn page_properties(max_page_items: u32) -> [(&'static str, Value); 2] {
    [
        (
            "page_size",
            property("integer", &page_size_description(max_page_items)),
        ),
        ("cursor", property("string", PAGE_CURSOR)),
    ]
}

/// The revision and the dense position one identity is named by.
///
/// Every tool that takes a handle takes these two under its own key pair, so the
/// pair is described here once. A revision spelled two ways would be a handle a
/// client could assemble from the wrong half, and a `find_path` that wrote its
/// own copy for each endpoint was three chances for one of them to say something
/// else about the same argument.
///
/// `subject` names whose identity it is, which is the only part that differs:
/// a structure's, a route endpoint's, or a project's.
pub(super) fn identity_properties(
    revision_key: &'static str,
    id_key: &'static str,
    subject: &str,
) -> [(&'static str, Value); 2] {
    [
        (
            revision_key,
            property("string", &identity_revision(subject)),
        ),
        (id_key, property("integer", IDENTITY_POSITION)),
    ]
}

/// The two properties a revision-bound structure identity names.
pub(super) fn structure_properties() -> [(&'static str, Value); 2] {
    identity_properties("revision", "structure_id", STRUCTURE_SUBJECT)
}

/// The two properties every edge selection names.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(super) fn edge_properties() -> [(&'static str, Value); 2] {
    [
        (
            "edge_kinds",
            tokens(EDGE_KINDS, &EdgeKind::ALL.map(EdgeKind::token)),
        ),
        (
            "certainties",
            tokens(
                EDGE_CERTAINTIES,
                &EdgeCertainty::ALL.map(EdgeCertainty::token),
            ),
        ),
    ]
}
