//! The one tool the MCP transport exposes: name, schema, and dispatch.
//!
//! Listing, lookup, and calling all read this module, so the schema a client
//! sees cannot drift from the handler that answers its call.

use std::path::Path;
use std::sync::{Arc, LazyLock};

use pedant_snippet::{Extraction, Location, extract_path};
use rmcp::ErrorData;
use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool, ToolAnnotations};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::CommandError;

/// The tool name listing and dispatch share.
const NAME: &str = "enclosing_unit";

/// What the tool does, as clients see it.
const DESCRIPTION: &str = "Return the source declaration enclosing one file location";

/// The arguments one call supplies.
///
/// Unknown fields are rejected: a misspelled `column` would otherwise answer
/// the line-only question instead of reporting the typo, where the CLI's
/// equivalent misspelling is a clap error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    /// The file to read.
    path: Box<str>,
    /// One-based line number.
    line: usize,
    /// One-based UTF-8 byte offset within the line.
    column: Option<usize>,
}

/// The served definition, built once.
///
/// The annotations are published, not left to default. An absent `annotations`
/// block means `readOnlyHint: false`, `destructiveHint: true`, and
/// `openWorldHint: true`, so a client gates this call behind an approval prompt.
/// The tool holds one capability, `file_read`: it opens the named file, returns
/// bytes, writes nothing, and reaches no host but this one. Reading the same
/// location twice returns the same answer.
static DEFINITION: LazyLock<Tool> = LazyLock::new(|| {
    Tool::new(NAME, DESCRIPTION, Arc::new(schema())).annotate(
        ToolAnnotations::new()
            .read_only(true)
            .idempotent(true)
            .open_world(false),
    )
});

/// The definition `tools/list` returns.
pub(crate) fn definition() -> Tool {
    DEFINITION.clone()
}

/// The definition of `name`, when this server serves it.
pub(crate) fn lookup(name: &str) -> Option<Tool> {
    (name == NAME).then(definition)
}

/// Route one call by tool name.
///
/// A name this server does not serve and arguments that do not deserialize are
/// both protocol errors, not tool results: `isError` says a tool ran and failed,
/// and in neither case did one run. A read that fails is the opposite — the file
/// was named, the tool ran, the read failed — so that stays a tool error.
///
/// The arguments arrive owned and are consumed here, because
/// `serde_json::from_value` takes the `Value` by value.
pub(crate) fn dispatch(
    name: &str,
    arguments: Option<JsonObject>,
) -> Result<CallToolResult, ErrorData> {
    match name {
        NAME => Ok(extract(&params(arguments)?)),
        other => Err(ErrorData::invalid_params(
            format!("unknown tool: {other}"),
            None,
        )),
    }
}

/// The JSON Schema a client validates its arguments against.
fn schema() -> JsonObject {
    JsonObject::from_iter([
        ("type".to_owned(), json!("object")),
        (
            "properties".to_owned(),
            json!({
                "path": {
                    "type": "string",
                    "description": "File to read, absolute or relative to the server's working directory"
                },
                "line": {
                    "type": "integer",
                    "description": "One-based line number"
                },
                "column": {
                    "type": "integer",
                    "description": "One-based UTF-8 byte offset within the line"
                }
            }),
        ),
        ("required".to_owned(), json!(["path", "line"])),
        // States the rule `Params` enforces: an argument this schema does not
        // name is a mistake, not a field to ignore.
        ("additionalProperties".to_owned(), json!(false)),
    ])
}

/// Read one call's arguments.
///
/// A misspelled or missing argument means the tool never ran, so the refusal is
/// the same `-32602` a name this server does not serve gets, and the same class
/// of refusal clap gives the CLI for a misspelled flag.
fn params(arguments: Option<JsonObject>) -> Result<Params, ErrorData> {
    let value = Value::Object(arguments.unwrap_or_default());
    serde_json::from_value(value).map_err(|failure| {
        ErrorData::invalid_params(format!("invalid parameters: {failure}"), None)
    })
}

/// Extract the declaration the arguments name.
///
/// The server outlives every call, so it releases the Rust parser's thread-local
/// source map afterwards. Without that, each Rust extraction retains the whole
/// file for the life of the process. This is the caller that may do it: the
/// answer is already an owned [`Extraction`], and nothing here holds a span.
fn extract(params: &Params) -> CallToolResult {
    let at = Location {
        line: params.line,
        column: params.column,
    };
    let extracted = extract_path(Path::new(&*params.path), at);
    pedant_snippet::invalidate_parser_cache();
    match extracted {
        Ok(unit) => success(&Extraction { unit }),
        // Reported through `CommandError`, so the sentence an MCP client reads
        // is the one the CLI prints for the same failure.
        Err(failure) => error(CommandError::Extract(failure).to_string()),
    }
}

/// One successful envelope as tool content.
///
/// A serialization failure reports through [`CommandError`], so the sentence an
/// MCP client reads is the one the CLI prints for the same failure.
fn success(extraction: &Extraction) -> CallToolResult {
    match extraction.to_json() {
        Ok(json) => CallToolResult::success(vec![ContentBlock::text(json)]),
        Err(failure) => error(CommandError::Serialize(failure).to_string()),
    }
}

/// One tool error carrying its reason.
fn error(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}
