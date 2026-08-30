//! `outline_file`: one file's complete structure forest.

use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::Operation;

use super::params::parameters;
use super::schema::{OUTLINE_PATH, property, schema};

/// What `outline_file` accepts.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    path: Box<str>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition() -> JsonObject {
    schema([("path", property("string", OUTLINE_PATH))], &["path"])
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    Ok(Operation::OutlineFile(stated.path))
}
