//! `structure_at`: the narrowest structure containing one point.

use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::Operation;

use super::params::parameters;
use super::schema::{POINT_COLUMN, POINT_LINE, POINT_PATH, property, schema};

/// What `structure_at` accepts.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    path: Box<str>,
    line: u32,
    #[serde(default)]
    column: Option<u32>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition() -> JsonObject {
    schema(
        [
            ("path", property("string", POINT_PATH)),
            ("line", property("integer", POINT_LINE)),
            ("column", property("integer", POINT_COLUMN)),
        ],
        &["path", "line"],
    )
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    Ok(Operation::StructureAt {
        path: stated.path,
        line: stated.line,
        column: stated.column,
    })
}
