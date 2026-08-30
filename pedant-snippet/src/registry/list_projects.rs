//! `list_projects`: every project the index resolved.

use pedant_snippet::PageCursor;
use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::{Operation, page};

use super::params::parameters;
use super::schema::{page_properties, schema};

/// What `list_projects` accepts.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    cursor: Option<PageCursor>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition(max_page_items: u32) -> JsonObject {
    schema(page_properties(max_page_items), &[])
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    Ok(Operation::ListProjects(page(
        stated.page_size,
        stated.cursor,
    )))
}
