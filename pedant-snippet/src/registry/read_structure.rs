//! `read_structure`: one revision-bound structure and its exact source.

use pedant_snippet::{IndexRevision, StructureHandle};
use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::Operation;

use super::params::parameters;
use super::schema::{schema, structure_properties};

/// What `read_structure` accepts.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    revision: IndexRevision,
    structure_id: u32,
}

/// The schema a client validates its arguments against.
pub(super) fn definition() -> JsonObject {
    schema(structure_properties(), &["revision", "structure_id"])
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    Ok(Operation::ReadStructure(StructureHandle::new(
        stated.revision,
        stated.structure_id,
    )))
}
