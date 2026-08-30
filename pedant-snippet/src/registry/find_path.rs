//! `find_path`: the shortest route between two declarations.

use pedant_snippet::{EdgeCertainty, EdgeKind, IndexRevision, StructureHandle};
use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::{Operation, path_query};

use super::params::parameters;
use super::schema::{
    PATH_PROJECT, ROUTE_END_SUBJECT, ROUTE_START_SUBJECT, edge_properties, identity_properties,
    property, schema,
};

/// What `find_path` accepts.
///
/// No depth: a route is as long as the topology makes it, so the search is
/// bounded by the host's admitted node and selected-edge ceilings alone.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    from_revision: IndexRevision,
    from_id: u32,
    to_revision: IndexRevision,
    to_id: u32,
    #[serde(default)]
    project_id: Option<u32>,
    edge_kinds: Box<[EdgeKind]>,
    certainties: Box<[EdgeCertainty]>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition() -> JsonObject {
    let mut properties = Vec::from(identity_properties(
        "from_revision",
        "from_id",
        ROUTE_START_SUBJECT,
    ));
    properties.extend(identity_properties(
        "to_revision",
        "to_id",
        ROUTE_END_SUBJECT,
    ));
    properties.push(("project_id", property("integer", PATH_PROJECT)));
    properties.extend(edge_properties());
    schema(
        properties,
        &[
            "from_revision",
            "from_id",
            "to_revision",
            "to_id",
            "edge_kinds",
            "certainties",
        ],
    )
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    Ok(Operation::FindPath(path_query(
        StructureHandle::new(stated.from_revision, stated.from_id),
        StructureHandle::new(stated.to_revision, stated.to_id),
        stated.project_id,
        &stated.edge_kinds,
        &stated.certainties,
    )))
}
