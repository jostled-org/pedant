//! `query_relations`: one declaration's graph neighborhood.

use pedant_snippet::{
    EdgeCertainty, EdgeKind, IndexRevision, PageCursor, RelationDirection, StructureHandle,
};
use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::{Operation, page, relation_query};

use super::params::parameters;
use super::schema::{
    RELATION_DEPTH, RELATION_DIRECTION, RELATIONS_PROJECT, choice, edge_properties,
    page_properties, property, schema, structure_properties,
};

/// What `query_relations` accepts.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    revision: IndexRevision,
    structure_id: u32,
    #[serde(default)]
    project_id: Option<u32>,
    direction: RelationDirection,
    edge_kinds: Box<[EdgeKind]>,
    certainties: Box<[EdgeCertainty]>,
    max_depth: u32,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    cursor: Option<PageCursor>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition(max_page_items: u32) -> JsonObject {
    let mut properties = Vec::from(structure_properties());
    properties.push(("project_id", property("integer", RELATIONS_PROJECT)));
    properties.push((
        "direction",
        choice(
            RELATION_DIRECTION,
            &RelationDirection::ALL.map(RelationDirection::token),
        ),
    ));
    properties.push(("max_depth", property("integer", RELATION_DEPTH)));
    properties.extend(edge_properties());
    properties.extend(page_properties(max_page_items));
    schema(
        properties,
        &[
            "revision",
            "structure_id",
            "direction",
            "edge_kinds",
            "certainties",
            "max_depth",
        ],
    )
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    let query = relation_query(
        StructureHandle::new(stated.revision, stated.structure_id),
        stated.project_id,
        stated.direction,
        &stated.edge_kinds,
        &stated.certainties,
        stated.max_depth,
    );
    Ok(Operation::QueryRelations(
        query,
        page(stated.page_size, stated.cursor),
    ))
}
