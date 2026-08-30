//! `analyze_graph`: one derived answer about one project graph.

use pedant_snippet::{
    AnalysisLimitRequest, AnalysisMode, EdgeCertainty, EdgeKind, IndexRevision, ProjectHandle,
};
use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::{Operation, analysis_query};

use super::params::parameters;
use super::schema::{
    ANALYSIS_MAX_BETWEENNESS_WORK, ANALYSIS_MAX_DEPTH, ANALYSIS_MAX_NODES,
    ANALYSIS_MAX_SELECTED_EDGES, ANALYSIS_MODE, PROJECT_SUBJECT, choice, edge_properties,
    identity_properties, property, schema,
};

/// What `analyze_graph` accepts.
///
/// Every stated ceiling may only lower the host's own. A request that asked for
/// more work than the index was configured to do would be a caller raising its
/// own budget, and the library refuses it before an analysis is constructed.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    project_revision: IndexRevision,
    project_id: u32,
    mode: AnalysisMode,
    edge_kinds: Box<[EdgeKind]>,
    certainties: Box<[EdgeCertainty]>,
    #[serde(default)]
    max_nodes: Option<u32>,
    #[serde(default)]
    max_selected_edges: Option<u32>,
    #[serde(default)]
    max_depth: Option<u32>,
    #[serde(default)]
    max_betweenness_work: Option<u64>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition() -> JsonObject {
    let mut properties = Vec::from(identity_properties(
        "project_revision",
        "project_id",
        PROJECT_SUBJECT,
    ));
    properties.extend([
        (
            "mode",
            choice(ANALYSIS_MODE, &AnalysisMode::ALL.map(AnalysisMode::token)),
        ),
        ("max_nodes", property("integer", ANALYSIS_MAX_NODES)),
        (
            "max_selected_edges",
            property("integer", ANALYSIS_MAX_SELECTED_EDGES),
        ),
        ("max_depth", property("integer", ANALYSIS_MAX_DEPTH)),
        (
            "max_betweenness_work",
            property("integer", ANALYSIS_MAX_BETWEENNESS_WORK),
        ),
    ]);
    properties.extend(edge_properties());
    schema(
        properties,
        &[
            "project_revision",
            "project_id",
            "mode",
            "edge_kinds",
            "certainties",
        ],
    )
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    Ok(Operation::AnalyzeGraph(analysis_query(
        ProjectHandle::new(stated.project_revision, stated.project_id),
        stated.mode,
        &stated.edge_kinds,
        &stated.certainties,
        AnalysisLimitRequest {
            max_nodes: stated.max_nodes,
            max_selected_edges: stated.max_selected_edges,
            max_depth: stated.max_depth,
            max_betweenness_work: stated.max_betweenness_work,
        },
    )))
}
