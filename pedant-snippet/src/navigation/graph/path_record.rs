//! What one path answer states.
//!
//! A route always states one more node than it states edges: the nodes are the
//! stops and the edges are the steps between them. Both travel whole, so a
//! caller reading a route sees the same edges, in the same order, that the
//! graph would hand it directly.
//!
//! No route and no evidence are different answers, and the line runs through
//! the endpoints rather than through the graphs. An endpoint no project graph
//! states a node for is a typed refusal: there is nothing to search from, and
//! the seed says so before a route is looked for. Two endpoints that both state
//! nodes answer successfully with no route whenever no eligible pair is
//! connected — including when the graphs holding them share nothing, which is
//! the same answer an unconnected pair inside one graph states.

use pedant_graph::GraphEdge;
use serde::Serialize;

use crate::index::ProjectHandle;

use super::entity::NavigationEntity;

/// One selected route through one project graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoutedPath {
    project: ProjectHandle,
    nodes: Box<[NavigationEntity]>,
    edges: Box<[GraphEdge]>,
}

impl RoutedPath {
    /// One route, as its own graph states it.
    pub(super) fn stated(
        project: ProjectHandle,
        nodes: Box<[NavigationEntity]>,
        edges: Box<[GraphEdge]>,
    ) -> Self {
        Self {
            project,
            nodes,
            edges,
        }
    }

    /// The project graph the route runs inside.
    pub fn project(&self) -> ProjectHandle {
        self.project
    }

    /// The stops, from source to target.
    pub fn nodes(&self) -> &[NavigationEntity] {
        &self.nodes
    }

    /// The steps between them, in the order the route takes them.
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }
}

/// What one path query found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PathAnswer {
    #[serde(skip_serializing_if = "Option::is_none")]
    selected: Option<RoutedPath>,
}

impl PathAnswer {
    /// The route a query selected, or that it selected none.
    pub(super) fn stated(selected: Option<RoutedPath>) -> Self {
        Self { selected }
    }

    /// The selected route, absent where no eligible pair is connected.
    pub fn selected(&self) -> Option<&RoutedPath> {
        self.selected.as_ref()
    }
}
