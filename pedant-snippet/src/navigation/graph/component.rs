//! What a component or condensation answer states.
//!
//! A strongly connected component is a set of declarations that can all reach
//! each other over the selected edges, and the condensation is the acyclic view
//! over those sets. Both travel with their members projected and their identities
//! kept: a component identity indexes back into the same answer, which is what
//! lets a condensation edge name two of them.

use pedant_graph::{GraphComponentId, GraphEdgeId};
use serde::Serialize;

use super::entity::NavigationEntity;

/// One strongly connected component and what it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComponentRecord {
    id: GraphComponentId,
    members: Box<[NavigationEntity]>,
    cyclic: bool,
}

impl ComponentRecord {
    /// One component, with its members projected.
    pub(super) fn stated(
        id: GraphComponentId,
        members: Box<[NavigationEntity]>,
        cyclic: bool,
    ) -> Self {
        Self {
            id,
            members,
            cyclic,
        }
    }

    /// This component's identity inside the answer that states it.
    pub fn id(&self) -> GraphComponentId {
        self.id
    }

    /// What it holds, in node-id order.
    pub fn members(&self) -> &[NavigationEntity] {
        &self.members
    }

    /// Whether its members can reach each other over the selected edges.
    pub fn cyclic(&self) -> bool {
        self.cyclic
    }
}

/// One condensation edge and the raw edges behind it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CondensationEdgeRecord {
    source: GraphComponentId,
    target: GraphComponentId,
    edges: Box<[GraphEdgeId]>,
}

impl CondensationEdgeRecord {
    /// One edge between two components.
    pub(super) fn stated(
        source: GraphComponentId,
        target: GraphComponentId,
        edges: Box<[GraphEdgeId]>,
    ) -> Self {
        Self {
            source,
            target,
            edges,
        }
    }

    /// The component the edge leaves.
    pub fn source(&self) -> GraphComponentId {
        self.source
    }

    /// The component it arrives at.
    pub fn target(&self) -> GraphComponentId {
        self.target
    }

    /// Every raw graph edge this one stands for.
    pub fn edges(&self) -> &[GraphEdgeId] {
        &self.edges
    }
}

/// The acyclic view over one graph's strongly connected components.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CondensationAnswer {
    components: Box<[ComponentRecord]>,
    edges: Box<[CondensationEdgeRecord]>,
    topological_order: Box<[GraphComponentId]>,
}

impl CondensationAnswer {
    /// One condensation, projected whole.
    pub(super) fn stated(
        components: Box<[ComponentRecord]>,
        edges: Box<[CondensationEdgeRecord]>,
        topological_order: Box<[GraphComponentId]>,
    ) -> Self {
        Self {
            components,
            edges,
            topological_order,
        }
    }

    /// Every component, in component-id order.
    pub fn components(&self) -> &[ComponentRecord] {
        &self.components
    }

    /// Every edge between two distinct components.
    pub fn edges(&self) -> &[CondensationEdgeRecord] {
        &self.edges
    }

    /// One order in which no component precedes a component it depends on.
    pub fn topological_order(&self) -> &[GraphComponentId] {
        &self.topological_order
    }
}
