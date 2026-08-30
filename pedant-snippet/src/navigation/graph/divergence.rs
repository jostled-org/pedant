//! Where the declared module tree and the selected topology disagree.
//!
//! Evidence, not judgment. A module with low cohesion, a symbol whose edges
//! mostly leave its own partition, and a cycle that crosses a boundary are
//! measurements over the partition the graph declares. Whether any of them is a
//! problem is the caller's to decide, so nothing here is ranked, filtered, or
//! given a threshold.

use pedant_graph::GraphComponentId;
use serde::Serialize;

use super::entity::NavigationEntity;

/// How much of one module's selected traffic stays inside it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CohesionRecord {
    root: NavigationEntity,
    internal_edges: u32,
    boundary_edges: u32,
    score: Option<f64>,
}

impl CohesionRecord {
    /// One measured module.
    pub(super) fn stated(root: NavigationEntity, edges: (u32, u32), score: Option<f64>) -> Self {
        let (internal_edges, boundary_edges) = edges;
        Self {
            root,
            internal_edges,
            boundary_edges,
            score,
        }
    }

    /// The module container this measures.
    pub fn root(&self) -> &NavigationEntity {
        &self.root
    }

    /// Selected edges whose ends are both inside it.
    pub fn internal_edges(&self) -> u32 {
        self.internal_edges
    }

    /// Selected edges with exactly one end inside it.
    pub fn boundary_edges(&self) -> u32 {
        self.boundary_edges
    }

    /// Internal edges over all its edges, absent where it states none.
    pub fn score(&self) -> Option<f64> {
        self.score
    }
}

/// One symbol whose selected edges mostly leave its declared partition.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MisplacementRecord {
    symbol: NavigationEntity,
    declared_partition: NavigationEntity,
    candidate_partition: NavigationEntity,
    foreign_edges: u32,
    total_outgoing_edges: u32,
    affinity: f64,
}

impl MisplacementRecord {
    /// One measured symbol and the partition its edges prefer.
    pub(super) fn stated(
        placed: (NavigationEntity, NavigationEntity, NavigationEntity),
        edges: (u32, u32),
        affinity: f64,
    ) -> Self {
        let (symbol, declared_partition, candidate_partition) = placed;
        let (foreign_edges, total_outgoing_edges) = edges;
        Self {
            symbol,
            declared_partition,
            candidate_partition,
            foreign_edges,
            total_outgoing_edges,
            affinity,
        }
    }

    /// The measured symbol.
    pub fn symbol(&self) -> &NavigationEntity {
        &self.symbol
    }

    /// The partition the source declares it in.
    pub fn declared_partition(&self) -> &NavigationEntity {
        &self.declared_partition
    }

    /// The partition its selected edges prefer.
    pub fn candidate_partition(&self) -> &NavigationEntity {
        &self.candidate_partition
    }

    /// Selected outgoing edges reaching the candidate partition.
    pub fn foreign_edges(&self) -> u32 {
        self.foreign_edges
    }

    /// Every selected outgoing edge it states.
    pub fn total_outgoing_edges(&self) -> u32 {
        self.total_outgoing_edges
    }

    /// Foreign edges over all of them.
    pub fn affinity(&self) -> f64 {
        self.affinity
    }
}

/// One cycle whose members are declared in more than one partition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BoundaryRecord {
    component: GraphComponentId,
    partitions: Box<[NavigationEntity]>,
}

impl BoundaryRecord {
    /// One boundary-crossing component.
    pub(super) fn stated(component: GraphComponentId, partitions: Box<[NavigationEntity]>) -> Self {
        Self {
            component,
            partitions,
        }
    }

    /// The component that crosses.
    pub fn component(&self) -> GraphComponentId {
        self.component
    }

    /// Every partition its members are declared in.
    pub fn partitions(&self) -> &[NavigationEntity] {
        &self.partitions
    }
}

/// Everything one divergence answer measured.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DivergenceAnswer {
    cohesion: Box<[CohesionRecord]>,
    modularity: Option<f64>,
    candidates: Box<[MisplacementRecord]>,
    boundary_components: Box<[BoundaryRecord]>,
}

impl DivergenceAnswer {
    /// One projected divergence answer.
    pub(super) fn stated(
        cohesion: Box<[CohesionRecord]>,
        modularity: Option<f64>,
        candidates: Box<[MisplacementRecord]>,
        boundary_components: Box<[BoundaryRecord]>,
    ) -> Self {
        Self {
            cohesion,
            modularity,
            candidates,
            boundary_components,
        }
    }

    /// Every declared module and how much traffic stays inside it.
    pub fn cohesion(&self) -> &[CohesionRecord] {
        &self.cohesion
    }

    /// How much better the declared partition explains the topology than
    /// chance would, absent where the graph states no selected edge.
    pub fn modularity(&self) -> Option<f64> {
        self.modularity
    }

    /// Every symbol whose edges prefer another partition.
    pub fn candidates(&self) -> &[MisplacementRecord] {
        &self.candidates
    }

    /// Every cycle that crosses a declared boundary.
    pub fn boundary_components(&self) -> &[BoundaryRecord] {
        &self.boundary_components
    }
}
