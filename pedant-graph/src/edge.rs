//! A graph edge, how certain it is, and the evidence that produced it.

use std::sync::Arc;

use pedant_types::ResolutionCertainty;
use serde::Serialize;

use crate::id::{GraphEdgeId, GraphNodeId, GraphReferenceId};
use crate::reference::GraphReferenceKind;

/// What relation an edge states.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GraphEdgeKind {
    /// The source calls the target.
    Call,
    /// The source imports the target.
    Import,
    /// The source implements the target.
    Implementation,
    /// Any other source relation between the two.
    Reference,
    /// The source's build unit depends on the target's build unit.
    DependsOn,
}

impl GraphEdgeKind {
    /// The edge one candidate of a reference produces.
    ///
    /// Graph vocabulary answered from graph vocabulary, so every adapter that
    /// turns a reference's candidates into edges reads the one mapping rather
    /// than restating it in its own language's terms.
    pub(crate) fn of_reference(kind: GraphReferenceKind) -> Self {
        match kind {
            GraphReferenceKind::Call => Self::Call,
            GraphReferenceKind::Import => Self::Import,
            GraphReferenceKind::Implementation => Self::Implementation,
            GraphReferenceKind::Reference => Self::Reference,
        }
    }
}

/// How much an edge is known.
///
/// A projection maps a producer's certainty one for one and never upgrades a
/// possible answer to a resolved one.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GraphCertainty {
    /// Language rules identify this one target without inference.
    Resolved,
    /// Source evidence identifies the target, but proof is not available.
    Possible,
}

impl GraphCertainty {
    /// How much one answered candidate is known.
    ///
    /// The shared resolution vocabulary maps one for one, so no adapter can
    /// promote a possible answer on the way into a graph.
    pub(crate) fn of(certainty: ResolutionCertainty) -> Self {
        match certainty {
            ResolutionCertainty::Resolved => Self::Resolved,
            ResolutionCertainty::Possible => Self::Possible,
        }
    }
}

/// Which dependency table declared a build-unit edge.
///
/// Graph-owned vocabulary rather than the consumed build-system enum, so a
/// second producer cannot widen the wire contract from outside this crate.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GraphDependencyKind {
    /// An ordinary dependency edge.
    Normal,
    /// A development-only dependency edge.
    Development,
    /// A build-time dependency edge.
    Build,
}

/// What one build-unit dependency edge retained from its declaration.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DependencyEvidence {
    alias: Arc<str>,
    kind: GraphDependencyKind,
    predicate: Option<Arc<str>>,
}

impl DependencyEvidence {
    pub(crate) fn new(
        alias: Arc<str>,
        kind: GraphDependencyKind,
        predicate: Option<Arc<str>>,
    ) -> Self {
        Self {
            alias,
            kind,
            predicate,
        }
    }

    /// The namespace-local name the declaring unit sees the target under.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Which dependency table declared the edge.
    pub fn kind(&self) -> GraphDependencyKind {
        self.kind
    }

    /// The unevaluated activation predicate, when the edge is conditional.
    pub fn predicate(&self) -> Option<&str> {
        self.predicate.as_deref()
    }
}

/// Why an edge exists. No edge exists without one of these.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GraphEdgeOrigin {
    /// One candidate of one reference record produced the edge.
    Reference {
        /// The record that produced it, for the reverse evidence link.
        reference: GraphReferenceId,
    },
    /// One declared build-unit dependency produced the edge.
    Dependency {
        /// What the declaration stated.
        evidence: DependencyEvidence,
    },
}

/// One directed relation between two graph nodes.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct GraphEdge {
    id: GraphEdgeId,
    source: GraphNodeId,
    target: GraphNodeId,
    kind: GraphEdgeKind,
    certainty: GraphCertainty,
    origin: GraphEdgeOrigin,
}

/// Everything a projection states about one edge before it has an identity.
pub(crate) struct EdgeDraft {
    /// The node the relation starts at.
    pub(crate) source: GraphNodeId,
    /// The node the relation ends at.
    pub(crate) target: GraphNodeId,
    /// What relation the edge states.
    pub(crate) kind: GraphEdgeKind,
    /// How much the relation is known.
    pub(crate) certainty: GraphCertainty,
    /// Why the edge exists.
    pub(crate) origin: GraphEdgeOrigin,
}

impl GraphEdge {
    pub(crate) fn new(id: GraphEdgeId, draft: EdgeDraft) -> Self {
        Self {
            id,
            source: draft.source,
            target: draft.target,
            kind: draft.kind,
            certainty: draft.certainty,
            origin: draft.origin,
        }
    }

    /// This edge's dense identity, equal to its position in the graph.
    pub fn id(&self) -> GraphEdgeId {
        self.id
    }

    /// The node the relation starts at.
    pub fn source(&self) -> GraphNodeId {
        self.source
    }

    /// The node the relation ends at.
    pub fn target(&self) -> GraphNodeId {
        self.target
    }

    /// What relation this edge states.
    pub fn kind(&self) -> GraphEdgeKind {
        self.kind
    }

    /// How much this relation is known.
    pub fn certainty(&self) -> GraphCertainty {
        self.certainty
    }

    /// Why this edge exists.
    pub fn origin(&self) -> &GraphEdgeOrigin {
        &self.origin
    }
}
