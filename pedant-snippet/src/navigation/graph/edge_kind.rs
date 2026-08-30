//! Which relation a graph request admits.
//!
//! `pedant-graph` deliberately deserializes nothing: every identity it publishes
//! is a position into a graph a caller must have read it out of, and a record it
//! could hydrate from bytes would be one nothing proved. That decision is the
//! graph owner's and this crate does not widen it — so a request that arrives
//! over a transport states its selection in this crate's own vocabulary and is
//! translated once, in the module that owns it.
//!
//! The match below is total in both directions, so a new graph variant fails to
//! compile here rather than falling silently out of a selection or a cursor
//! claim.

use pedant_graph::GraphEdgeKind;
use serde::{Deserialize, Serialize};

/// Which relation a graph query admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
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

impl EdgeKind {
    /// Every kind, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 5] = [
        Self::Call,
        Self::Import,
        Self::Implementation,
        Self::Reference,
        Self::DependsOn,
    ];

    /// The stable token this kind is claimed under.
    pub fn token(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Import => "import",
            Self::Implementation => "implementation",
            Self::Reference => "reference",
            Self::DependsOn => "depends_on",
        }
    }

    /// The relation one graph edge states, in this vocabulary.
    ///
    /// No caller: an answer carries `pedant_graph::GraphEdge` itself, which
    /// serializes in the graph crate's own spelling. The compiler is what reads
    /// this match — it is the half of the translation that names every
    /// `GraphEdgeKind`, so a sixth graph relation fails to compile here rather
    /// than dropping silently out of the vocabulary a caller selects with.
    pub fn of(kind: GraphEdgeKind) -> Self {
        match kind {
            GraphEdgeKind::Call => Self::Call,
            GraphEdgeKind::Import => Self::Import,
            GraphEdgeKind::Implementation => Self::Implementation,
            GraphEdgeKind::Reference => Self::Reference,
            GraphEdgeKind::DependsOn => Self::DependsOn,
        }
    }

    /// The same relation, as the graph crate names it.
    pub(super) fn admitted(self) -> GraphEdgeKind {
        match self {
            Self::Call => GraphEdgeKind::Call,
            Self::Import => GraphEdgeKind::Import,
            Self::Implementation => GraphEdgeKind::Implementation,
            Self::Reference => GraphEdgeKind::Reference,
            Self::DependsOn => GraphEdgeKind::DependsOn,
        }
    }
}
