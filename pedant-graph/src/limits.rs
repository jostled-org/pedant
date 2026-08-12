//! The configured ceilings a graph build refuses at, and the collections they
//! address.

use std::fmt;

use serde::{Serialize, Serializer};

/// Which graph collection a ceiling addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GraphCollection {
    /// The node slice.
    Node,
    /// The reference-record slice.
    Reference,
    /// The edge slice.
    Edge,
}

impl GraphCollection {
    /// The lower-snake-case token this collection is named by.
    fn token(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Reference => "reference",
            Self::Edge => "edge",
        }
    }
}

/// One spelling for one collection: a refusal names it exactly as the wire
/// does, rather than in the `Debug` form of the same value.
impl fmt::Display for GraphCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// The wire form is that same token, so the serialized spelling and the spelling
/// a refusal prints cannot drift apart.
impl Serialize for GraphCollection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.token())
    }
}

/// How many nodes, reference records, and edges one build may produce.
///
/// The default is the fixed-width identity ceiling, so the configured limit and
/// the representable ceiling are enforced by one check rather than by two rules
/// that can disagree. Lowering a field exercises exactly the production
/// insertion path an ordinary build uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphLimits {
    max_nodes: u32,
    max_references: u32,
    max_edges: u32,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: u32::MAX,
            max_references: u32::MAX,
            max_edges: u32::MAX,
        }
    }
}

impl GraphLimits {
    /// Ceilings for the three bounded collections.
    pub fn new(max_nodes: u32, max_references: u32, max_edges: u32) -> Self {
        Self {
            max_nodes,
            max_references,
            max_edges,
        }
    }

    /// The configured node ceiling.
    pub fn max_nodes(&self) -> u32 {
        self.max_nodes
    }

    /// The configured reference-record ceiling.
    pub fn max_references(&self) -> u32 {
        self.max_references
    }

    /// The configured edge ceiling.
    pub fn max_edges(&self) -> u32 {
        self.max_edges
    }

    /// The ceiling one collection is bounded by.
    pub(crate) fn ceiling(&self, collection: GraphCollection) -> u32 {
        match collection {
            GraphCollection::Node => self.max_nodes,
            GraphCollection::Reference => self.max_references,
            GraphCollection::Edge => self.max_edges,
        }
    }
}
