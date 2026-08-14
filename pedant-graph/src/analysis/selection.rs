//! Which edges one analysis admits.
//!
//! The selection is stated by the caller and applied once, so every query and
//! metric reads the same admitted set. Each kind and certainty is assigned its
//! bit by an explicit match, which keeps the declaration order of the graph's
//! own enums out of the algorithm.

use crate::edge::{GraphCertainty, GraphEdge, GraphEdgeKind};

/// Every edge kind the graph vocabulary states.
const EVERY_KIND: &[GraphEdgeKind] = &[
    GraphEdgeKind::Call,
    GraphEdgeKind::Import,
    GraphEdgeKind::Implementation,
    GraphEdgeKind::Reference,
    GraphEdgeKind::DependsOn,
];

/// Every certainty the graph vocabulary states.
const EVERY_CERTAINTY: &[GraphCertainty] = &[GraphCertainty::Resolved, GraphCertainty::Possible];

/// The edge kinds and certainties one analysis admits.
///
/// A selection admits exactly the Cartesian intersection of the kinds and the
/// certainties it was stated with: naming a kind twice changes nothing, and
/// either empty side admits no edge at all. There is no default, because which
/// relations answer a question is the caller's to state rather than this
/// crate's to assume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphEdgeSelection {
    kinds: u8,
    certainties: u8,
}

impl GraphEdgeSelection {
    /// Exactly the edges whose kind is one of `kinds` and whose certainty is
    /// one of `certainties`.
    pub fn new(kinds: &[GraphEdgeKind], certainties: &[GraphCertainty]) -> Self {
        Self {
            kinds: kinds.iter().fold(0, |mask, kind| mask | kind_bit(*kind)),
            certainties: certainties
                .iter()
                .fold(0, |mask, certainty| mask | certainty_bit(*certainty)),
        }
    }

    /// Every kind at every certainty.
    pub fn all() -> Self {
        Self::new(EVERY_KIND, EVERY_CERTAINTY)
    }

    /// Every source relation at every certainty, and no build-unit dependency.
    pub fn code_relations() -> Self {
        Self {
            kinds: EVERY_KIND
                .iter()
                .filter(|kind| is_code_relation(**kind))
                .fold(0, |mask, kind| mask | kind_bit(*kind)),
            certainties: Self::all().certainties,
        }
    }

    /// Whether this selection admits one edge.
    ///
    /// The exact predicate analysis construction applies, so a caller can ask
    /// the same question of a raw edge that the indexes were built with.
    pub fn allows(self, edge: &GraphEdge) -> bool {
        self.kinds & kind_bit(edge.kind()) != 0
            && self.certainties & certainty_bit(edge.certainty()) != 0
    }
}

/// Whether one kind states a relation between source declarations rather than
/// between build units.
///
/// An explicit match rather than a second written-down list: a kind added to the
/// vocabulary has to be placed on one side of this split here, instead of
/// falling silently out of the selection that names itself the source relations.
fn is_code_relation(kind: GraphEdgeKind) -> bool {
    match kind {
        GraphEdgeKind::Call
        | GraphEdgeKind::Import
        | GraphEdgeKind::Implementation
        | GraphEdgeKind::Reference => true,
        GraphEdgeKind::DependsOn => false,
    }
}

/// The bit one edge kind occupies.
fn kind_bit(kind: GraphEdgeKind) -> u8 {
    match kind {
        GraphEdgeKind::Call => 1,
        GraphEdgeKind::Import => 1 << 1,
        GraphEdgeKind::Implementation => 1 << 2,
        GraphEdgeKind::Reference => 1 << 3,
        GraphEdgeKind::DependsOn => 1 << 4,
    }
}

/// The bit one certainty occupies.
fn certainty_bit(certainty: GraphCertainty) -> u8 {
    match certainty {
        GraphCertainty::Resolved => 1,
        GraphCertainty::Possible => 1 << 1,
    }
}
