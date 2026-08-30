//! The edge selections every graph case states, written once.
//!
//! `pedant-graph` publishes no default selection, and neither does this
//! product. A test table that spelled its own list per row would be four
//! chances to prove a claim about a narrower topology than the one it named.

use pedant_snippet::{
    EdgeCertainty, EdgeKind, EdgeSelection, GraphCertainty, GraphEdgeKind, GraphEdgeSelection,
};

/// Every edge kind the graph vocabulary states.
///
/// The product's own published list rather than a third spelling of the variant
/// set. `vocabulary.rs` writes that set down once and holds `EdgeKind::ALL` to
/// it, so a row selecting everything here selects everything the schema
/// advertises — and a variant the array forgot fails there, where the claim is,
/// instead of quietly narrowing every topology these cases reason about.
pub const EVERY_KIND: &[EdgeKind] = &EdgeKind::ALL;

/// Every certainty the graph vocabulary states, on the same terms.
pub const EVERY_CERTAINTY: &[EdgeCertainty] = &EdgeCertainty::ALL;

/// Every kind at every certainty.
pub fn everything() -> EdgeSelection {
    EdgeSelection {
        kinds: Box::from(EVERY_KIND),
        certainties: Box::from(EVERY_CERTAINTY),
    }
}

/// Exactly the stated kinds, at every certainty.
pub fn kinds(selected: &[EdgeKind]) -> EdgeSelection {
    EdgeSelection {
        kinds: Box::from(selected),
        certainties: Box::from(EVERY_CERTAINTY),
    }
}

/// Every kind, at exactly the stated certainties.
pub fn certainties(selected: &[EdgeCertainty]) -> EdgeSelection {
    EdgeSelection {
        kinds: Box::from(EVERY_KIND),
        certainties: Box::from(selected),
    }
}

/// The same whole selection, as the graph crate names it.
///
/// Spelled beside [`everything`] rather than derived from it, so a row that
/// compares this product's answer with the graph crate's own is comparing two
/// statements of the selection instead of one value handed to both.
pub fn admitted() -> GraphEdgeSelection {
    GraphEdgeSelection::new(
        &[
            GraphEdgeKind::Call,
            GraphEdgeKind::Import,
            GraphEdgeKind::Implementation,
            GraphEdgeKind::Reference,
            GraphEdgeKind::DependsOn,
        ],
        &[GraphCertainty::Resolved, GraphCertainty::Possible],
    )
}
