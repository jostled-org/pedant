//! Everything name resolution reads: the module graph, the definition index,
//! and the units those two are addressed through.

use super::graph::Graph;
use super::index::Index;
use super::units::Units;

/// The resolved snapshot, as one borrowed reading surface.
pub(super) struct Corpus<'a> {
    pub(super) graph: &'a Graph,
    pub(super) index: &'a Index,
    pub(super) units: &'a Units,
}

impl Corpus<'_> {
    /// The unit one node belongs to.
    pub(super) fn unit_of(&self, node: usize) -> Option<usize> {
        self.graph.nodes.get(node).map(|entry| entry.unit)
    }

    /// The crate-root node of one unit.
    pub(super) fn root_of(&self, unit: usize) -> Option<usize> {
        self.graph.roots.get(unit).copied()
    }

    /// The module instance that lexically contains one node.
    pub(super) fn parent_of(&self, node: usize) -> Option<usize> {
        self.graph.nodes.get(node).and_then(|entry| entry.parent)
    }

    /// Whether one definition slot belongs to the unit that holds `node`.
    ///
    /// Definitions are indexed by name across the whole snapshot, so a source
    /// two units share states each of its names twice. Only this test keeps one
    /// unit's lookup from selecting the other unit's definition.
    pub(super) fn holds(&self, node: usize, slot: usize) -> bool {
        let owner = self.index.slot(slot).map(|found| found.node);
        owner.and_then(|found| self.unit_of(found)) == self.unit_of(node)
    }
}
