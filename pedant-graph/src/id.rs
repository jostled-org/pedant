//! Dense typed identities into one graph's collections.
//!
//! One identity shape, branded three ways: a node position can never be read as
//! a reference or an edge position, and the value semantics, serialization, and
//! `index()` form cannot drift between them. Each is a transparent `u32` with no
//! public constructor, so a caller reads an identity out of a graph and indexes
//! back into the same graph but cannot manufacture one that names nothing.

use std::marker::PhantomData;

use serde::Serialize;

/// One dense `u32` position whose marker fixes the collection it addresses.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[serde(transparent)]
pub struct GraphId<K> {
    index: u32,
    #[serde(skip)]
    collection: PhantomData<fn() -> K>,
}

impl<K> GraphId<K> {
    pub(crate) fn new(index: u32) -> Self {
        Self {
            index,
            collection: PhantomData,
        }
    }

    /// This identity's position in the collection it addresses.
    pub fn index(self) -> u32 {
        self.index
    }
}

/// Marker distinguishing node identities from the other identity kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeIdKind;

/// Marker distinguishing reference identities from the other identity kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceIdKind;

/// Marker distinguishing edge identities from the other identity kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeIdKind;

/// A node's dense identity within one [`crate::CodeGraph`].
pub type GraphNodeId = GraphId<NodeIdKind>;

/// A reference record's dense identity within one [`crate::CodeGraph`].
pub type GraphReferenceId = GraphId<ReferenceIdKind>;

/// An edge's dense identity within one [`crate::CodeGraph`].
pub type GraphEdgeId = GraphId<EdgeIdKind>;

/// The slice position one stored identity names.
///
/// Every identity this crate stores is a `u32`, and every slice it reads is
/// addressed by `usize`. On a target where `usize` is narrower, the saturating
/// answer selects no element, which each caller already treats as absence.
pub(crate) fn index_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// The stored identity one slice position is recorded as.
///
/// The saturating answer names no record, and every caller reads it as absence:
/// a diagnostic payload prints the ceiling value, and a lookup made with it
/// selects nothing. Minting paths never reach the saturation, because
/// [`crate::GraphLimits`] proves the configured and fixed-width ceilings first;
/// a position taken from a supplied collection, such as a snapshot dependency
/// edge index, is bounded by no ceiling and may reach it.
pub(crate) fn position(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
