//! The scoping and indexing shared by every language's opaque identities.
//!
//! An identity issued by one project must never select a record in another
//! project that happens to share a local index, and every language model needs
//! that guarantee in the same shape. One owner states it, so a second language
//! cannot answer the question differently.

/// The root fingerprint and manifest revision that scope every issued identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProjectAuthority {
    root: [u8; 32],
    revision: [u8; 32],
}

impl ProjectAuthority {
    /// Bind a canonical-root fingerprint to a manifest revision.
    pub(crate) fn new(root: [u8; 32], revision: [u8; 32]) -> Self {
        Self { root, revision }
    }

    /// Whether both authorities describe the same canonical repository root.
    pub(crate) fn same_root(&self, other: &Self) -> bool {
        self.root == other.root
    }

    /// Whether both authorities describe the same manifest revision.
    pub(crate) fn same_revision(&self, other: &Self) -> bool {
        self.revision == other.revision
    }
}

/// The slice position one stored index names.
///
/// Every index this crate stores is a `u32`, and every slice it reads is
/// addressed by `usize`. On a target where `usize` is narrower than `u32` the
/// saturating answer selects no element, which each caller already treats as
/// absence.
pub(crate) fn index_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// The stored index one slice position is recorded as.
///
/// The saturating answer names no record, which each caller reports rather
/// than resolves.
pub(crate) fn position(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
