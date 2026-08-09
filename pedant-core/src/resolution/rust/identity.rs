//! Opaque, project-scoped identities.
//!
//! Every identity carries the canonical-root fingerprint and the manifest
//! revision of the project that issued it, so an identity from one project can
//! never select a record in another project that happens to share a local
//! index.

use std::fmt;

/// The root fingerprint and manifest revision that scope every issued identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ProjectAuthority {
    root: [u8; 32],
    revision: [u8; 32],
}

impl ProjectAuthority {
    /// Bind a canonical-root fingerprint to a manifest revision.
    pub(super) fn new(root: [u8; 32], revision: [u8; 32]) -> Self {
        Self { root, revision }
    }

    /// Whether both authorities describe the same canonical repository root.
    pub(super) fn same_root(&self, other: &Self) -> bool {
        self.root == other.root
    }

    /// Whether both authorities describe the same manifest revision.
    pub(super) fn same_revision(&self, other: &Self) -> bool {
        self.revision == other.revision
    }
}

/// Opaque identity of a Cargo package inside one loaded project.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageId {
    authority: ProjectAuthority,
    index: u32,
}

impl PackageId {
    /// Issue an identity for the package at `index`.
    pub(super) fn new(authority: ProjectAuthority, index: u32) -> Self {
        Self { authority, index }
    }

    /// The issuing project's authority.
    pub(super) fn authority(&self) -> ProjectAuthority {
        self.authority
    }

    /// The project-local index this identity selects.
    pub(super) fn index(&self) -> u32 {
        self.index
    }
}

impl fmt::Debug for PackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_identity(formatter, "PackageId", self.index)
    }
}

/// Opaque identity of a Cargo target inside one loaded project.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetId {
    authority: ProjectAuthority,
    index: u32,
}

impl TargetId {
    /// Issue an identity for the target at `index`.
    pub(super) fn new(authority: ProjectAuthority, index: u32) -> Self {
        Self { authority, index }
    }

    /// The issuing project's authority.
    pub(super) fn authority(&self) -> ProjectAuthority {
        self.authority
    }

    /// The project-local index this identity selects.
    pub(super) fn index(&self) -> u32 {
        self.index
    }
}

impl fmt::Debug for TargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_identity(formatter, "TargetId", self.index)
    }
}

/// Render an identity without exposing its scoping fingerprints.
fn write_identity(formatter: &mut fmt::Formatter<'_>, label: &str, index: u32) -> fmt::Result {
    write!(formatter, "{label}({index})")
}

/// The slice position one stored index names.
///
/// Every index this crate stores is a `u32`, and every slice it reads is
/// addressed by `usize`. On a target where `usize` is narrower than `u32` the
/// saturating answer selects no element, which each caller already treats as
/// absence.
pub(super) fn index_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// The stored index one slice position is recorded as.
///
/// The saturating answer names no record, which each caller reports rather
/// than resolves.
pub(super) fn position(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
