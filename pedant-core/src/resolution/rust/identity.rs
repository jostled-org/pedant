//! Opaque, project-scoped identities.
//!
//! Every identity carries the canonical-root fingerprint and the manifest
//! revision of the project that issued it, so an identity from one project can
//! never select a record in another project that happens to share a local
//! index.

use std::fmt;

pub(super) use crate::resolution::identity::{index_of, position};

/// The scoping both identities below carry, stated once for every language.
pub(super) type ProjectAuthority = crate::resolution::identity::ProjectAuthority;

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
