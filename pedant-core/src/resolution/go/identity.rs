//! Opaque, project-scoped Go module identities.
//!
//! An identity carries the canonical-root fingerprint and the manifest revision
//! of the project that issued it, so an identity from one project can never
//! select a record in another project that happens to share a local index.

use std::fmt;

pub(super) use crate::resolution::identity::{index_of, position};

/// The scoping every issued identity carries, stated once for every language.
pub(super) type ProjectAuthority = crate::resolution::identity::ProjectAuthority;

/// Opaque identity of a Go module inside one loaded project.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoModuleId {
    authority: ProjectAuthority,
    index: u32,
}

impl GoModuleId {
    /// Issue an identity for the module at `index`.
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

impl fmt::Debug for GoModuleId {
    /// Render the identity without exposing its scoping fingerprints.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GoModuleId({})", self.index)
    }
}
