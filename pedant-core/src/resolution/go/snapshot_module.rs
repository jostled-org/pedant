//! The modules a snapshot carries and the local dependency edges between them.
//!
//! A snapshot restates the modules its project admitted rather than borrowing
//! them, so a graph built from a snapshot outlives the project the snapshot was
//! taken from and cannot be joined to a different one by accident.

use std::fmt;
use std::sync::Arc;

/// Opaque identity of one module inside a single snapshot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoSnapshotModuleId {
    index: u32,
}

impl GoSnapshotModuleId {
    /// Issue an identity for the module at `index`.
    pub(super) fn new(index: u32) -> Self {
        Self { index }
    }

    /// The snapshot-local index this identity selects.
    pub(super) fn index(self) -> u32 {
        self.index
    }
}

impl fmt::Debug for GoSnapshotModuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GoSnapshotModuleId({})", self.index)
    }
}

/// One module a snapshot walked: the main module, or a local replacement a
/// required module resolved to.
#[derive(Debug)]
pub struct GoSnapshotModule {
    pub(super) id: GoSnapshotModuleId,
    pub(super) path: Arc<str>,
    pub(super) directory: Arc<str>,
    pub(super) manifest: Arc<str>,
    pub(super) depth: u32,
}

impl GoSnapshotModule {
    /// This module's snapshot-local identity.
    pub fn id(&self) -> GoSnapshotModuleId {
        self.id
    }

    /// The module path its own `module` directive declares.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The module's directory, repository-relative and `/`-separated. The main
    /// module's directory is the empty string.
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// The module's `go.mod`, repository-relative and `/`-separated.
    pub fn manifest(&self) -> &str {
        &self.manifest
    }

    /// How many local replacement hops separate this module from the main
    /// module, which sits at zero.
    pub fn depth(&self) -> u32 {
        self.depth
    }
}

/// One requirement an admitted local replacement satisfied, as an edge between
/// two snapshot modules.
///
/// An external or version-only requirement states no edge: nothing was read for
/// it, so a graph built from this snapshot has no node to point at.
#[derive(Debug)]
pub struct GoSnapshotEdge {
    pub(super) source: GoSnapshotModuleId,
    pub(super) target: GoSnapshotModuleId,
    pub(super) module_path: Box<str>,
    pub(super) version: Box<str>,
}

impl GoSnapshotEdge {
    /// The module that declares the requirement.
    pub fn source(&self) -> GoSnapshotModuleId {
        self.source
    }

    /// The module the requirement resolved to.
    pub fn target(&self) -> GoSnapshotModuleId {
        self.target
    }

    /// The module path the requirement names.
    pub fn module_path(&self) -> &str {
        &self.module_path
    }

    /// The version the requirement names.
    pub fn version(&self) -> &str {
        &self.version
    }
}
