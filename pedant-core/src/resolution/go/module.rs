//! One module admitted into a Go project.

use std::sync::Arc;

use super::identity::GoModuleId;

/// One module admitted into a project: the main module, or a local replacement
/// a required module resolved to.
///
/// Every field is private and every view is borrowed, so a caller reads what the
/// manifest declared and cannot restate it as something the loader never saw.
#[derive(Debug)]
pub struct GoModule {
    pub(super) id: GoModuleId,
    pub(super) path: Arc<str>,
    pub(super) directory: Box<str>,
    pub(super) manifest: Box<str>,
    pub(super) depth: u32,
}

impl GoModule {
    /// This module's project-scoped identity.
    pub fn id(&self) -> GoModuleId {
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
