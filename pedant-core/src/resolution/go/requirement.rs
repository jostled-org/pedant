//! One `require` directive, and what the root manifest's authority resolved it
//! to.

use std::sync::Arc;

use super::identity::GoModuleId;

/// One `require` directive, and what the project resolved it to.
#[derive(Debug)]
pub struct GoRequirement {
    pub(super) module: GoModuleId,
    pub(super) path: Box<str>,
    pub(super) version: Box<str>,
    pub(super) resolution: GoRequirementResolution,
}

impl GoRequirement {
    /// The admitted module whose manifest declares this requirement.
    pub fn module(&self) -> GoModuleId {
        self.module
    }

    /// The required module path, exactly as declared.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The required version, exactly as declared. No minimal-version selection
    /// runs, so two modules may require one path at two versions.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// What the root manifest's directives resolved this requirement to.
    pub fn resolution(&self) -> &GoRequirementResolution {
        &self.resolution
    }
}

/// What a requirement resolved to under the root manifest's authority.
#[derive(Debug)]
pub enum GoRequirementResolution {
    /// Unreplaced, or replaced by nothing this project reads: declared external
    /// metadata with no module record.
    External,
    /// Replaced by another module version, which stays external metadata.
    ReplacedModule {
        /// The replacing module path, shared with the replacement that states
        /// it because one entry can answer several requirements.
        path: Arc<str>,
        /// The replacing version, shared for the same reason.
        version: Arc<str>,
    },
    /// Replaced by an admitted in-root local module.
    LocalModule(GoModuleId),
}
