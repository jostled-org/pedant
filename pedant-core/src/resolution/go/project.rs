//! The project view: the main module, every admitted local replacement, and
//! every directive the root manifest states.

use std::path::Path;

use super::exclusion::GoExclusion;
use super::identity::{GoModuleId, ProjectAuthority, index_of};
use super::limits::GoResolutionLimits;
use super::module::GoModule;
use super::replacement::GoReplacement;
use super::requirement::GoRequirement;
use super::snapshot::GoResolutionSnapshot;
use super::snapshot_error::GoSnapshotError;
use super::{error::GoProjectError, load, snapshot};

/// A factual Go module project rooted at one canonical repository root.
///
/// Views are borrowed and deterministically ordered by stable structural keys,
/// so reordering filesystem enumeration cannot change what a caller reads. The
/// main module is a field rather than the first element of a list, because a
/// loaded project always has exactly one and no caller should have to ask.
#[derive(Debug)]
pub struct GoProject {
    pub(super) root: Box<Path>,
    pub(super) limits: GoResolutionLimits,
    pub(super) authority: ProjectAuthority,
    pub(super) main: GoModule,
    pub(super) required: Box<[GoModule]>,
    pub(super) requirements: Box<[GoRequirement]>,
    pub(super) replacements: Box<[GoReplacement]>,
    pub(super) exclusions: Box<[GoExclusion]>,
}

impl GoProject {
    /// Read the `go.mod` at `root` and index the module project it declares.
    ///
    /// Reads `go.mod` files only: no Go source is opened, and no process,
    /// toolchain, code generator, or network client is invoked.
    pub fn load(root: &Path, limits: GoResolutionLimits) -> Result<Self, GoProjectError> {
        load::load_project(root, limits)
    }

    /// Walk every admitted module's packages and snapshot what they state.
    ///
    /// Reads the `.go` sources the walk admits and nothing else: no process,
    /// toolchain, code generator, or network client is invoked, and no
    /// environment or host selection state decides which sources exist.
    pub fn snapshot_resolution(&self) -> Result<GoResolutionSnapshot, GoSnapshotError> {
        snapshot::build(self)
    }

    /// The canonical repository root this project was loaded from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The limits this project was loaded under and retains for snapshots.
    pub fn limits(&self) -> GoResolutionLimits {
        self.limits
    }

    /// The main module, which the root `go.mod` declares.
    pub fn root_module(&self) -> &GoModule {
        &self.main
    }

    /// Every admitted module: the main module first, then each local
    /// replacement in admission order.
    pub fn modules(&self) -> impl Iterator<Item = &GoModule> {
        std::iter::once(&self.main).chain(self.required.iter())
    }

    /// The module an identity issued by this project selects.
    pub fn module(&self, id: GoModuleId) -> Option<&GoModule> {
        let index = self.select(id)?;
        match index.checked_sub(1) {
            None => Some(&self.main),
            Some(offset) => self.required.get(offset),
        }
    }

    /// Every requirement every admitted module declares, ordered by declaring
    /// module and then by required path and version.
    pub fn requirements(&self) -> &[GoRequirement] {
        &self.requirements
    }

    /// Every requirement one admitted module declares.
    pub fn module_requirements(&self, module: GoModuleId) -> impl Iterator<Item = &GoRequirement> {
        self.requirements
            .iter()
            .filter(move |requirement| requirement.module() == module)
    }

    /// Every `replace` directive the root manifest states, ordered by replaced
    /// path and version, together with whether a requirement selected it.
    pub fn replacements(&self) -> &[GoReplacement] {
        &self.replacements
    }

    /// Every `exclude` directive the root manifest states, ordered by excluded
    /// path and version.
    pub fn exclusions(&self) -> &[GoExclusion] {
        &self.exclusions
    }

    /// Reject an identity issued by another project before it selects a record.
    fn select(&self, id: GoModuleId) -> Option<usize> {
        match id.authority() == self.authority {
            true => Some(index_of(id.index())),
            false => None,
        }
    }
}
