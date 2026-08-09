//! The module-instance view: where one unit's modules live and how they nest.
//!
//! An instance is unit-local. The same source may be instantiated under two
//! units, or twice inside one unit through separate `#[path]` declarations, and
//! each occurrence is its own instance.

use std::fmt;
use std::sync::Arc;

/// Opaque identity of one module instance inside a single resolution unit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RustModuleId {
    index: u32,
}

impl RustModuleId {
    /// Issue an identity for the module instance at `index`.
    pub(super) fn new(index: u32) -> Self {
        Self { index }
    }

    /// The unit-local index this identity selects.
    pub(in crate::resolution::rust) fn index(&self) -> u32 {
        self.index
    }
}

impl fmt::Debug for RustModuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RustModuleId({})", self.index)
    }
}

/// One module instance: its place in the unit's module tree and the source
/// whose items it owns.
#[derive(Debug)]
pub struct RustModuleInstance {
    pub(super) id: RustModuleId,
    pub(super) parent: Option<RustModuleId>,
    pub(super) name: Arc<str>,
    pub(super) path: Arc<str>,
    pub(super) inline: bool,
    pub(super) depth: u32,
    /// Which lexical scope of [`Self::path`] this instance holds.
    pub(in crate::resolution::rust) scope: u32,
    /// This instance's position in the declaring source's IR declaration
    /// table; absent for a unit's crate root.
    pub(in crate::resolution::rust) declaration: Option<u32>,
}

impl RustModuleInstance {
    /// This instance's unit-local identity.
    pub fn id(&self) -> RustModuleId {
        self.id
    }

    /// The instance that declares this one; absent for the crate root.
    pub fn parent(&self) -> Option<RustModuleId> {
        self.parent
    }

    /// The declared module name; `crate` for the root instance.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The repository-relative source holding this instance's items.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the parent source declares this module inline.
    pub fn is_inline(&self) -> bool {
        self.inline
    }

    /// Module nesting depth below the crate root, which is zero.
    pub fn depth(&self) -> u32 {
        self.depth
    }
}
