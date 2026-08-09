//! The dependency view: one declared Cargo edge and how it activates.

use std::sync::Arc;

use super::identity::{PackageId, TargetId};

/// Which Cargo dependency table declared an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CargoDependencyKind {
    /// A `[dependencies]` edge.
    Normal,
    /// A `[dev-dependencies]` edge.
    Development,
    /// A `[build-dependencies]` edge.
    Build,
}

/// Whether an edge is unconditional, or carries a predicate this model records
/// without evaluating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyActivation {
    /// The edge is active in every configuration.
    Always,
    /// The edge is active only under the recorded, unevaluated predicate.
    Conditional(Arc<str>),
}

/// One dependency edge declared by a package inside the project.
#[derive(Debug)]
pub struct RustDependency {
    pub(super) source: PackageId,
    pub(super) name: Arc<str>,
    pub(super) package_name: Arc<str>,
    pub(super) kind: CargoDependencyKind,
    pub(super) activation: DependencyActivation,
    pub(super) package: Option<PackageId>,
    pub(super) library: Option<TargetId>,
}

impl RustDependency {
    /// The package that declares this edge.
    pub fn source(&self) -> PackageId {
        self.source
    }

    /// The namespace-local dependency name, which a rename may change.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The depended-on package's real Cargo name.
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// Which dependency table declared this edge.
    pub fn kind(&self) -> CargoDependencyKind {
        self.kind
    }

    /// Whether this edge is always active, and under which predicate otherwise.
    pub fn activation(&self) -> &DependencyActivation {
        &self.activation
    }

    /// The in-repository package this edge selects, when it resolves to one.
    pub fn package(&self) -> Option<PackageId> {
        self.package
    }

    /// The in-repository library target this edge selects, when one exists.
    pub fn library(&self) -> Option<TargetId> {
        self.library
    }
}
