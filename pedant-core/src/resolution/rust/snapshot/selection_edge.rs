//! Cargo namespace edges exposed from one selected resolution unit.
//!
//! Manifest dependencies retain their declared activation and alias. Binary,
//! example, test, and benchmark roots also expose Cargo's implicit edge to the
//! package library. This module selects edges only; traversal and cycle
//! ownership remain in `selection`.

use std::sync::Arc;

use crate::resolution::rust::dependency::{CargoDependencyKind, RustDependency};
use crate::resolution::rust::identity::{PackageId, TargetId};
use crate::resolution::rust::package::RustPackage;
use crate::resolution::rust::project::RustProject;
use crate::resolution::rust::target::{CargoTargetKind, RustTarget};

use super::activation::{Predicate, conjoin};
use super::error::{ClosureSite, SourceClosureFailure, SourceClosureFailureKind};
use super::failure::failure;

/// Test compilation is the mode a library or binary root exposes its
/// development dependencies under.
const TEST_MODE: &str = "cfg(test)";

/// One namespace edge that selects an in-repository library unit.
pub(super) enum SelectedEdge<'a> {
    /// An edge declared in a Cargo dependency table.
    Declared {
        dependency: &'a RustDependency,
        target: &'a RustTarget,
        package: &'a RustPackage,
        predicate: Predicate,
    },
    /// Cargo's implicit edge from a non-library target to its package library.
    PackageLibrary {
        target: &'a RustTarget,
        package: &'a RustPackage,
    },
}

/// Select every declared and implicit edge one unit exposes.
pub(super) fn select(
    project: &RustProject,
    package: PackageId,
    root: (bool, CargoTargetKind),
) -> Result<Vec<SelectedEdge<'_>>, SourceClosureFailure> {
    let mut selected: Vec<SelectedEdge<'_>> = project
        .package_dependencies(package)
        .filter_map(|dependency| select_declared(project, dependency, root))
        .collect::<Result<_, _>>()?;
    selected.extend(package_library(project, package, root));
    Ok(selected)
}

/// `None` when the edge is not exposed or leaves the repository; a failure when
/// it selects an in-root package with no usable library target.
fn select_declared<'a>(
    project: &'a RustProject,
    dependency: &'a RustDependency,
    root: (bool, CargoTargetKind),
) -> Option<Result<SelectedEdge<'a>, SourceClosureFailure>> {
    let predicate = exposure(root, dependency.kind())
        .map(|mode| conjoin(&Predicate::of(dependency.activation()), &mode))?;
    let package = project.package(dependency.package()?)?;
    Some(
        library_target(project, dependency).map(|target| SelectedEdge::Declared {
            dependency,
            target,
            package,
            predicate,
        }),
    )
}

/// The library target a declared edge selects.
///
/// A package that declares no library and a library identity the project no
/// longer holds are different facts: the first is a manifest that cannot be
/// depended on, the second is an index that went stale under a project this
/// snapshot was told to trust.
fn library_target<'a>(
    project: &'a RustProject,
    dependency: &RustDependency,
) -> Result<&'a RustTarget, SourceClosureFailure> {
    let declared = dependency
        .library()
        .ok_or_else(|| missing_library(project, dependency))?;
    project
        .target(declared)
        .ok_or_else(|| unresolved_library(project, (dependency, declared)))
}

/// Cargo exposes a package's library crate to each non-library executable or
/// test target without requiring a manifest dependency declaration.
fn package_library(
    project: &RustProject,
    package: PackageId,
    root: (bool, CargoTargetKind),
) -> Option<SelectedEdge<'_>> {
    match root {
        (
            true,
            CargoTargetKind::Binary
            | CargoTargetKind::Example
            | CargoTargetKind::Test
            | CargoTargetKind::Benchmark,
        ) => library_edge(project, package),
        _ => None,
    }
}

/// The package's own library target, when it declares one.
fn library_edge(project: &RustProject, package: PackageId) -> Option<SelectedEdge<'_>> {
    let owner = project.package(package)?;
    let target = project
        .package_targets(package)
        .find(|target| target.kind() == CargoTargetKind::Library)?;
    Some(SelectedEdge::PackageLibrary {
        target,
        package: owner,
    })
}

impl SelectedEdge<'_> {
    pub(super) fn target(&self) -> &RustTarget {
        match self {
            Self::Declared { target, .. } | Self::PackageLibrary { target, .. } => target,
        }
    }

    pub(super) fn package(&self) -> &RustPackage {
        match self {
            Self::Declared { package, .. } | Self::PackageLibrary { package, .. } => package,
        }
    }

    /// The edge's name as the project already owns it, so a caller keying an
    /// edge shares the string rather than copying it.
    pub(super) fn shared_name(&self) -> &Arc<str> {
        match self {
            Self::Declared { dependency, .. } => &dependency.name,
            Self::PackageLibrary { target, .. } => &target.name,
        }
    }

    pub(super) fn kind(&self) -> CargoDependencyKind {
        match self {
            Self::Declared { dependency, .. } => dependency.kind(),
            Self::PackageLibrary { .. } => CargoDependencyKind::Normal,
        }
    }

    pub(super) fn predicate(&self) -> Predicate {
        match self {
            Self::Declared { predicate, .. } => predicate.clone(),
            Self::PackageLibrary { .. } => Predicate::Always,
        }
    }

    pub(super) fn site(&self, project: &RustProject) -> ClosureSite {
        match self {
            Self::Declared { dependency, .. } => dependency_site(project, dependency),
            Self::PackageLibrary { package, target } => ClosureSite::Dependency {
                package: Box::from(package.name()),
                dependency: Box::from(target.name()),
            },
        }
    }
}

fn exposure(root: (bool, CargoTargetKind), kind: CargoDependencyKind) -> Option<Predicate> {
    match root {
        (false, _) => normal_only(kind),
        (true, root_kind) => root_exposure(root_kind, kind),
    }
}

/// A dependency library propagates only its own normal dependencies.
fn normal_only(kind: CargoDependencyKind) -> Option<Predicate> {
    matches!(kind, CargoDependencyKind::Normal).then_some(Predicate::Always)
}

fn root_exposure(root_kind: CargoTargetKind, kind: CargoDependencyKind) -> Option<Predicate> {
    match (root_kind, kind) {
        (CargoTargetKind::BuildScript, CargoDependencyKind::Build) => Some(Predicate::Always),
        (CargoTargetKind::BuildScript, _) => None,
        (_, CargoDependencyKind::Build) => None,
        (_, CargoDependencyKind::Normal) => Some(Predicate::Always),
        (CargoTargetKind::Library | CargoTargetKind::Binary, CargoDependencyKind::Development) => {
            Some(Predicate::Stated(Arc::from(TEST_MODE)))
        }
        (_, CargoDependencyKind::Development) => Some(Predicate::Always),
    }
}

fn dependency_site(project: &RustProject, dependency: &RustDependency) -> ClosureSite {
    let package = project
        .package(dependency.source())
        .map(|owner| owner.name())
        .unwrap_or("<unknown>");
    ClosureSite::Dependency {
        package: Box::from(package),
        dependency: Box::from(dependency.name()),
    }
}

fn missing_library(project: &RustProject, dependency: &RustDependency) -> SourceClosureFailure {
    let site = dependency_site(project, dependency);
    let message = format!("{site}: the depended-on package declares no library target");
    failure(
        SourceClosureFailureKind::MissingDependencyLibraryTarget,
        (&site, None),
        message,
    )
}

fn unresolved_library(
    project: &RustProject,
    edge: (&RustDependency, TargetId),
) -> SourceClosureFailure {
    let (dependency, declared) = edge;
    let site = dependency_site(project, dependency);
    let message = format!(
        "{site}: the declared library target at local index {} is not in this project",
        declared.index()
    );
    failure(
        SourceClosureFailureKind::UnresolvedDependencyLibraryTarget,
        (&site, None),
        message,
    )
}
