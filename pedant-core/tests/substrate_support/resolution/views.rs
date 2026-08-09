//! Comparable text taken from the public project and snapshot views.
//!
//! Every resolution case asserts against ordered `String` lines rather than
//! against nested structures, so each borrowed view is rendered exactly once
//! here and no case reimplements a reader.

use pedant_core::resolution::rust::{
    CargoTargetKind, DependencyActivation, PackageId, RustProject, RustResolutionSnapshot,
    RustResolutionUnit, RustSnapshotError, RustSnapshotUnitId, RustTargetSnapshot,
    SourceClosureFailureKind, TargetId,
};

/// The identity of one target, selected by the package that declares it.
pub fn target_id(
    project: &RustProject,
    package: &str,
    kind: CargoTargetKind,
    name: &str,
) -> TargetId {
    project
        .targets()
        .iter()
        .find(|target| {
            target.kind() == kind
                && target.name() == name
                && project
                    .package(target.package())
                    .is_some_and(|owner| owner.name() == package)
        })
        .map(|target| target.id())
        .unwrap_or_else(|| panic!("{package} declares no {kind:?} target named {name}"))
}

/// The library target every single-package fixture declares.
pub fn app_library(project: &RustProject) -> TargetId {
    target_id(project, "app", CargoTargetKind::Library, "app")
}

/// The one library target a single-package fixture declares, whatever its
/// package is named.
pub fn sole_library(project: &RustProject) -> TargetId {
    let libraries: Vec<TargetId> = project
        .targets()
        .iter()
        .filter(|target| target.kind() == CargoTargetKind::Library)
        .map(|target| target.id())
        .collect();
    match libraries.as_slice() {
        [only] => *only,
        found => panic!("the fixture declares {} library targets", found.len()),
    }
}

/// The name of one package, or a stable placeholder when the project lost it.
pub fn package_name(project: &RustProject, id: PackageId) -> &str {
    project
        .package(id)
        .map(|package| package.name())
        .unwrap_or("<unknown>")
}

/// The name of one target, or a stable placeholder when the project lost it.
pub fn target_name(project: &RustProject, id: TargetId) -> &str {
    project
        .target(id)
        .map(|target| target.name())
        .unwrap_or("<unknown>")
}

/// The activation predicate, with `always` standing for the unconditional case.
pub fn activation_text(activation: &DependencyActivation) -> &str {
    match activation {
        DependencyActivation::Always => "always",
        DependencyActivation::Conditional(condition) => condition,
    }
}

/// The paths one probe observed, as comparable borrowed text.
#[cfg(feature = "resolution-test-support")]
pub fn observed_paths(paths: &[Box<str>]) -> Vec<&str> {
    paths.iter().map(|path| &**path).collect()
}

/// Every typed failure kind one snapshot attempt reported.
pub fn closure_kinds(error: &RustSnapshotError) -> Vec<SourceClosureFailureKind> {
    closure_of(error)
        .failures()
        .iter()
        .map(|entry| entry.kind())
        .collect()
}

/// The paths a failed closure did reach, as diagnostic evidence only.
pub fn reached_paths(error: &RustSnapshotError) -> Vec<String> {
    closure_of(error)
        .reached()
        .iter()
        .map(|path| path.to_string())
        .collect()
}

fn closure_of(error: &RustSnapshotError) -> &pedant_core::resolution::rust::SourceClosureError {
    match error {
        RustSnapshotError::SourceClosure(closure) => closure,
        other => panic!("expected a source-closure failure, got {other:?}"),
    }
}

/// `index|name|parent` for every lexical module scope one snapshotted source
/// declares, which is what a site's scope index means.
pub fn render_scopes(snapshot: &RustResolutionSnapshot, path: &str) -> Vec<String> {
    snapshot
        .source(path)
        .unwrap_or_else(|| panic!("{path} is not a source of this snapshot"))
        .ir()
        .module_scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| format!("{index}|{}|{:?}", scope.name, scope.parent))
        .collect()
}

/// Every source one target snapshot stored, in its sorted path order.
pub fn source_paths(snapshot: &RustTargetSnapshot) -> Vec<&str> {
    snapshot
        .sources()
        .iter()
        .map(|source| source.path())
        .collect()
}

/// `id|name|source|depth|inline|parent` for every module instance one unit
/// holds, in the order the unit records them.
pub fn render_modules(unit: &RustResolutionUnit) -> Vec<String> {
    unit.modules()
        .iter()
        .map(|instance| {
            format!(
                "{:?}|{}|{}|{}|{}|{:?}",
                instance.id(),
                instance.name(),
                instance.path(),
                instance.depth(),
                instance.is_inline(),
                instance.parent(),
            )
        })
        .collect()
}

/// The module instances one target's own unit holds. Instances are unit-local,
/// so the multi-unit snapshot is the only view that exposes them.
pub fn root_modules(project: &RustProject, target: TargetId) -> Vec<String> {
    let snapshot = project
        .snapshot_resolution(target)
        .expect("the target resolves against its own unit");
    let root = snapshot.unit(snapshot.root_unit()).expect("the root unit");
    render_modules(root)
}

/// `package|target|activation` for every unit a resolution snapshot selected.
pub fn render_units(project: &RustProject, snapshot: &RustResolutionSnapshot) -> Vec<String> {
    snapshot
        .units()
        .iter()
        .map(|unit| {
            format!(
                "{}|{}|{}",
                package_name(project, unit.package()),
                target_name(project, unit.target()),
                activation_text(unit.activation()),
            )
        })
        .collect()
}

/// `source|alias|target|kind|activation` for every Cargo edge between units.
pub fn render_edges(project: &RustProject, snapshot: &RustResolutionSnapshot) -> Vec<String> {
    snapshot
        .edges()
        .iter()
        .map(|edge| {
            format!(
                "{}|{}|{}|{:?}|{}",
                unit_package(project, snapshot, edge.source()),
                edge.name(),
                unit_package(project, snapshot, edge.target()),
                edge.kind(),
                activation_text(edge.activation()),
            )
        })
        .collect()
}

/// `package|source,source` for every unit, which binds each closure to the
/// unit that owns it rather than to the path-deduplicated store.
pub fn render_unit_sources(
    project: &RustProject,
    snapshot: &RustResolutionSnapshot,
) -> Vec<String> {
    snapshot
        .units()
        .iter()
        .map(|unit| {
            let sources: Vec<&str> = unit.sources().iter().map(|path| &**path).collect();
            format!(
                "{}|{}",
                package_name(project, unit.package()),
                sources.join(",")
            )
        })
        .collect()
}

/// The unit one package contributes to a resolution snapshot.
pub fn unit_of<'a>(
    project: &RustProject,
    snapshot: &'a RustResolutionSnapshot,
    package: &str,
) -> &'a RustResolutionUnit {
    snapshot
        .units()
        .iter()
        .find(|unit| package_name(project, unit.package()) == package)
        .unwrap_or_else(|| panic!("{package} contributes no unit"))
}

fn unit_package<'a>(
    project: &'a RustProject,
    snapshot: &RustResolutionSnapshot,
    unit: RustSnapshotUnitId,
) -> &'a str {
    snapshot
        .unit(unit)
        .map(|found| package_name(project, found.package()))
        .unwrap_or("<unknown>")
}
