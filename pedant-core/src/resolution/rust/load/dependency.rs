//! Dependency-table reading: kinds, renames, activations, and in-root paths.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::resolution::rust::dependency::{CargoDependencyKind, DependencyActivation};
use crate::resolution::rust::error::RustProjectError;
use crate::resolution::rust::paths;
use crate::resolution::rust::toml_view;

/// Cargo accepts both spellings of each optional dependency table.
const TABLE_KEYS: &[(&[&str], CargoDependencyKind)] = &[
    (&["dependencies"], CargoDependencyKind::Normal),
    (
        &["dev-dependencies", "dev_dependencies"],
        CargoDependencyKind::Development,
    ),
    (
        &["build-dependencies", "build_dependencies"],
        CargoDependencyKind::Build,
    ),
];

/// What a manifest declares about one dependency, before project identities
/// exist to bind it to.
pub(super) struct DeclaredEdge {
    pub(super) name: Arc<str>,
    pub(super) package_name: Arc<str>,
    pub(super) kind: CargoDependencyKind,
    pub(super) activation: DependencyActivation,
    /// Canonical manifest of the in-root package this edge selects, if any.
    pub(super) manifest: Option<PathBuf>,
}

/// Where a manifest's dependency paths resolve from.
pub(super) struct EdgeContext<'a> {
    pub(super) root: &'a Path,
    pub(super) directory: &'a Path,
    pub(super) workspace: Option<&'a toml::Table>,
}

/// Every dependency edge one manifest declares, ordered by kind then local name.
pub(super) fn declared_edges(
    context: &EdgeContext<'_>,
    manifest: &toml::Table,
) -> Result<Box<[DeclaredEdge]>, RustProjectError> {
    let mut edges = Vec::new();
    collect_tables(context, manifest, &DependencyActivation::Always, &mut edges)?;
    for (key, table) in target_tables(manifest) {
        let activation = DependencyActivation::Conditional(condition_text(key));
        collect_tables(context, table, &activation, &mut edges)?;
    }
    edges.sort_by(|left, right| {
        (left.kind, left.name.as_ref()).cmp(&(right.kind, right.name.as_ref()))
    });
    Ok(edges.into_boxed_slice())
}

/// The `[target.<key>]` tables, in sorted key order.
fn target_tables(manifest: &toml::Table) -> Box<[(&str, &toml::Table)]> {
    toml_view::table(manifest, "target")
        .map(|targets| {
            targets
                .iter()
                .filter_map(|(key, value)| value.as_table().map(|table| (key.as_str(), table)))
                .collect()
        })
        .unwrap_or_default()
}

/// Normalize a `[target.<key>]` selector into a recorded predicate.
fn condition_text(key: &str) -> Arc<str> {
    match key.starts_with("cfg(") {
        true => Arc::from(key),
        false => Arc::from(format!("target = \"{key}\"").as_str()),
    }
}

fn collect_tables(
    context: &EdgeContext<'_>,
    parent: &toml::Table,
    activation: &DependencyActivation,
    edges: &mut Vec<DeclaredEdge>,
) -> Result<(), RustProjectError> {
    for (keys, kind) in TABLE_KEYS {
        let table = toml_view::aliased_table(parent, keys);
        for (name, value) in table.into_iter().flatten() {
            edges.push(build_edge(
                context,
                (name.as_str(), value),
                *kind,
                activation,
            )?);
        }
    }
    Ok(())
}

fn build_edge(
    context: &EdgeContext<'_>,
    entry: (&str, &toml::Value),
    kind: CargoDependencyKind,
    activation: &DependencyActivation,
) -> Result<DeclaredEdge, RustProjectError> {
    let (name, value) = entry;
    let spec = value.as_table();
    let inherited = spec
        .filter(|table| toml_view::flag(table, "workspace", false))
        .and_then(|_| workspace_entry(context, name));
    Ok(DeclaredEdge {
        name: Arc::from(name),
        package_name: package_name(spec, inherited, name),
        kind,
        activation: combine(activation, optional_feature(spec, name)),
        manifest: resolve_manifest(context, spec, inherited)?,
    })
}

/// The `[workspace.dependencies]` entry an inheriting edge points at.
fn workspace_entry<'a>(context: &EdgeContext<'a>, name: &str) -> Option<&'a toml::Table> {
    context
        .workspace
        .and_then(|workspace| toml_view::table(workspace, "dependencies"))
        .and_then(|dependencies| dependencies.get(name))
        .and_then(toml::Value::as_table)
}

/// A `package = "..."` rename wins over the table key; inheritance may supply it.
fn package_name(
    spec: Option<&toml::Table>,
    inherited: Option<&toml::Table>,
    name: &str,
) -> Arc<str> {
    spec.and_then(|table| toml_view::string(table, "package"))
        .or_else(|| inherited.and_then(|table| toml_view::string(table, "package")))
        .map(Arc::from)
        .unwrap_or_else(|| Arc::from(name))
}

/// An optional dependency activates through its implicit Cargo feature.
fn optional_feature(spec: Option<&toml::Table>, name: &str) -> Option<Arc<str>> {
    spec.filter(|table| toml_view::flag(table, "optional", false))
        .map(|_| Arc::from(format!("feature = \"{name}\"").as_str()))
}

/// Conjoin the table's predicate with the dependency's own predicate.
fn combine(base: &DependencyActivation, feature: Option<Arc<str>>) -> DependencyActivation {
    match (base, feature) {
        (DependencyActivation::Always, None) => DependencyActivation::Always,
        (DependencyActivation::Always, Some(feature)) => DependencyActivation::Conditional(feature),
        (DependencyActivation::Conditional(condition), None) => {
            DependencyActivation::Conditional(Arc::clone(condition))
        }
        (DependencyActivation::Conditional(condition), Some(feature)) => {
            DependencyActivation::Conditional(Arc::from(
                format!("all({condition}, {feature})").as_str(),
            ))
        }
    }
}

/// A declared path resolves from the manifest's directory; an inherited path
/// resolves from the workspace root that declared it.
fn resolve_manifest(
    context: &EdgeContext<'_>,
    spec: Option<&toml::Table>,
    inherited: Option<&toml::Table>,
) -> Result<Option<PathBuf>, RustProjectError> {
    let declared = spec
        .and_then(|table| toml_view::string(table, "path"))
        .map(|path| context.directory.join(path));
    let workspace_path = inherited
        .and_then(|table| toml_view::string(table, "path"))
        .map(|path| context.root.join(path));
    let directory = match declared.or(workspace_path) {
        Some(directory) => directory,
        None => return Ok(None),
    };
    let manifest = paths::canonical_manifest(&directory)?;
    Ok(manifest.filter(|manifest| paths::contains(context.root, manifest)))
}
