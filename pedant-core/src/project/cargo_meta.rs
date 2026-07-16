use std::collections::BTreeMap;

use serde::Deserialize;

/// The subset of `cargo metadata --format-version 1` output that
/// `feature-boundary` needs. Unknown fields are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CargoMetadata {
    /// Every package in the dependency graph.
    #[serde(default)]
    pub packages: Vec<CargoPackage>,
    /// Package ids of the workspace members built by default.
    #[serde(default)]
    pub workspace_default_members: Vec<String>,
    /// Package ids of all workspace members (fallback when
    /// `workspace_default_members` is absent on older Cargo).
    #[serde(default)]
    pub workspace_members: Vec<String>,
}

/// A single resolved package.
#[derive(Debug, Clone, Deserialize)]
pub struct CargoPackage {
    /// Crate name.
    pub name: String,
    /// Opaque package id, matched against the workspace-member lists.
    pub id: String,
    /// Feature definitions: feature name → the features/deps it enables.
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
    /// Declared dependencies.
    #[serde(default)]
    pub dependencies: Vec<CargoDependency>,
}

/// A dependency declaration on a package.
#[derive(Debug, Clone, Deserialize)]
pub struct CargoDependency {
    /// The depended-on crate's name.
    pub name: String,
    /// `null`/absent for normal, `"dev"`, or `"build"`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Features requested on the dependency.
    #[serde(default)]
    pub features: Vec<String>,
    /// Whether the dependency's default features are enabled (defaults to true).
    #[serde(default = "default_uses_default_features")]
    pub uses_default_features: bool,
    /// Whether the dependency is optional.
    #[serde(default)]
    pub optional: bool,
    /// The local alias when the dependency is renamed.
    #[serde(default)]
    pub rename: Option<String>,
}

impl CargoDependency {
    /// The name this dependency is referred to by in feature strings
    /// (the rename if present, else the crate name).
    pub fn local_name(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }
}

fn default_uses_default_features() -> bool {
    true
}
