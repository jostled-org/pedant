use std::path::{Path, PathBuf};

use pedant_core::WorkspaceMemberError;
use pedant_core::resolve_workspace_members as expand_workspace_members;
use pedant_types::AnalysisTier;

use super::IndexError;
use super::crate_index::read_file;

pub use pedant_core::lint::discover_workspace_root;

#[derive(serde::Deserialize)]
struct WorkspaceSection {
    #[serde(default)]
    members: Box<[Box<str>]>,
}

#[derive(serde::Deserialize)]
struct CargoManifest {
    workspace: Option<WorkspaceSection>,
}

/// Resolve workspace member directories and extract each member's crate name.
///
/// Returns `(member_dir, crate_name)` pairs for every valid member.
pub(super) fn resolve_workspace_members_with_names(
    workspace_root: &Path,
    cargo_toml_str: &str,
    cargo_toml_path: &Path,
) -> Result<Vec<(PathBuf, Box<str>)>, IndexError> {
    let member_dirs = resolve_workspace_members(workspace_root, cargo_toml_str, cargo_toml_path)?;
    let mut result = Vec::with_capacity(member_dirs.len());
    for member_dir in member_dirs {
        let name = parse_crate_name(&member_dir)?;
        result.push((member_dir, name));
    }
    Ok(result)
}

/// Extract the `package.name` field from a crate's `Cargo.toml`.
fn parse_crate_name(crate_dir: &Path) -> Result<Box<str>, IndexError> {
    let cargo_toml = crate_dir.join("Cargo.toml");
    let content = read_file(&cargo_toml)?;
    let value: toml::Value = super::crate_index::parse_toml(&content, &cargo_toml)?;
    value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(Box::from)
        .ok_or_else(|| IndexError::MissingPackageName {
            path: cargo_toml.to_string_lossy().into(),
        })
}

/// Parse `Cargo.toml` to determine workspace members or single-crate layout.
///
/// Returns an error if the TOML is malformed. Returns a single-element vec
/// when the manifest is valid TOML but has no `[workspace]` key.
fn resolve_workspace_members(
    workspace_root: &Path,
    cargo_toml_str: &str,
    cargo_toml_path: &Path,
) -> Result<Vec<PathBuf>, IndexError> {
    let manifest: CargoManifest =
        toml::from_str(cargo_toml_str).map_err(|source| IndexError::TomlParse {
            path: cargo_toml_path.to_string_lossy().into(),
            source,
        })?;
    match manifest.workspace {
        Some(workspace) => resolve_members(workspace_root, &workspace.members),
        None => Ok(vec![workspace_root.to_path_buf()]),
    }
}

/// Resolve workspace member patterns to actual directories.
///
/// Supports literal paths and simple glob patterns (e.g. `crates/*`).
fn resolve_members(
    workspace_root: &Path,
    members: &[Box<str>],
) -> Result<Vec<PathBuf>, IndexError> {
    expand_workspace_members(workspace_root, members).map_err(map_workspace_member_error)
}

fn map_workspace_member_error(error: WorkspaceMemberError) -> IndexError {
    match error {
        WorkspaceMemberError::ReadDir { path, source } => IndexError::Io { path, source },
    }
}

pub(super) fn crate_tier(has_flows: bool, semantic_available: bool) -> AnalysisTier {
    match (has_flows, semantic_available) {
        (true, _) => AnalysisTier::DataFlow,
        (false, true) => AnalysisTier::Semantic,
        (false, false) => AnalysisTier::Syntactic,
    }
}
