use std::fs;
use std::path::{Path, PathBuf};

use super::IndexError;
use super::crate_index::read_file;

pub use pedant_core::lint::discover_workspace_root;

#[derive(serde::Deserialize)]
struct WorkspaceSection {
    #[serde(default)]
    members: Box<[Box<str>]>,
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
    let manifest: toml::Value = super::crate_index::parse_toml(cargo_toml_str, cargo_toml_path)?;
    match manifest.get("workspace") {
        Some(workspace) => {
            let workspace = workspace
                .clone()
                .try_into::<WorkspaceSection>()
                .map_err(|source| IndexError::TomlParse {
                    path: cargo_toml_path.to_string_lossy().into(),
                    source,
                })?;
            resolve_members(workspace_root, &workspace.members)
        }
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
    let mut dirs: Vec<PathBuf> = members
        .iter()
        .map(|member| expand_member(workspace_root, member))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .filter(|p| p.join("Cargo.toml").exists())
        .collect();
    dirs.sort();
    Ok(dirs)
}

/// Expand a single workspace member pattern into candidate directories.
fn expand_member(workspace_root: &Path, member: &str) -> Result<Vec<PathBuf>, IndexError> {
    match member.contains('*') {
        true => expand_glob_member(workspace_root, member),
        false => Ok(vec![workspace_root.join(member)]),
    }
}

fn expand_glob_member(workspace_root: &Path, member: &str) -> Result<Vec<PathBuf>, IndexError> {
    let max_depth = member_path_segments(member).len();
    let mut matches = Vec::new();
    collect_matching_dirs(
        workspace_root,
        workspace_root,
        member,
        max_depth,
        &mut matches,
    )?;
    Ok(matches)
}

fn collect_matching_dirs(
    workspace_root: &Path,
    current_dir: &Path,
    member: &str,
    max_depth: usize,
    matches: &mut Vec<PathBuf>,
) -> Result<(), IndexError> {
    for entry in read_directory(current_dir)? {
        let path = entry.path();
        match (
            path.is_dir(),
            relative_depth(workspace_root, &path) < max_depth,
        ) {
            (true, true) => {
                add_matching_dir(workspace_root, &path, member, matches);
                collect_matching_dirs(workspace_root, &path, member, max_depth, matches)?;
            }
            (true, false) => add_matching_dir(workspace_root, &path, member, matches),
            (false, _) => continue,
        }
    }
    Ok(())
}

fn add_matching_dir(workspace_root: &Path, path: &Path, member: &str, matches: &mut Vec<PathBuf>) {
    if matches_member_pattern(workspace_root, path, member) {
        matches.push(path.to_path_buf());
    }
}

fn read_directory(path: &Path) -> Result<Vec<fs::DirEntry>, IndexError> {
    fs::read_dir(path)
        .map_err(|source| IndexError::Io {
            path: path.to_string_lossy().into(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| IndexError::Io {
            path: path.to_string_lossy().into(),
            source,
        })
}

fn relative_depth(workspace_root: &Path, path: &Path) -> usize {
    path.strip_prefix(workspace_root)
        .ok()
        .map(path_component_count)
        .unwrap_or(0)
}

fn matches_member_pattern(workspace_root: &Path, path: &Path, member: &str) -> bool {
    let relative = match path.strip_prefix(workspace_root) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    let path_segments = path_segments(relative);
    let member_segments = member_path_segments(member);
    match path_segments.len() == member_segments.len() {
        true => path_segments
            .iter()
            .zip(member_segments.iter())
            .all(|(path_segment, member_segment)| segment_matches(path_segment, member_segment)),
        false => false,
    }
}

fn path_component_count(path: &Path) -> usize {
    path.components().count()
}

fn path_segments(path: &Path) -> Vec<Box<str>> {
    path.iter()
        .map(|segment| segment.to_string_lossy().into_owned().into_boxed_str())
        .collect()
}

fn member_path_segments(member: &str) -> Vec<&str> {
    member
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn segment_matches(path_segment: &str, pattern_segment: &str) -> bool {
    let parts = pattern_segment.split('*').collect::<Vec<_>>();
    match parts.len() {
        1 => path_segment == pattern_segment,
        _ => wildcard_segment_matches(path_segment, &parts, pattern_segment.starts_with('*')),
    }
}

fn wildcard_segment_matches(
    path_segment: &str,
    parts: &[&str],
    starts_with_wildcard: bool,
) -> bool {
    let mut remaining = path_segment;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let found = match (index == 0, starts_with_wildcard) {
            (true, false) => remaining.strip_prefix(part),
            _ => remaining
                .find(part)
                .map(|offset| &remaining[offset + part.len()..]),
        };
        match found {
            Some(next) => remaining = next,
            None => return false,
        }
    }
    pattern_segment_ends_with_wildcard(parts, remaining)
}

fn pattern_segment_ends_with_wildcard(parts: &[&str], remaining: &str) -> bool {
    match parts.last() {
        Some(&"") => true,
        Some(_) => remaining.is_empty(),
        None => false,
    }
}
