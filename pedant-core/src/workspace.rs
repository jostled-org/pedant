use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceMemberError {
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
}

pub fn resolve_workspace_members(
    workspace_root: &Path,
    members: &[Box<str>],
) -> Result<Vec<PathBuf>, WorkspaceMemberError> {
    let mut dirs: Vec<PathBuf> = members
        .iter()
        .map(|member| expand_member(workspace_root, member))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    dirs.sort();
    dirs.dedup();
    Ok(dirs)
}

fn expand_member(
    workspace_root: &Path,
    member: &str,
) -> Result<Vec<PathBuf>, WorkspaceMemberError> {
    match member.contains('*') {
        true => expand_glob_member(workspace_root, member),
        false => Ok(vec![workspace_root.join(member)]),
    }
}

fn expand_glob_member(
    workspace_root: &Path,
    member: &str,
) -> Result<Vec<PathBuf>, WorkspaceMemberError> {
    let (scan_root, pattern) = scan_root_for_member(workspace_root, member);
    if !scan_root.is_dir() {
        return Ok(Vec::new());
    }

    let max_depth = member_path_segments(pattern.as_ref()).len();
    let mut matches = Vec::new();
    collect_matching_dirs(
        &scan_root,
        &scan_root,
        pattern.as_ref(),
        max_depth,
        &mut matches,
    )?;
    Ok(matches)
}

fn scan_root_for_member(workspace_root: &Path, member: &str) -> (PathBuf, Box<str>) {
    let member_segments = member_path_segments(member);
    let split_index = member_segments
        .iter()
        .position(|segment| segment.contains('*'))
        .unwrap_or(member_segments.len());
    let mut scan_root = workspace_root.to_path_buf();
    for segment in &member_segments[..split_index] {
        scan_root.push(segment);
    }
    let pattern = member_segments[split_index..].join("/").into_boxed_str();
    (scan_root, pattern)
}

fn collect_matching_dirs(
    pattern_root: &Path,
    current_dir: &Path,
    member: &str,
    max_depth: usize,
    matches: &mut Vec<PathBuf>,
) -> Result<(), WorkspaceMemberError> {
    for entry in read_directory(current_dir)? {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if !matches_member_prefix(pattern_root, &path, member) {
            continue;
        }

        add_matching_dir(pattern_root, &path, member, matches);
        if relative_depth(pattern_root, &path) < max_depth {
            collect_matching_dirs(pattern_root, &path, member, max_depth, matches)?;
        }
    }
    Ok(())
}

fn add_matching_dir(workspace_root: &Path, path: &Path, member: &str, matches: &mut Vec<PathBuf>) {
    if matches_member_pattern(workspace_root, path, member) {
        matches.push(path.to_path_buf());
    }
}

fn read_directory(path: &Path) -> Result<Vec<fs::DirEntry>, WorkspaceMemberError> {
    fs::read_dir(path)
        .map_err(|source| WorkspaceMemberError::ReadDir {
            path: path.to_string_lossy().into(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| WorkspaceMemberError::ReadDir {
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

fn matches_member_prefix(workspace_root: &Path, path: &Path, member: &str) -> bool {
    let relative = match path.strip_prefix(workspace_root) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    let path_segments = path_segments(relative);
    let member_segments = member_path_segments(member);
    match path_segments.len() <= member_segments.len() {
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
