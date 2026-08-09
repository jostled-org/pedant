//! Workspace member and exclude pattern expansion.
//!
//! Literal entries resolve directly against the workspace root; entries holding
//! `*` are expanded by scanning the filesystem in sorted order, so enumeration
//! order cannot change the result.

use std::path::{Path, PathBuf};

use super::error::RustProjectError;
use super::limits::ResolutionLimits;
use super::paths::read_directory;

/// How much of the tree one expansion has already walked.
///
/// Member globs are expanded before any manifest is read, so `max_manifests`
/// bounds nothing here. The budget is spent across every pattern of one
/// workspace rather than reset per pattern, because the cost a caller cares
/// about is the whole expansion.
struct Scan {
    visited: u32,
    ceiling: u32,
}

impl Scan {
    fn new(limits: ResolutionLimits) -> Self {
        Self {
            visited: 0,
            ceiling: limits.max_member_scan_entries,
        }
    }

    /// Charge one directory entry, refusing once the ceiling is crossed.
    fn charge(&mut self) -> Result<(), RustProjectError> {
        self.visited = self.visited.saturating_add(1);
        match self.visited > self.ceiling {
            true => Err(RustProjectError::MemberScanLimitExceeded {
                limit: self.ceiling,
            }),
            false => Ok(()),
        }
    }
}

/// Expand `members` minus `exclude` into sorted, deduplicated member
/// directories that hold a `Cargo.toml`.
pub(super) fn member_directories(
    workspace_root: &Path,
    patterns: (&[Box<str>], &[Box<str>]),
    limits: ResolutionLimits,
) -> Result<Box<[PathBuf]>, RustProjectError> {
    let (members, exclude) = patterns;
    let mut scan = Scan::new(limits);
    let excluded = expand_patterns(workspace_root, exclude, &mut scan)?;
    let mut dirs: Vec<PathBuf> = expand_patterns(workspace_root, members, &mut scan)?
        .into_iter()
        .filter(|path| path.join("Cargo.toml").is_file())
        .filter(|path| !is_excluded(path, &excluded))
        .collect();
    dirs.sort();
    dirs.dedup();
    Ok(dirs.into_boxed_slice())
}

/// An exclude entry removes the named directory and everything beneath it.
fn is_excluded(path: &Path, excluded: &[PathBuf]) -> bool {
    excluded.iter().any(|entry| path.starts_with(entry))
}

fn expand_patterns(
    workspace_root: &Path,
    patterns: &[Box<str>],
    scan: &mut Scan,
) -> Result<Vec<PathBuf>, RustProjectError> {
    let mut expanded: Vec<PathBuf> = Vec::new();
    for pattern in patterns {
        expanded.extend(expand_pattern(workspace_root, pattern, scan)?);
    }
    Ok(expanded)
}

fn expand_pattern(
    workspace_root: &Path,
    pattern: &str,
    scan: &mut Scan,
) -> Result<Vec<PathBuf>, RustProjectError> {
    match pattern.contains('*') {
        true => expand_glob_pattern(workspace_root, pattern, scan),
        false => Ok(vec![workspace_root.join(pattern)]),
    }
}

fn expand_glob_pattern(
    workspace_root: &Path,
    pattern: &str,
    scan: &mut Scan,
) -> Result<Vec<PathBuf>, RustProjectError> {
    let (scan_root, tail) = scan_root_for_pattern(workspace_root, pattern);
    if !scan_root.is_dir() {
        return Ok(Vec::new());
    }

    let max_depth = pattern_segments(tail.as_ref()).len();
    let mut matches = Vec::new();
    collect_matching_dirs(
        (&scan_root, &scan_root),
        (tail.as_ref(), max_depth),
        (&mut matches, scan),
    )?;
    matches.sort();
    Ok(matches)
}

fn scan_root_for_pattern(workspace_root: &Path, pattern: &str) -> (PathBuf, Box<str>) {
    let segments = pattern_segments(pattern);
    let split_index = segments
        .iter()
        .position(|segment| segment.contains('*'))
        .unwrap_or(segments.len());
    let mut scan_root = workspace_root.to_path_buf();
    for segment in &segments[..split_index] {
        scan_root.push(segment);
    }
    (
        scan_root,
        segments[split_index..].join("/").into_boxed_str(),
    )
}

fn collect_matching_dirs(
    roots: (&Path, &Path),
    shape: (&str, usize),
    found: (&mut Vec<PathBuf>, &mut Scan),
) -> Result<(), RustProjectError> {
    let (pattern_root, current_dir) = roots;
    let (pattern, max_depth) = shape;
    let (matches, scan) = found;
    for entry in read_directory(current_dir)? {
        scan.charge()?;
        let path = entry.path();
        let candidate = path.is_dir() && matches_prefix(pattern_root, &path, pattern);
        if !candidate {
            continue;
        }

        add_matching_dir(pattern_root, &path, pattern, matches);
        if relative_depth(pattern_root, &path) < max_depth {
            collect_matching_dirs((pattern_root, &path), shape, (matches, scan))?;
        }
    }
    Ok(())
}

fn add_matching_dir(pattern_root: &Path, path: &Path, pattern: &str, matches: &mut Vec<PathBuf>) {
    if matches_pattern(pattern_root, path, pattern) {
        matches.push(path.to_path_buf());
    }
}

fn relative_depth(pattern_root: &Path, path: &Path) -> usize {
    path.strip_prefix(pattern_root)
        .ok()
        .map(|relative| relative.components().count())
        .unwrap_or(0)
}

fn matches_pattern(pattern_root: &Path, path: &Path, pattern: &str) -> bool {
    let path_parts = match relative_segments(pattern_root, path) {
        Some(parts) => parts,
        None => return false,
    };
    let pattern_parts = pattern_segments(pattern);
    path_parts.len() == pattern_parts.len() && zip_matches(&path_parts, &pattern_parts)
}

fn matches_prefix(pattern_root: &Path, path: &Path, pattern: &str) -> bool {
    let path_parts = match relative_segments(pattern_root, path) {
        Some(parts) => parts,
        None => return false,
    };
    let pattern_parts = pattern_segments(pattern);
    path_parts.len() <= pattern_parts.len() && zip_matches(&path_parts, &pattern_parts)
}

fn zip_matches(path_parts: &[Box<str>], pattern_parts: &[&str]) -> bool {
    path_parts
        .iter()
        .zip(pattern_parts.iter())
        .all(|(path_part, pattern_part)| segment_matches(path_part, pattern_part))
}

fn relative_segments(pattern_root: &Path, path: &Path) -> Option<Vec<Box<str>>> {
    path.strip_prefix(pattern_root).ok().map(|relative| {
        relative
            .iter()
            .map(|segment| segment.to_string_lossy().into_owned().into_boxed_str())
            .collect()
    })
}

fn pattern_segments(pattern: &str) -> Vec<&str> {
    pattern
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
    ends_with_wildcard(parts, remaining)
}

fn ends_with_wildcard(parts: &[&str], remaining: &str) -> bool {
    match parts.last() {
        Some(&"") => true,
        Some(_) => remaining.is_empty(),
        None => false,
    }
}
