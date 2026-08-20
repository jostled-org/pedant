//! Canonical confinement and repository-relative naming for the Go loader.
//!
//! Every filesystem answer the loader needs is stated here, so "the loader
//! reads nothing outside the root" is a claim about one module rather than
//! about every call site.

use std::path::{Path, PathBuf};

use super::error::GoProjectError;
use crate::resolution::path_normalization::{RelativePathError, relative_text as lexical_text};
use crate::resolution::paths::RootError;

pub(super) use crate::resolution::paths::path_text;

/// Resolve the supplied root to its canonical directory form.
pub(super) fn canonical_root(root: &Path) -> Result<PathBuf, GoProjectError> {
    crate::resolution::paths::canonical_root(root).map_err(|error| GoProjectError::InvalidRoot {
        path: path_text(root),
        reason: match error {
            RootError::Unreadable(source) => source.to_string().into_boxed_str(),
            RootError::NotADirectory => Box::from("the project root is not a directory"),
        },
    })
}

/// The canonical form of a path beneath `root`, or `None` when it does not
/// exist.
///
/// A path that resolves outside the root is refused here rather than reported
/// as absent, so a symlink cannot widen what the loader goes on to read.
pub(super) fn canonical_in_root(
    root: &Path,
    path: &Path,
) -> Result<Option<PathBuf>, GoProjectError> {
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return Ok(None);
    };
    match canonical.starts_with(root) {
        true => Ok(Some(canonical)),
        false => Err(GoProjectError::OutOfRoot {
            path: path_text(&canonical),
            root: path_text(root),
        }),
    }
}

/// Normalize a path inside the root to repository-relative `/`-separated text.
pub(super) fn relative_text(root: &Path, path: &Path) -> Result<Box<str>, GoProjectError> {
    lexical_text(root, path).map_err(|error| match error {
        RelativePathError::OutsideRoot => GoProjectError::OutOfRoot {
            path: path_text(path),
            root: path_text(root),
        },
        RelativePathError::NonUtf8 => GoProjectError::NonUtf8Path {
            path: path_text(path),
        },
    })
}
