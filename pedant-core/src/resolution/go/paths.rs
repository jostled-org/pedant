//! Canonical confinement and repository-relative naming for the Go loader and
//! the snapshots taken from it.
//!
//! Every filesystem answer either stage needs is stated here, so "nothing
//! outside the root is read" is a claim about one module rather than about
//! every call site. The answers are stated once and adapted to each stage's own
//! error type, because a confinement rule that existed twice could hold for a
//! manifest and not for a source.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::GoProjectError;
use super::snapshot_error::GoSnapshotError;
use crate::resolution::path_normalization::{RelativePathError, relative_text as lexical_text};
use crate::resolution::paths::RootError;

pub(super) use crate::resolution::paths::path_text;

/// Why one path answer could not be given.
///
/// Both stages refuse the same two ways, so the reason is stated once and each
/// stage's error type is built from it.
pub(super) enum PathFault {
    /// The path resolves outside the supplied repository root.
    OutOfRoot {
        /// The path that escaped.
        path: Box<str>,
        /// The root that does not contain it.
        root: Box<str>,
    },
    /// The path is not valid UTF-8, so it has no normalized text.
    NonUtf8 {
        /// The offending path, rendered lossily for the message only.
        path: Box<str>,
    },
}

impl From<PathFault> for GoProjectError {
    fn from(fault: PathFault) -> Self {
        match fault {
            PathFault::OutOfRoot { path, root } => Self::OutOfRoot { path, root },
            PathFault::NonUtf8 { path } => Self::NonUtf8Path { path },
        }
    }
}

impl From<PathFault> for GoSnapshotError {
    fn from(fault: PathFault) -> Self {
        match fault {
            PathFault::OutOfRoot { path, root } => Self::OutOfRoot { path, root },
            PathFault::NonUtf8 { path } => Self::NonUtf8Path { path },
        }
    }
}

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
/// as absent, so a symlink cannot widen what either stage goes on to read.
pub(super) fn canonical_in_root(root: &Path, path: &Path) -> Result<Option<PathBuf>, PathFault> {
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return Ok(None);
    };
    match canonical.starts_with(root) {
        true => Ok(Some(canonical)),
        false => Err(PathFault::OutOfRoot {
            path: path_text(&canonical),
            root: path_text(root),
        }),
    }
}

/// Normalize a path inside the root to repository-relative `/`-separated text.
pub(super) fn relative_text(root: &Path, path: &Path) -> Result<Box<str>, PathFault> {
    lexical_text(root, path).map_err(|error| match error {
        RelativePathError::OutsideRoot => PathFault::OutOfRoot {
            path: path_text(path),
            root: path_text(root),
        },
        RelativePathError::NonUtf8 => PathFault::NonUtf8 {
            path: path_text(path),
        },
    })
}

/// The same normalized text, shared rather than copied, for the paths a
/// snapshot names from several units at once.
pub(super) fn relative_shared(root: &Path, path: &Path) -> Result<Arc<str>, PathFault> {
    relative_text(root, path).map(Arc::from)
}
