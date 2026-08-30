//! Canonical-root authority and repository-relative path normalization.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::RustProjectError;
use crate::resolution::path_normalization::RelativePathError;
use crate::resolution::paths::RootError;

pub(super) use crate::resolution::paths::path_text;

/// Resolve the supplied root to its canonical directory form.
pub(super) fn canonical_root(root: &Path) -> Result<PathBuf, RustProjectError> {
    crate::resolution::paths::canonical_root(root).map_err(|error| RustProjectError::InvalidRoot {
        path: path_text(root),
        reason: RootError::reason(error),
    })
}

/// Normalize a path inside the root to repository-relative `/`-separated text.
///
/// Owned rather than shared, for the seams that render one path, read it once,
/// and drop it: a failure payload naming the source that escaped. A caller that
/// hands the same path to several holders asks [`relative_shared`] instead,
/// rather than copying the text again on the way into an `Arc`.
pub(super) fn relative_text(root: &Path, path: &Path) -> Result<Box<str>, RustProjectError> {
    crate::resolution::path_normalization::relative_text(root, path)
        .map_err(|error| unrelative(error, root, path))
}

/// The same normalized text, shared rather than copied, for the paths a
/// manifest identity and a target entry are both named by.
pub(super) fn relative_shared(root: &Path, path: &Path) -> Result<Arc<str>, RustProjectError> {
    crate::resolution::path_normalization::relative_shared(root, path)
        .map_err(|error| unrelative(error, root, path))
}

/// Why one path has no repository-relative spelling, in this loader's words.
///
/// Published beside the two renderings above, because the shared snapshot store
/// renders its own keys into a buffer it owns and needs only this loader's name
/// for a render that refused.
pub(super) fn unrelative(error: RelativePathError, root: &Path, path: &Path) -> RustProjectError {
    match error {
        RelativePathError::OutsideRoot => RustProjectError::OutOfRoot {
            path: path_text(path),
            root: path_text(root),
        },
        RelativePathError::NonUtf8 => RustProjectError::NonUtf8Path {
            path: path_text(path),
        },
    }
}

/// Whether `path` is the root itself or lies beneath it.
pub(super) fn contains(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
}

/// Read one directory's entries, reporting the path that could not be listed.
pub(super) fn read_directory(path: &Path) -> Result<Box<[std::fs::DirEntry]>, RustProjectError> {
    let entries = std::fs::read_dir(path).map_err(|source| RustProjectError::ManifestRead {
        path: path_text(path),
        source,
    })?;
    entries
        .collect::<Result<Box<[_]>, _>>()
        .map_err(|source| RustProjectError::ManifestRead {
            path: path_text(path),
            source,
        })
}

/// Canonical form of a directory's manifest, or `None` when it has none.
///
/// A directory that holds no `Cargo.toml` is absence. Every other read failure —
/// a denied permission, a symlink loop, a dangling link — is reported, so a
/// declared member cannot drop out of a load unseen.
pub(super) fn canonical_manifest(directory: &Path) -> Result<Option<PathBuf>, RustProjectError> {
    let manifest = directory.join("Cargo.toml");
    match std::fs::canonicalize(&manifest) {
        Ok(canonical) => Ok(canonical.is_file().then_some(canonical)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(RustProjectError::ManifestRead {
            path: path_text(&manifest),
            source,
        }),
    }
}
