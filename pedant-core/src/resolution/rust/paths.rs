//! Canonical-root authority and repository-relative path normalization.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::RustProjectError;
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
pub(super) fn relative_text(root: &Path, path: &Path) -> Result<Arc<str>, RustProjectError> {
    let relative =
        crate::resolution::path_normalization::relative_text(root, path).map_err(|error| {
            match error {
                crate::resolution::path_normalization::RelativePathError::OutsideRoot => {
                    RustProjectError::OutOfRoot {
                        path: path_text(path),
                        root: path_text(root),
                    }
                }
                crate::resolution::path_normalization::RelativePathError::NonUtf8 => {
                    RustProjectError::NonUtf8Path {
                        path: path_text(path),
                    }
                }
            }
        })?;
    Ok(Arc::from(relative))
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
