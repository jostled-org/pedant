//! One `Cargo.toml` read from the project root, with the digest of its bytes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::RustProjectError;
use super::paths::{path_text, relative_text};
use super::toml_view;
use crate::observe::{self, Observation};

/// One participating manifest and the digest its bytes had at load time.
///
/// A snapshot re-reads these before it traverses any source, so a manifest
/// edited after the project was indexed cannot be resolved against.
#[derive(Debug)]
pub(super) struct ManifestFingerprint {
    pub(super) relative: Arc<str>,
    pub(super) digest: [u8; 32],
}

/// A parsed manifest, its normalized identity, and the digest of its exact bytes.
pub(super) struct ManifestDocument {
    path: PathBuf,
    directory: PathBuf,
    relative: Arc<str>,
    digest: [u8; 32],
    table: toml::Table,
}

impl ManifestDocument {
    /// Read and parse one manifest that lies inside `root`.
    ///
    /// Normalization comes first: it is pure path arithmetic, it refuses a path
    /// the root does not contain before the read rather than after it, and it
    /// gives the observation the same repository-relative shape the revision
    /// re-check and the source readers record. The observation follows the
    /// read, so one event means one manifest that was read to its end.
    pub(super) fn read(root: &Path, path: &Path) -> Result<Self, RustProjectError> {
        let relative = relative_text(root, path)?;
        let text =
            std::fs::read_to_string(path).map_err(|source| RustProjectError::ManifestRead {
                path: path_text(path),
                source,
            })?;
        observe::record(Observation::ManifestRead(&relative));
        let table =
            text.parse::<toml::Table>()
                .map_err(|error| RustProjectError::ManifestParse {
                    path: path_text(path),
                    message: error.to_string().into_boxed_str(),
                })?;
        Ok(Self {
            path: path.to_path_buf(),
            directory: parent_directory(path),
            relative,
            digest: crate::hash::digest_bytes(text.as_bytes()),
            table,
        })
    }

    /// The exact path this manifest was read from.
    ///
    /// Every caller supplies the canonical path, so this is the one key under
    /// which a dependency edge can find the package a manifest declares. A
    /// reconstructed `<directory>/Cargo.toml` is not that key: a symlinked
    /// manifest canonicalizes to a different file name.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// The directory holding this manifest.
    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }

    /// The repository-relative, `/`-separated manifest path.
    pub(super) fn relative(&self) -> &Arc<str> {
        &self.relative
    }

    /// SHA-256 of the manifest's exact bytes.
    pub(super) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The whole manifest table.
    pub(super) fn table(&self) -> &toml::Table {
        &self.table
    }

    /// The `[package]` table, when this manifest declares one.
    pub(super) fn package(&self) -> Option<&toml::Table> {
        toml_view::table(&self.table, "package")
    }

    /// The `[workspace]` table, when this manifest declares one.
    pub(super) fn workspace(&self) -> Option<&toml::Table> {
        toml_view::table(&self.table, "workspace")
    }

    /// This manifest's identity and digest, retained for snapshot freshness.
    pub(super) fn fingerprint(&self) -> ManifestFingerprint {
        ManifestFingerprint {
            relative: Arc::clone(&self.relative),
            digest: self.digest,
        }
    }
}

fn parent_directory(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_default()
}
