//! One temporary directory, owned by whoever holds it.
//!
//! Every index test owns its own tree: the `TempDir` is a field, so the
//! directory is removed when the owner drops, on success, on failure, and on
//! panic alike. Nothing here reads the repository this test suite lives in.
//!
//! It sits apart from [`fixture`](super::fixture) because the profile predicate
//! runs in every feature configuration and needs a root and nothing else, while
//! the mixed six-language repository is only answerable by the complete
//! selection. One owner of the temporary directory, two callers.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tempfile::TempDir;

/// One temporary root, removed when this value drops.
pub struct TempRoot {
    directory: TempDir,
    canonical: OnceLock<PathBuf>,
}

impl TempRoot {
    /// An empty temporary root.
    pub fn new() -> Self {
        Self {
            directory: TempDir::new().expect("a temporary repository root"),
            canonical: OnceLock::new(),
        }
    }

    /// The canonical root: what an index is built over, and where every file
    /// beneath it is written.
    ///
    /// Canonical rather than as `TempDir` spelled it: macOS hands out
    /// `/var/...`, which is a symlink to `/private/var/...`, and an index that
    /// canonicalizes its root would then report every path as outside it. One
    /// spelling for writing and for indexing, so a test cannot hold two.
    ///
    /// Resolved once and lent afterwards. The path is fixed when the directory
    /// is created, and every write beneath this root asked for it again: an
    /// eighteen-file fixture paid eighteen `canonicalize` syscalls for one
    /// answer, and this tree builds about twenty such fixtures. Holding the
    /// answer also means [`Repository::remove`](super::fixture::Repository::remove)
    /// no longer takes the root away with it — the one caller that removes its
    /// own tree resolved the path to remove it, so the rows that read the root
    /// afterwards still get the spelling it had.
    pub fn canonical(&self) -> &Path {
        self.canonical.get_or_init(|| {
            self.directory
                .path()
                .canonicalize()
                .expect("the temporary root canonicalizes")
        })
    }
}
