//! The repository a live case changes, and every way it changes it.
//!
//! Separate from [`Live`](super::harness::Live) because they answer different
//! questions: this one is what the tree holds, that one is what the index says
//! about it. A case reads like the two things it is doing — change the
//! repository, then ask the index — rather than like one owner that does both.

use std::fs;
use std::path::{Path, PathBuf};

use crate::index::fixture::{Repository, parented};
use crate::index::root::TempRoot;

/// One temporary repository, and the staging root new files arrive through.
pub struct Tree {
    staging: TempRoot,
    repository: Repository,
}

impl Tree {
    /// A tree holding exactly the named files.
    pub fn of(files: &[(&str, &str)]) -> Self {
        Self::over(Repository::of(files))
    }

    /// A tree over a repository a case wrote itself.
    pub fn over(repository: Repository) -> Self {
        Self {
            staging: TempRoot::new(),
            repository,
        }
    }

    /// The canonical root an index is built over.
    pub fn root(&self) -> &Path {
        self.repository.root()
    }

    /// Where one repository-relative path sits on this host.
    pub fn at(&self, path: &str) -> PathBuf {
        self.repository.root().join(path)
    }

    /// Write one file, creating the directories above it.
    pub fn write(&self, path: &str, contents: &str) {
        self.repository.write(path, contents);
    }

    /// Write one file whose bytes are not valid UTF-8.
    pub fn write_bytes(&self, path: &str, bytes: &[u8]) {
        self.repository.write_bytes(path, bytes);
    }

    /// Create one file by renaming complete bytes into place.
    ///
    /// A file created empty and filled afterwards is not observable on every
    /// host: a backend that learns of a new file from its parent directory
    /// registers the file's own watch after the scan that reported it, so a
    /// fill landing in that window raises no event at all. A rename carries the
    /// final bytes in, so the one create event a watcher sees is complete.
    pub fn place(&self, path: &str, contents: &str) {
        let staged = self.staging.canonical().join("staged");
        fs::write(&staged, contents).expect("the staged source is written");
        let target = self.at(path);
        fs::rename(&staged, parented(&target)).expect("the staged source is placed");
    }

    /// Remove one file.
    pub fn remove(&self, path: &str) {
        fs::remove_file(self.at(path)).expect("the fixture file is removed");
    }

    /// Rename one file inside the repository.
    pub fn rename(&self, from: &str, to: &str) {
        let target = self.at(to);
        fs::rename(self.at(from), parented(&target)).expect("the fixture file is renamed");
    }
}
