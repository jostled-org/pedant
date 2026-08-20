//! Which directories and files one module's package walk admits.
//!
//! Go keeps four kinds of directory out of package discovery — dot-prefixed,
//! underscore-prefixed, `testdata`, and the vendored tree — and treats a
//! directory holding its own manifest as another module. All four are decided
//! here, before any source is opened, and every admitted path is canonicalized
//! and confined to the repository root first, so a link cannot widen what the
//! snapshot goes on to read.

use std::path::{Path, PathBuf};

use super::limits::GoResolutionLimits;
use super::paths;
use super::snapshot_error::GoSnapshotError;

/// The file name a module manifest always has, which marks a nested module.
const MANIFEST: &str = "go.mod";

/// The extension an admitted source has.
const SOURCE_EXTENSION: &str = ".go";

/// The directory names Go reserves from package discovery outright.
const RESERVED_DIRECTORIES: &[&str] = &["testdata", "vendor"];

/// One directory of one module that holds at least one Go source.
pub(super) struct GoPackageDirectory {
    /// The canonical directory itself.
    pub(super) canonical: PathBuf,
    /// The directory relative to its own module's directory, `/`-separated and
    /// empty for the module root.
    pub(super) within_module: Box<str>,
    /// Every admitted source in the directory, canonical and name-sorted.
    pub(super) sources: Box<[PathBuf]>,
}

/// How many directory entries one whole snapshot may still visit.
///
/// One budget spans every module, because the ceiling bounds the walk rather
/// than any one directory, and a per-module budget would admit a project that
/// spent the whole ceiling once per module.
pub(super) struct EntryBudget {
    limits: GoResolutionLimits,
    visited: u32,
}

impl EntryBudget {
    /// A budget that has visited nothing.
    pub(super) fn new(limits: GoResolutionLimits) -> Self {
        Self { limits, visited: 0 }
    }

    /// Admit `entries` more directory entries, or refuse before any of them is
    /// examined.
    fn spend(&mut self, entries: usize) -> Result<(), GoSnapshotError> {
        let requested = u32::try_from(entries).unwrap_or(u32::MAX);
        let visited = self.visited.saturating_add(requested);
        match visited > self.limits.max_directory_entries {
            true => Err(GoSnapshotError::DirectoryEntryLimitExceeded {
                limit: self.limits.max_directory_entries,
            }),
            false => {
                self.visited = visited;
                Ok(())
            }
        }
    }
}

/// Every package directory beneath one module, in walk order.
///
/// The module's own directory comes first, then each admitted subdirectory in
/// name order, so the sources a snapshot reads are read in one stated order
/// whatever order the filesystem enumerated them in.
pub(super) fn package_directories(
    root: &Path,
    module: &Path,
    budget: &mut EntryBudget,
) -> Result<Box<[GoPackageDirectory]>, GoSnapshotError> {
    let mut walk = PackageWalk {
        root,
        module,
        budget,
        found: Vec::new(),
    };
    walk.descend(module)?;
    Ok(walk.found.into_boxed_slice())
}

/// One module's walk: where it is rooted, what it has spent, and what it found.
struct PackageWalk<'a> {
    root: &'a Path,
    module: &'a Path,
    budget: &'a mut EntryBudget,
    found: Vec<GoPackageDirectory>,
}

impl PackageWalk<'_> {
    /// Admit one directory, then descend into the subdirectories it admits.
    fn descend(&mut self, directory: &Path) -> Result<(), GoSnapshotError> {
        let entries = self.listing(directory)?;
        let sources = admitted_sources(self.root, &entries)?;
        self.retain(directory, sources)?;
        for child in admitted_directories(self.root, &entries)?.iter() {
            self.descend(child)?;
        }
        Ok(())
    }

    /// Keep one directory that holds at least one admitted source.
    ///
    /// The one body that grows the found table, so the budget the listing
    /// charged dominates every directory a walk ever keeps.
    fn retain(&mut self, directory: &Path, sources: Box<[PathBuf]>) -> Result<(), GoSnapshotError> {
        let Some(sources) = (!sources.is_empty()).then_some(sources) else {
            return Ok(());
        };
        self.found.push(GoPackageDirectory {
            within_module: paths::relative_text(self.module, directory)?,
            canonical: directory.to_path_buf(),
            sources,
        });
        Ok(())
    }

    /// Every entry one directory holds, name-sorted and charged to the budget.
    fn listing(&mut self, directory: &Path) -> Result<Box<[PathBuf]>, GoSnapshotError> {
        let read = std::fs::read_dir(directory)
            .map_err(|source| directory_error(self.root, directory, source))?;
        let mut entries: Vec<PathBuf> = Vec::new();
        for entry in read {
            let held = entry.map_err(|source| directory_error(self.root, directory, source))?;
            entries.push(held.path());
        }
        self.budget.spend(entries.len())?;
        entries.sort();
        Ok(entries.into_boxed_slice())
    }
}

/// Every Go source one listing admits, canonical and confined.
fn admitted_sources(root: &Path, entries: &[PathBuf]) -> Result<Box<[PathBuf]>, GoSnapshotError> {
    let mut admitted = Vec::new();
    for entry in entries.iter().filter(|entry| is_source(entry)) {
        admitted.extend(paths::canonical_in_root(root, entry)?.filter(|path| path.is_file()));
    }
    Ok(admitted.into_boxed_slice())
}

/// Every subdirectory one listing admits, canonical and confined.
fn admitted_directories(
    root: &Path,
    entries: &[PathBuf],
) -> Result<Box<[PathBuf]>, GoSnapshotError> {
    let mut admitted = Vec::new();
    for entry in entries.iter().filter(|entry| is_walkable(entry)) {
        admitted.extend(
            paths::canonical_in_root(root, entry)?
                .filter(|path| path.is_dir() && !holds_manifest(path)),
        );
    }
    Ok(admitted.into_boxed_slice())
}

/// Whether one entry is a Go source by name.
fn is_source(entry: &Path) -> bool {
    entry_name(entry).ends_with(SOURCE_EXTENSION)
}

/// Whether one entry names a directory a package walk may enter.
///
/// The name alone answers this: dot-prefixed and underscore-prefixed
/// directories and the two reserved names are excluded whatever they hold, so
/// nothing inside them is ever listed.
fn is_walkable(entry: &Path) -> bool {
    let name = entry_name(entry);
    let reserved =
        name.starts_with('.') || name.starts_with('_') || RESERVED_DIRECTORIES.contains(&&*name);
    !reserved
}

/// Whether a directory declares its own module, which makes it another
/// module's tree rather than this one's package.
fn holds_manifest(directory: &Path) -> bool {
    directory.join(MANIFEST).is_file()
}

/// One entry's file name, lossily, which is what the name rules read.
fn entry_name(entry: &Path) -> Box<str> {
    entry
        .file_name()
        .map(|name| name.to_string_lossy().into_owned().into_boxed_str())
        .unwrap_or_default()
}

/// A directory listing failure, named repository-relative when it can be.
fn directory_error(root: &Path, directory: &Path, source: std::io::Error) -> GoSnapshotError {
    GoSnapshotError::DirectoryRead {
        path: paths::relative_text(root, directory).unwrap_or_else(|_| paths::path_text(directory)),
        source,
    }
}
