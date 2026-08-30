//! Which directories and files one module's package walk admits.
//!
//! Go keeps four kinds of directory out of package discovery — dot-prefixed,
//! underscore-prefixed, `testdata`, and the vendored tree — and treats a
//! directory holding its own manifest as another module. All four are decided
//! here, before any source is opened.
//!
//! Only a link is resolved. The walk starts at a canonical directory and every
//! directory it queues is one, so an ordinary entry beneath one of them is
//! already named canonically and cannot leave the root; the one entry whose
//! target may sit anywhere is the one the listing reports as a link. The
//! confinement of an ordinary source belongs to the provider that opens it,
//! which is the seam that has to make that test anyway — resolving each source
//! here as well charged two canonicalization chains per file for one answer.
//!
//! The walk is a worklist rather than a recursion, and it remembers every
//! canonical directory it has entered. Confinement stops a link leaving the
//! root; it does not stop one pointing back inside it, which resolves to a
//! directory the walk may already hold. Without the memory that mints a second
//! package unit for one import path, and a link to an ancestor never
//! terminates. A heap worklist is the other half: depth is then bounded by the
//! entry budget rather than by the stack, so a deep tree earns a typed refusal
//! instead of taking the process down.

use std::borrow::Cow;
use std::collections::{BTreeSet, VecDeque};
use std::fs::FileType;
use std::path::{Path, PathBuf};

use crate::resolution::capacity::admits_one_more;
use crate::resolution::identity::index_of;

use super::limits::GoResolutionLimits;
use super::paths;
use super::snapshot_error::GoSnapshotError;

/// The extension an admitted source has.
const SOURCE_EXTENSION: &str = ".go";

/// The directory names Go reserves from package discovery outright.
const RESERVED_DIRECTORIES: &[&str] = &["testdata", "vendor"];

/// One listing's admitted sources and admitted subdirectories, in that order.
type AdmittedEntries = (Box<[PathBuf]>, Box<[PathBuf]>);

/// One directory entry as the listing reported it.
///
/// The type comes from the listing rather than from a second question to the
/// filesystem: it is what tells an ordinary file, which needs no resolution,
/// apart from a link, which is the only entry this walk resolves.
struct ListedEntry {
    path: PathBuf,
    file_type: FileType,
}

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

    /// Admit one more directory entry, or refuse before it is examined.
    ///
    /// Charged per entry rather than per listing: a directory holding ten
    /// million entries has to be refused at the ceiling, not after ten million
    /// paths were allocated in order to count them.
    fn spend(&mut self) -> Result<(), GoSnapshotError> {
        match admits_one_more(index_of(self.visited), self.limits.max_directory_entries) {
            false => Err(GoSnapshotError::DirectoryEntryLimitExceeded {
                limit: self.limits.max_directory_entries,
            }),
            true => {
                self.visited = self.visited.saturating_add(1);
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
        walked: BTreeSet::from([module.to_path_buf()]),
        pending: VecDeque::from([module.to_path_buf()]),
        found: Vec::new(),
    };
    while let Some(directory) = walk.pending.pop_front() {
        walk.descend(&directory)?;
    }
    Ok(walk.found.into_boxed_slice())
}

/// One module's walk: where it is rooted, what it has spent, where it has been,
/// what it has left to enter, and what it found.
struct PackageWalk<'a> {
    root: &'a Path,
    module: &'a Path,
    budget: &'a mut EntryBudget,
    walked: BTreeSet<PathBuf>,
    pending: VecDeque<PathBuf>,
    found: Vec<GoPackageDirectory>,
}

impl PackageWalk<'_> {
    /// Admit one directory, then queue the subdirectories it admits.
    fn descend(&mut self, directory: &Path) -> Result<(), GoSnapshotError> {
        let (sources, subdirectories) = self.listing(directory)?;
        self.retain(directory, sources)?;
        self.pending.extend(subdirectories.into_vec());
        Ok(())
    }

    /// Keep one directory that holds at least one admitted source.
    ///
    /// The one body that grows the found table, so the budget the listing
    /// charged dominates every directory a walk ever keeps.
    /// The push is written here rather than behind a second helper: this body is
    /// the one that grows the table, and the substrate reads it by that name.
    /// Splitting the non-empty arm out moved the growth to a body the ownership
    /// claim does not know about, which is the drift the claim exists to catch.
    fn retain(&mut self, directory: &Path, sources: Box<[PathBuf]>) -> Result<(), GoSnapshotError> {
        match sources.is_empty() {
            true => Ok(()),
            false => {
                self.found.push(GoPackageDirectory {
                    within_module: paths::relative_text(self.module, directory)?,
                    canonical: directory.to_path_buf(),
                    sources,
                });
                Ok(())
            }
        }
    }

    /// One directory's entries, name-sorted and charged one by one, split into
    /// the sources and the subdirectories it admits.
    ///
    /// The type each entry states is taken from the listing that reported it,
    /// because the listing already knows and a second stat would ask again.
    fn listing(&mut self, directory: &Path) -> Result<AdmittedEntries, GoSnapshotError> {
        let read = std::fs::read_dir(directory)
            .map_err(|source| directory_error(self.root, directory, source))?;
        let mut entries: Vec<ListedEntry> = Vec::new();
        for entry in read {
            self.budget.spend()?;
            let held = entry.map_err(|source| directory_error(self.root, directory, source))?;
            let file_type = held
                .file_type()
                .map_err(|source| directory_error(self.root, directory, source))?;
            entries.push(ListedEntry {
                path: held.path(),
                file_type,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        self.admitted(&entries)
    }

    /// Every admitted entry of one listing, split by the type it states.
    ///
    /// One pass. An excluded name is never resolved and never listed, so a
    /// reserved tree and a `vendor` link leaving the root both cost nothing.
    fn admitted(&mut self, entries: &[ListedEntry]) -> Result<AdmittedEntries, GoSnapshotError> {
        let mut sources: Vec<PathBuf> = Vec::new();
        let mut subdirectories: Vec<PathBuf> = Vec::new();
        let named = entries
            .iter()
            .map(|entry| (entry, entry_name(&entry.path)))
            .filter(|(_, name)| !is_excluded_name(name));
        for (entry, name) in named {
            self.sort_entry(entry, &name, (&mut sources, &mut subdirectories))?;
        }
        Ok((
            sources.into_boxed_slice(),
            subdirectories.into_boxed_slice(),
        ))
    }

    /// File one listed entry under the list its type and name put it in.
    ///
    /// An ordinary file and an ordinary directory are named beneath a canonical
    /// directory, so each one already is its own canonical path and neither can
    /// leave the root. A link is the one entry whose target the name does not
    /// state, so it is the one entry resolved.
    fn sort_entry(
        &mut self,
        entry: &ListedEntry,
        name: &str,
        admitted: (&mut Vec<PathBuf>, &mut Vec<PathBuf>),
    ) -> Result<(), GoSnapshotError> {
        let (sources, subdirectories) = admitted;
        match (entry.file_type.is_dir(), entry.file_type.is_file()) {
            (true, _) => {
                subdirectories.extend(self.walkable(entry.path.clone())?);
                Ok(())
            }
            (false, true) => {
                sources.extend(is_source_name(name).then(|| entry.path.clone()));
                Ok(())
            }
            (false, false) => self.sort_link(entry, name, (sources, subdirectories)),
        }
    }

    /// File one entry the listing reported as neither a file nor a directory.
    ///
    /// A link, whose target may sit anywhere, so it is canonicalized and
    /// confined here: a link the root does not hold refuses the snapshot, and a
    /// link the filesystem states nothing for is the absence it is. A link that
    /// resolves inside the root is filed under the path it resolves to, so two
    /// links to one source name one admitted source.
    fn sort_link(
        &mut self,
        entry: &ListedEntry,
        name: &str,
        admitted: (&mut Vec<PathBuf>, &mut Vec<PathBuf>),
    ) -> Result<(), GoSnapshotError> {
        let (sources, subdirectories) = admitted;
        let Some(canonical) = paths::canonical_in_root(self.root, &entry.path)? else {
            return Ok(());
        };
        match (canonical.is_dir(), is_source_name(name)) {
            (true, _) => subdirectories.extend(self.walkable(canonical)?),
            (false, true) => sources.push(canonical),
            (false, false) => (),
        }
        Ok(())
    }

    /// One subdirectory this walk may still enter, recorded as entered.
    ///
    /// A directory that declares its own module belongs to that module's tree,
    /// and one this walk already entered yields nothing: a link inside the root
    /// resolves to a directory the walk may already hold.
    fn walkable(&mut self, canonical: PathBuf) -> Result<Option<PathBuf>, GoSnapshotError> {
        match holds_manifest(self.root, &canonical)? || self.walked.contains(&canonical) {
            true => Ok(None),
            false => {
                self.walked.insert(canonical.clone());
                Ok(Some(canonical))
            }
        }
    }
}

/// Whether one entry's name is a name the Go toolchain compiles.
fn is_source_name(name: &str) -> bool {
    name.ends_with(SOURCE_EXTENSION)
}

/// Whether one entry's name keeps it out of every Go build.
///
/// The Go toolchain ignores a dot-prefixed and an underscore-prefixed name
/// wherever it appears, so an editor lock file, a source parked out of the
/// build, and a generated cgo intermediate are all outside the build a snapshot
/// describes. One rule for files and directories, because it is one rule.
fn is_ignored_name(name: &str) -> bool {
    name.starts_with('.') || name.starts_with('_')
}

/// Whether one entry is worth resolving at all, by its name alone.
///
/// The reserved directory names join the ignored prefixes before the entry is
/// resolved rather than after, so nothing inside a reserved tree is ever
/// listed and a `vendor` link leaving the root is excluded exactly as Go
/// excludes it instead of refusing the snapshot for escaping. No name Go
/// compiles is lost to the shared filter: a `.go` source cannot be called
/// `testdata` or `vendor`.
fn is_excluded_name(name: &str) -> bool {
    is_ignored_name(name) || RESERVED_DIRECTORIES.contains(&name)
}

/// Whether a directory declares its own module, which makes it another
/// module's tree rather than this one's package.
fn holds_manifest(root: &Path, directory: &Path) -> Result<bool, GoSnapshotError> {
    match paths::confined_manifest(root, directory)? {
        None => Ok(false),
        Some(manifest) if manifest.is_regular() => Ok(true),
        Some(manifest) => Err(GoSnapshotError::PathRead {
            path: paths::path_text(manifest.path()),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "go.mod is not a regular file",
            ),
        }),
    }
}

/// One entry's file name, lossily, which is what the name rules read.
///
/// Borrowed whenever the name is already UTF-8, which every name a Go build
/// compiles is; only a lossy rendering allocates.
fn entry_name(entry: &Path) -> Cow<'_, str> {
    entry
        .file_name()
        .map(std::ffi::OsStr::to_string_lossy)
        .unwrap_or(Cow::Borrowed(""))
}

/// A directory listing failure, named repository-relative when it can be.
fn directory_error(root: &Path, directory: &Path, source: std::io::Error) -> GoSnapshotError {
    GoSnapshotError::DirectoryRead {
        path: paths::relative_text(root, directory).unwrap_or_else(|_| paths::path_text(directory)),
        source,
    }
}
