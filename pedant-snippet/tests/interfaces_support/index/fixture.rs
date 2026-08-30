//! Temporary repositories the index tests are built over.
//!
//! Every fixture writes its own tree and owns it through [`TempRoot`], so the
//! directory is removed when the fixture drops, on success, on failure, and on
//! panic alike. Nothing here reads the repository this test suite lives in.
//!
//! The rows themselves live in [`sources`](super::sources). This module is the
//! writer and the platform helpers it needs; that one is the catalog.

use std::fs;
use std::path::Path;

use super::root::TempRoot;

/// One temporary repository, removed when this value drops.
pub struct Repository {
    root: TempRoot,
}

impl Repository {
    /// An empty repository.
    pub fn empty() -> Self {
        Self {
            root: TempRoot::new(),
        }
    }

    /// A repository holding exactly the named files.
    pub fn of(files: &[(&str, &str)]) -> Self {
        let repository = Self::empty();
        for (path, contents) in files {
            repository.write(path, contents);
        }
        repository
    }

    /// The same files, written last one first.
    ///
    /// The order a tree was created in is the only handle a test has on the
    /// order a filesystem enumerates it, so every order-independence claim
    /// needs the same rows laid down both ways. Derived from one row list
    /// rather than hand-written beside it: two lists nothing compares are two
    /// repositories, and a row added to one of them turns the claim into a
    /// comparison of different corpora.
    pub fn of_reversed(files: &[(&str, &str)]) -> Self {
        let repository = Self::empty();
        for (path, contents) in files.iter().rev() {
            repository.write(path, contents);
        }
        repository
    }

    /// The same files, with one row rewritten or one row added.
    ///
    /// The shape every identity row is taken over: a checkout equal to a
    /// baseline in every row but one, so a claim that moves is a claim that
    /// holds the row that moved. Written through the same rows and the same
    /// writer as the baseline, because a perturbed checkout laid down by a
    /// second path is a second repository, and then a moved identity says
    /// nothing about the perturbation.
    pub fn perturbed(files: &[(&str, &str)], path: &str, contents: &str) -> Self {
        let repository = Self::of(files);
        repository.write(path, contents);
        repository
    }

    /// The canonical root, which is what the index is built over.
    pub fn root(&self) -> &Path {
        self.root.canonical()
    }

    /// Write one file, creating the directories above it.
    pub fn write(&self, path: &str, contents: &str) {
        self.write_bytes(path, contents.as_bytes());
    }

    /// Write one file's exact bytes, creating the directories above it.
    pub fn write_bytes(&self, path: &str, bytes: &[u8]) {
        let target = self.root.canonical().join(path);
        fs::write(parented(&target), bytes).expect("the fixture file is written");
    }

    /// Write one file whose name has no UTF-8 spelling, where the host has such
    /// names to offer.
    ///
    /// Returns the lossy rendering of what it created, and `None` on a
    /// filesystem that refuses the byte sequence outright — APFS and NTFS both
    /// do, and a repository that cannot hold the name cannot state the case.
    ///
    /// Only a refusal of the *name* answers `None`. The one caller reads that
    /// answer as "this host cannot spell such a name" and takes its skip
    /// branch, so a permission failure, a full disk, or a join that landed
    /// somewhere else would be reported there as a claim about the host and the
    /// case would pass having asserted nothing about `PathEncoding`. Every
    /// other failure is this fixture's own and panics.
    #[cfg(unix)]
    pub fn write_unspellable(&self, extension: &str) -> Option<String> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let mut name = b"unspellable\xff.".to_vec();
        name.extend_from_slice(extension.as_bytes());
        let target = self.root.canonical().join(OsStr::from_bytes(&name));
        match fs::write(&target, "def unspellable():\n    return 1\n") {
            Ok(()) => Some(target.to_string_lossy().into_owned()),
            Err(error) if refused_the_name(&error) => None,
            Err(error) => panic!(
                "this host spells names like {} and refused this one for reasons of its own, \
                 which is a broken fixture rather than a host with no such names: {error}",
                target.display()
            ),
        }
    }

    /// Write one file whose name has no UTF-8 spelling, where the host has such
    /// names to offer.
    #[cfg(not(unix))]
    pub fn write_unspellable(&self, _: &str) -> Option<String> {
        None
    }

    /// Remove this repository's whole tree while the fixture is still alive.
    ///
    /// For the one claim that cannot be made with the tree present: an index
    /// that answers after its repository is gone answered from what it
    /// retained. The `TempDir` still owns the directory and still tries to
    /// remove it on drop, which is a no-op once it is already gone.
    #[cfg(feature = "test-support")]
    pub fn remove(&self) {
        fs::remove_dir_all(self.root.canonical()).expect("the fixture tree is removed");
    }

    /// Link `path` at this root to `target`, which may sit outside it.
    ///
    /// Returns whether the host created the link. A platform that refuses
    /// symbolic links states that here rather than through a test that quietly
    /// asserts nothing.
    pub fn symlink(&self, path: &str, target: &Path) -> bool {
        let link = self.root.canonical().join(path);
        symlink_at(target, parented(&link))
    }
}

/// The target, with every directory above it created.
///
/// Returned rather than dropped so a caller writes `fs::write(parented(&t), …)`
/// and cannot state the path twice. Published because `Tree` stages and renames
/// into the same repository and owed the same directories.
pub fn parented(target: &Path) -> &Path {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).expect("the fixture directory is created");
    }
    target
}

/// The `EILSEQ` this host numbers.
///
/// Read as a number because rust maps `EILSEQ` to `ErrorKind::Uncategorized`,
/// which no stable `match` may name. The number is not the same on every Unix
/// and the wrong one names a different failure, so each is stated under its own
/// target rather than as one list every host is tested against. Linux admits
/// the byte in a filename at all, so its arm is here for completeness rather
/// than for a refusal anyone has seen.
#[cfg(all(unix, target_os = "linux"))]
const ILLEGAL_BYTE_SEQUENCE: i32 = 84;

/// The `EILSEQ` this host numbers, on the Darwin and BSD lineage.
#[cfg(all(unix, not(target_os = "linux")))]
const ILLEGAL_BYTE_SEQUENCE: i32 = 92;

/// Whether one write failure is the filesystem refusing the name's bytes.
///
/// The one answer [`Repository::write_unspellable`] may return as `None`, and
/// the one its caller reads as "this host has no such names to offer". APFS
/// states the refusal as `EILSEQ`, which carries no stable kind; a host that
/// does classify it states `InvalidFilename`, and one that classifies it as a
/// bad argument states `InvalidInput`.
///
/// Everything else — a permission failure, a full disk, a join that landed
/// outside the root — is this fixture's own fault. Folding those into `None`
/// let a case take its skip branch and pass having asserted nothing about the
/// refusal it exists to state. Darwin is the narrow exception: APFS reports
/// this invalid byte spelling as `EPERM`, after the same fixture has already
/// written ordinary names into the directory.
#[cfg(unix)]
fn refused_the_name(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        error.kind(),
        ErrorKind::InvalidInput | ErrorKind::InvalidFilename
    ) || error.raw_os_error() == Some(ILLEGAL_BYTE_SEQUENCE)
        || cfg!(target_os = "macos") && error.raw_os_error() == Some(1)
}

/// Create one symbolic link, on whichever platform this is.
#[cfg(unix)]
fn symlink_at(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

/// Create one symbolic link, on whichever platform this is.
#[cfg(windows)]
fn symlink_at(target: &Path, link: &Path) -> bool {
    match target.is_dir() {
        true => std::os::windows::fs::symlink_dir(target, link).is_ok(),
        false => std::os::windows::fs::symlink_file(target, link).is_ok(),
    }
}
