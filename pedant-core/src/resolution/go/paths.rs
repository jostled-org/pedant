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
use crate::resolution::confinement::{ConfinementFault, canonical_inside};
use crate::resolution::path_normalization::{RelativePathError, relative_text as lexical_text};
use crate::resolution::paths::RootError;

pub(super) use crate::resolution::paths::path_text;

/// The file name of a Go module manifest.
const MANIFEST: &str = "go.mod";

/// One confined manifest entry and whether it is a regular file.
pub(super) struct ConfinedManifest {
    canonical: PathBuf,
    regular: bool,
}

impl ConfinedManifest {
    /// The canonical manifest path.
    pub(super) fn path(&self) -> &Path {
        &self.canonical
    }

    /// Whether the entry can identify a nested module during discovery.
    pub(super) fn is_regular(&self) -> bool {
        self.regular
    }
}

/// Why one path answer could not be given.
///
/// Both stages refuse the same two ways, so the reason is stated once and each
/// stage's error type is built from it.
pub(super) enum PathFault {
    /// The path resolves outside the supplied repository root.
    OutOfRoot {
        /// Where the request landed, after every link was followed.
        path: Box<str>,
        /// The root that does not contain it.
        root: Box<str>,
        /// The path that was asked for, which is the one a caller can act on.
        ///
        /// A request that escaped through a link is spelled inside the root, so
        /// the landing alone reads as a contradiction and the request alone
        /// says nothing about where it went. Where the escape was measured
        /// lexically the two are one path, because that is the whole of what
        /// the measurement saw.
        request: Box<str>,
    },
    /// The path is not valid UTF-8, so it has no normalized text.
    NonUtf8 {
        /// The offending path, rendered lossily for the message only.
        path: Box<str>,
    },
    /// The path exists as far as the filesystem is concerned but could not be
    /// resolved: a denied permission, a symlink loop, an over-long name.
    Unreadable {
        /// The path that could not be resolved.
        path: Box<str>,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
}

/// A loader names the landing and the root it measured against. It states no
/// request, because a manifest walk asks for the directory it is standing in.
impl From<PathFault> for GoProjectError {
    fn from(fault: PathFault) -> Self {
        match fault {
            PathFault::OutOfRoot { path, root, .. } => Self::OutOfRoot { path, root },
            PathFault::NonUtf8 { path } => Self::NonUtf8Path { path },
            PathFault::Unreadable { path, source } => Self::PathRead { path, source },
        }
    }
}

impl From<PathFault> for GoSnapshotError {
    fn from(fault: PathFault) -> Self {
        match fault {
            PathFault::OutOfRoot {
                path,
                root,
                request,
            } => Self::OutOfRoot {
                path,
                root,
                request,
            },
            PathFault::NonUtf8 { path } => Self::NonUtf8Path { path },
            PathFault::Unreadable { path, source } => Self::PathRead { path, source },
        }
    }
}

/// Resolve the supplied root to its canonical directory form.
pub(super) fn canonical_root(root: &Path) -> Result<PathBuf, GoProjectError> {
    crate::resolution::paths::canonical_root(root).map_err(|error| GoProjectError::InvalidRoot {
        path: path_text(root),
        reason: RootError::reason(error),
    })
}

/// The canonical form of a path beneath `root`, or `None` when it does not
/// exist.
///
/// Only "no such file" is absence. Every other read failure — a denied
/// permission, a symlink loop, a dangling link, an over-long name — is
/// reported, so an admitted source cannot drop out of a package unseen and a
/// replacement directory nobody may read cannot be reported as one holding no
/// manifest.
///
/// A path that resolves outside the root is refused here rather than reported
/// as absent, so a symlink cannot widen what either stage goes on to read.
///
/// The rule itself belongs to [`canonical_inside`]; this states it in the Go
/// stages' own vocabulary, exactly as the Rust rules state it in theirs. A
/// second copy of the canonicalize-then-contain sequence would be a second
/// confinement rule, and the weaker one would be the one a symlink arrived
/// through.
pub(super) fn canonical_in_root(root: &Path, path: &Path) -> Result<Option<PathBuf>, PathFault> {
    canonical_inside(root, path).map_err(|fault| match fault {
        ConfinementFault::Unreadable(source) => PathFault::Unreadable {
            path: path_text(path),
            source,
        },
        ConfinementFault::OutOfRoot { canonical } => PathFault::OutOfRoot {
            path: path_text(&canonical),
            root: path_text(root),
            request: path_text(path),
        },
    })
}

/// Resolve one directory's module manifest beneath the repository root.
pub(super) fn confined_manifest(
    root: &Path,
    directory: &Path,
) -> Result<Option<ConfinedManifest>, PathFault> {
    let request = directory.join(MANIFEST);
    let Some(manifest) = canonical_in_root(root, &request)? else {
        return Ok(None);
    };
    let metadata = manifest
        .metadata()
        .map_err(|source| PathFault::Unreadable {
            path: path_text(&request),
            source,
        })?;
    Ok(Some(ConfinedManifest {
        canonical: manifest,
        regular: metadata.is_file(),
    }))
}

/// The last segment of a normalized repository-relative path.
///
/// The one place a `/`-separated path becomes the file name the build rules
/// read. Both readers of those rules — the predicate the store retains and the
/// test context the package assembler assigns — ask this, so neither can be
/// handed a whole path where a name is documented.
pub(super) fn file_name(relative: &str) -> &str {
    relative.rsplit('/').next().unwrap_or(relative)
}

/// Normalize a path inside the root to repository-relative `/`-separated text.
pub(super) fn relative_text(root: &Path, path: &Path) -> Result<Box<str>, PathFault> {
    lexical_text(root, path).map_err(|error| unrelative(error, root, path))
}

/// The same normalized text, shared rather than copied, for the paths a
/// snapshot names from several units at once.
pub(super) fn relative_shared(root: &Path, path: &Path) -> Result<Arc<str>, PathFault> {
    crate::resolution::path_normalization::relative_shared(root, path)
        .map_err(|error| unrelative(error, root, path))
}

/// Why one path has no repository-relative spelling, in the Go stages' words.
///
/// Published beside the two renderings above, because the shared snapshot store
/// renders its own keys into a buffer it owns and needs only this stage's name
/// for a render that refused.
pub(super) fn unrelative(error: RelativePathError, root: &Path, path: &Path) -> PathFault {
    match error {
        RelativePathError::OutsideRoot => PathFault::OutOfRoot {
            path: path_text(path),
            root: path_text(root),
            request: path_text(path),
        },
        RelativePathError::NonUtf8 => PathFault::NonUtf8 {
            path: path_text(path),
        },
    }
}
