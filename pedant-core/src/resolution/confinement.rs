//! Whether one path is a confined location beneath a repository root.
//!
//! One owner, because a confinement rule that existed twice could hold for the
//! seam that asked and not for the seam that read. Every seam in either language
//! takes its answer from here and maps it into the typed error its own boundary
//! publishes: the Rust store that resolves a module candidate, the Rust provider
//! that opens a source, and the Go loader, discovery walk, and provider through
//! their own `PathFault`.
//!
//! Three answers, not two. A path the root does not hold is absence, which the
//! Go tree reports as absence and the Rust tree folds back into the not-found
//! read it is. That fold lives here as [`canonical_present`], so the two Rust
//! seams cannot disagree about what a missing candidate is called.

use std::path::{Path, PathBuf};

/// Why one path is not a confined location beneath a repository root.
///
/// Two answers, because a caller has to tell them apart: a path the filesystem
/// refused to resolve says nothing about where it is, while a path that
/// resolved and landed outside says exactly where it is and that the root does
/// not hold it.
pub(crate) enum ConfinementFault {
    /// The path could not be resolved at all.
    Unreadable(std::io::Error),
    /// The path resolves outside the root, in the canonical form it resolved to.
    OutOfRoot {
        /// Where the path actually landed, after every link was followed.
        canonical: PathBuf,
    },
}

/// The canonical form of `path`, absent when the root holds nothing there, and
/// refused when it resolves outside `root`.
///
/// Symlinks are followed before the decision, so a link inside the root that
/// points outside it is refused rather than read. One owner, because a
/// confinement rule that existed twice could hold for the seam that asked and
/// not for the seam that read.
///
/// Only "no such file" is absence. Every other read failure — a denied
/// permission, a symlink loop, a dangling link, an over-long name — is reported,
/// so a source nobody may read cannot be reported as one the repository never
/// held. A path that resolves outside the root is refused here rather than
/// reported as absent, so a symlink cannot widen what a caller goes on to read.
pub(crate) fn canonical_inside(
    root: &Path,
    path: &Path,
) -> Result<Option<PathBuf>, ConfinementFault> {
    let canonical = match std::fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ConfinementFault::Unreadable(source)),
    };
    match canonical.starts_with(root) {
        true => Ok(Some(canonical)),
        false => Err(ConfinementFault::OutOfRoot { canonical }),
    }
}

/// The same answer for a seam that states no absence.
///
/// Both Rust seams name a path they expect the root to hold, so nothing there is
/// the not-found read it is rather than a third outcome they would each have to
/// invent a spelling for.
pub(crate) fn canonical_present(root: &Path, path: &Path) -> Result<PathBuf, ConfinementFault> {
    canonical_inside(root, path)?.ok_or_else(|| {
        ConfinementFault::Unreadable(std::io::Error::from(std::io::ErrorKind::NotFound))
    })
}
