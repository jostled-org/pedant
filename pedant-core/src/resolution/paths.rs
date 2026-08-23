//! Path rendering and canonical-root resolution shared by resolution adapters.
//!
//! Both answers are language-neutral — a root is a canonical directory or it is
//! not one, and an error payload renders a path the same way whichever loader
//! rejected it — so each is stated once and mapped into the failing language's
//! own error by its caller.

use std::path::{Path, PathBuf};

/// Why a supplied root cannot anchor a project.
pub(crate) enum RootError {
    /// The path could not be canonicalized.
    Unreadable(std::io::Error),
    /// The canonical path is not a directory.
    NotADirectory,
}

impl RootError {
    /// How this refusal reads in the payload each loader publishes.
    ///
    /// Stated here rather than at each seam: the two loaders would otherwise
    /// each spell what an unreadable root and a non-directory root read like,
    /// and the pair could drift on either sentence.
    pub(crate) fn reason(self) -> Box<str> {
        match self {
            Self::Unreadable(source) => source.to_string().into_boxed_str(),
            Self::NotADirectory => Box::from("the project root is not a directory"),
        }
    }
}

/// Render a path for an error payload without borrowing it.
pub(crate) fn path_text(path: &Path) -> Box<str> {
    path.display().to_string().into_boxed_str()
}

/// Resolve the supplied root to its canonical directory form.
pub(crate) fn canonical_root(root: &Path) -> Result<PathBuf, RootError> {
    let canonical = std::fs::canonicalize(root).map_err(RootError::Unreadable)?;
    match canonical.is_dir() {
        true => Ok(canonical),
        false => Err(RootError::NotADirectory),
    }
}
