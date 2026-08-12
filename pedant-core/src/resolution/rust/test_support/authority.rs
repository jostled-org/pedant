//! Lexical path authority and defensively invalid target identities.

use std::path::Path;

use crate::resolution::path_normalization;
use crate::resolution::rust::identity::TargetId;
use crate::resolution::rust::project::RustProject;

/// Proof-facing form of a lexical relative-path normalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelativePathNormalizationError {
    /// The path does not begin with the root's lexical components.
    OutsideRoot,
    /// A relative component has no UTF-8 representation.
    NonUtf8,
}

/// Exercise the crate-private lexical path authority without widening the
/// ordinary resolution surface.
pub fn normalize_relative_path(
    root: &Path,
    path: &Path,
) -> Result<Box<str>, RelativePathNormalizationError> {
    path_normalization::relative_text(root, path).map_err(|error| match error {
        path_normalization::RelativePathError::OutsideRoot => {
            RelativePathNormalizationError::OutsideRoot
        }
        path_normalization::RelativePathError::NonUtf8 => RelativePathNormalizationError::NonUtf8,
    })
}

/// A defensively invalid target identity: this project's authority with a local
/// index past every target it issued.
///
/// `RustSnapshotError::UnknownTarget` guards an invariant the safe public API
/// cannot break, so proving both snapshot operations refuse it needs a
/// construction path that only the proof feature compiles.
pub fn unknown_target_id(project: &RustProject) -> TargetId {
    let index = u32::try_from(project.targets().len()).unwrap_or(u32::MAX);
    TargetId::new(project.authority, index)
}
