use std::path::{Path, PathBuf};

use pedant_core::resolution::rust::{ResolutionLimits, RustProject, RustProjectError};
use pedant_types::AnalysisTier;

use super::IndexError;

pub use pedant_core::lint::discover_workspace_root;

/// One workspace member: the directory to index and its package name.
pub(super) type WorkspaceMember = (PathBuf, Box<str>);

/// Every workspace member's directory and package name.
///
/// The shared Cargo project authority owns membership, so a root manifest that
/// is both a workspace and a package contributes its own crate here, and an
/// in-root path dependency that no member list names does not.
///
/// Member directories are re-based onto the caller's `workspace_root`. The
/// project loader canonicalizes its root, and cached file keys must keep the
/// spelling the caller indexed with.
pub(super) fn member_directories_with_names(
    workspace_root: &Path,
) -> Result<Box<[WorkspaceMember]>, IndexError> {
    let project = RustProject::load(workspace_root, ResolutionLimits::default())
        .map_err(map_project_error)?;
    Ok(project
        .workspace_members()
        .map(|package| {
            (
                package.directory_in(workspace_root),
                Box::from(package.name()),
            )
        })
        .collect())
}

fn map_project_error(source: RustProjectError) -> IndexError {
    IndexError::Project { source }
}

pub(super) fn crate_tier(has_flows: bool, semantic_available: bool) -> AnalysisTier {
    match (has_flows, semantic_available) {
        (true, _) => AnalysisTier::DataFlow,
        (false, true) => AnalysisTier::Semantic,
        (false, false) => AnalysisTier::Syntactic,
    }
}
