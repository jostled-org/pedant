//! Temporary Go module repositories shared by every Go project case.
//!
//! The tree materializer, the `repo/` prefix, and the out-of-root sibling it
//! leaves room for belong to [`crate::resolution::fixture`]; only the Go loader
//! entry points are stated here, so one fixture owner serves both languages.

use pedant_core::resolution::go::{GoProject, GoProjectError, GoResolutionLimits};

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root};

/// Materialize a Go fixture and load it under `limits`.
///
/// The `TempDir` is returned beside the result so the caller drops both at one
/// point, on success, failure, and panic alike.
pub fn load(
    files: &[FixtureFile],
    limits: GoResolutionLimits,
) -> (tempfile::TempDir, Result<GoProject, GoProjectError>) {
    let tree = build_repository(files, false);
    let loaded = GoProject::load(&repository_root(&tree), limits);
    (tree, loaded)
}

/// Load a Go fixture under the documented defaults and require it to succeed.
pub fn load_default(files: &[FixtureFile]) -> (tempfile::TempDir, GoProject) {
    let (tree, loaded) = load(files, GoResolutionLimits::default());
    let project = loaded.unwrap_or_else(|error| panic!("the fixture should load: {error}"));
    (tree, project)
}

/// Load a Go fixture and require a typed refusal.
pub fn refusal(files: &[FixtureFile]) -> GoProjectError {
    let (tree, loaded) = load(files, GoResolutionLimits::default());
    let error = match loaded {
        Ok(project) => panic!("the fixture should be refused, not loaded: {project:?}"),
        Err(error) => error,
    };
    drop(tree);
    error
}
