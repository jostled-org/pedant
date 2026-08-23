//! Temporary Go module repositories shared by every Go project case.
//!
//! The tree materializer, the `repo/` prefix, and the out-of-root sibling it
//! leaves room for belong to [`crate::resolution::fixture`]; only the Go loader
//! entry points are stated here, so one fixture owner serves both languages.

use pedant_core::resolution::go::{
    GoProject, GoProjectError, GoProjectResolution, GoResolutionError, GoResolutionLimits,
    GoResolutionSnapshot, GoResolver, GoSnapshotError,
};

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

/// Materialize a Go fixture, load it, and snapshot it under `limits`.
///
/// The load must succeed: a snapshot case states what a walked project holds,
/// and the load refusals are the project cases' own subject.
pub fn snapshot(
    files: &[FixtureFile],
    limits: GoResolutionLimits,
) -> (
    tempfile::TempDir,
    Result<GoResolutionSnapshot, GoSnapshotError>,
) {
    let (tree, loaded) = load(files, limits);
    let project = loaded.unwrap_or_else(|error| panic!("the fixture should load: {error}"));
    let taken = project.snapshot_resolution();
    drop(project);
    (tree, taken)
}

/// Snapshot a Go fixture under the documented defaults and require success.
pub fn snapshot_default(files: &[FixtureFile]) -> (tempfile::TempDir, GoResolutionSnapshot) {
    let (tree, taken) = snapshot(files, GoResolutionLimits::default());
    let snapshot = taken.unwrap_or_else(|error| panic!("the fixture should snapshot: {error}"));
    (tree, snapshot)
}

/// Snapshot a Go fixture under `limits` and require a typed refusal.
pub fn snapshot_refusal(files: &[FixtureFile], limits: GoResolutionLimits) -> GoSnapshotError {
    let (tree, taken) = snapshot(files, limits);
    let error = match taken {
        Ok(snapshot) => panic!("the fixture should be refused, not snapshotted: {snapshot:?}"),
        Err(error) => error,
    };
    drop(tree);
    error
}

/// Materialize a Go fixture, snapshot it, and resolve the snapshot.
///
/// The snapshot must succeed: a resolver case states what a walked corpus
/// denotes, and the snapshot refusals are the snapshot cases' own subject. The
/// snapshot is returned beside the result, because a published resolution names
/// the snapshot's units and a case reads both.
pub fn resolve(
    files: &[FixtureFile],
    limits: GoResolutionLimits,
) -> (
    tempfile::TempDir,
    GoResolutionSnapshot,
    Result<GoProjectResolution, GoResolutionError>,
) {
    let (tree, taken) = snapshot(files, limits);
    let snapshot = taken.unwrap_or_else(|error| panic!("the fixture should snapshot: {error}"));
    let resolved = GoResolver::resolve_syntactic(&snapshot);
    (tree, snapshot, resolved)
}

/// Resolve a Go fixture under the documented defaults and require success.
pub fn resolve_default(
    files: &[FixtureFile],
) -> (tempfile::TempDir, GoResolutionSnapshot, GoProjectResolution) {
    let (tree, snapshot, resolved) = resolve(files, GoResolutionLimits::default());
    let resolution = resolved.unwrap_or_else(|error| panic!("the fixture should resolve: {error}"));
    (tree, snapshot, resolution)
}

/// What one corpus does under one lowered ceiling: the ceiling that refused it,
/// or the report it published.
///
/// One owner because every ceiling case asks it. The refusing ceiling is
/// restated from the error rather than assumed, so a check that refused at some
/// other reference does not read the same as one that refused at the row's own
/// excess.
pub fn ceiling_outcome(files: &[FixtureFile], limits: GoResolutionLimits) -> Box<str> {
    let (tree, snapshot, resolved) = resolve(files, limits);
    let stated = match resolved {
        Ok(_) => Box::from("published"),
        Err(GoResolutionError::CandidateLimitExceeded { limit })
        | Err(GoResolutionError::InterfaceComparisonLimitExceeded { limit }) => {
            format!("refused at ceiling {limit}").into_boxed_str()
        }
        Err(other) => format!("refused by {other}").into_boxed_str(),
    };
    drop(snapshot);
    drop(tree);
    stated
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
