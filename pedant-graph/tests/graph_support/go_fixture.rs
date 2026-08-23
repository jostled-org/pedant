//! Real temporary Go repositories, and the production path from one to a
//! snapshot-bound resolution.
//!
//! Every fixture owns a `TempDir` and nothing else: no process, no toolchain,
//! no module cache, and no persistent file. A case releases it by RAII on
//! success, failure, and panic alike, and a case whose assertions need no files
//! closes it deliberately before it reads what the projection produced.

use std::path::PathBuf;

use pedant_core::resolution::go::{
    GoProject, GoProjectResolution, GoResolutionLimits, GoResolutionSnapshot, GoResolver,
};
use pedant_graph::{CodeGraph, GraphBuildError, GraphLimits, build_go_graph};

use super::corpus::FixtureFile;
use super::fixture::TempRepository;

/// One materialized Go repository.
pub struct GoFixture {
    repository: TempRepository,
}

/// One snapshot and the syntactic resolution validated against it.
pub struct GoResolved {
    /// The completed snapshot.
    pub snapshot: GoResolutionSnapshot,
    /// The report bound to that snapshot.
    pub resolution: GoProjectResolution,
}

impl GoFixture {
    /// Materialize `files` beneath a fresh temporary directory.
    pub fn build(files: &[FixtureFile]) -> Self {
        Self::written(files.iter().copied())
    }

    /// Materialize the same files in the order a caller states them.
    pub fn written<'a>(files: impl Iterator<Item = (&'a str, &'a str)>) -> Self {
        Self {
            repository: TempRepository::written(files),
        }
    }

    /// The repository root inside this fixture.
    pub fn root(&self) -> PathBuf {
        self.repository.root()
    }

    /// Load, snapshot, and syntactically resolve under the default ceilings.
    pub fn resolve(&self) -> GoResolved {
        self.resolve_with(GoResolutionLimits::default())
    }

    /// Load, snapshot, and syntactically resolve under stated ceilings.
    pub fn resolve_with(&self, limits: GoResolutionLimits) -> GoResolved {
        let project = GoProject::load(&self.root(), limits)
            .unwrap_or_else(|error| panic!("the fixture project should load: {error}"));
        let snapshot = project
            .snapshot_resolution()
            .unwrap_or_else(|error| panic!("the fixture project should snapshot: {error}"));
        let resolution = GoResolver::resolve_syntactic(&snapshot)
            .unwrap_or_else(|error| panic!("the fixture snapshot should resolve: {error}"));
        GoResolved {
            snapshot,
            resolution,
        }
    }

    /// Rewrite one source in place, leaving every manifest alone.
    pub fn rewrite(&self, relative: &str, contents: &str) {
        self.repository.write(relative, contents);
    }

    /// Release the repository, proving it is gone and answering with its root.
    pub fn close(self) -> PathBuf {
        self.repository.close()
    }
}

/// Materialize and resolve one corpus in one step.
pub fn resolve_go(files: &[FixtureFile]) -> (GoFixture, GoResolved) {
    let fixture = GoFixture::build(files);
    let resolved = fixture.resolve();
    (fixture, resolved)
}

/// Release one fixture before the assertions that need no files.
///
/// Named for the point of the call rather than for its one statement: a
/// projection, a query, or a serializer that reached the loader, the parser, or
/// the filesystem must fail here rather than pass against files that happen to
/// still exist. The proof that the directory is gone belongs to the release
/// itself, so it is stated once, wherever a repository is closed.
pub fn close_repository(fixture: GoFixture) {
    fixture.close();
}

/// Materialize one corpus, resolve it, project it, and release the repository.
///
/// Every graph case reads a value the snapshot and the report already hold, so
/// the files are released here and the whole case runs against memory alone.
pub fn project_go(files: &[FixtureFile]) -> (GoResolved, CodeGraph) {
    let (fixture, resolved) = resolve_go(files);
    let graph = projected(&resolved);
    close_repository(fixture);
    (resolved, graph)
}

/// The graph one resolved Go repository projects.
pub fn projected(resolved: &GoResolved) -> CodeGraph {
    build_go_graph(&resolved.snapshot, &resolved.resolution)
        .unwrap_or_else(|error| panic!("the Go fixture should project: {error}"))
}

/// The refusal one bounded Go build takes, or the graph it should not have
/// produced.
pub fn refused(resolved: &GoResolved, limits: GraphLimits) -> GraphBuildError {
    match pedant_graph::build_go_graph_with_limits(&resolved.snapshot, &resolved.resolution, limits)
    {
        Err(error) => error,
        Ok(graph) => panic!(
            "the bounded build should refuse, and returned {} nodes",
            graph.nodes().len()
        ),
    }
}
