//! The Go module repository every provider case shares.
//!
//! Its own owner, for the reason the sibling Rust fixture is: the two languages
//! share no type, and a file holding both would be two fixtures a reader has to
//! separate before either is legible.

use pedant_core::resolution::go::{GoProject, GoResolutionLimits, GoSourceProvider};

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root};

/// A Go module whose one package holds two sources.
pub const GO_REPOSITORY: &[FixtureFile] = &[
    ("repo/go.mod", "module example.com/demo\n\ngo 1.21\n"),
    (
        "repo/app/service.go",
        "package app\n\ntype Service struct {\n\tName string\n}\n\nfunc New() *Service {\n\treturn &Service{Name: \"demo\"}\n}\n",
    ),
    (
        "repo/app/helper.go",
        "package app\n\nfunc Helper(service *Service) string {\n\treturn service.Name\n}\n",
    ),
];

/// The same module, with one source the grammar cannot read.
///
/// The package walk admits a directory's sources in sorted order, so the
/// complete source is named to sort first: the snapshot refuses on the second,
/// and the first has already become a record.
pub const PARTIALLY_MALFORMED_GO_REPOSITORY: &[FixtureFile] = &[
    ("repo/go.mod", "module example.com/demo\n\ngo 1.21\n"),
    (
        "repo/app/admitted.go",
        "package app\n\nfunc Admitted() int {\n\treturn 1\n}\n",
    ),
    ("repo/app/broken.go", "package app\n\nfunc Broken( {{{\n"),
];

/// A materialized Go repository and its loaded project.
pub struct GoFixture {
    pub tree: tempfile::TempDir,
    pub project: GoProject,
}

impl GoFixture {
    /// Materialize [`GO_REPOSITORY`] and load it under `limits`.
    pub fn of(files: &[FixtureFile], limits: GoResolutionLimits) -> Self {
        let tree = build_repository(files, false);
        let project = GoProject::load(&repository_root(&tree), limits)
            .unwrap_or_else(|error| panic!("the fixture should load: {error}"));
        Self { tree, project }
    }

    /// Reload the same tree under different ceilings, keeping the fixture.
    pub fn reloaded(&self, limits: GoResolutionLimits) -> GoProject {
        GoProject::load(&repository_root(&self.tree), limits)
            .unwrap_or_else(|error| panic!("the fixture should reload: {error}"))
    }

    /// A provider rooted at this fixture, under `limits`.
    ///
    /// The project's root is already canonical, so the constructor's own
    /// canonicalization restates it rather than changing it.
    pub fn provider(&self, limits: GoResolutionLimits) -> GoSourceProvider {
        GoSourceProvider::new(self.project.root(), limits)
            .unwrap_or_else(|error| panic!("the fixture root should anchor a provider: {error}"))
    }
}
