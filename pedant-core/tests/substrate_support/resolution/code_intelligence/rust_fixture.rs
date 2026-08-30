//! The Cargo repositories every provider case shares.
//!
//! One owner, because each provider claim is about the same question — what
//! happens when two project slices reach one physical source — and a second
//! tree would let two cases disagree about which sources are shared.

use pedant_core::resolution::rust::{
    CargoTargetKind, ResolutionLimits, RustProject, RustSourceProvider, TargetId,
};

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root};

/// A Cargo package whose library and binary targets both reach one module.
///
/// The binary declares the shared module through an explicit `#[path]`, so the
/// two target closures are separate walks over the same physical file: exactly
/// the shape a repository index produces when several project slices admit one
/// source.
pub const SHARED_SOURCE_REPOSITORY: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub mod shared;\n\npub struct Root;\n"),
    (
        "repo/src/shared.rs",
        "pub struct Widget {\n    pub id: u32,\n}\n\npub fn make() -> Widget {\n    Widget { id: 0 }\n}\n",
    ),
    (
        "repo/src/main.rs",
        "#[path = \"shared.rs\"]\nmod shared;\n\nfn main() {\n    let _ = shared::make();\n}\n",
    ),
];

/// The same package, with one module the parser cannot read.
///
/// The library reaches a complete module and a malformed one, so the snapshot
/// refuses while every source that did complete has already become a record.
pub const PARTIALLY_MALFORMED_REPOSITORY: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub mod good;\npub mod bad;\n"),
    ("repo/src/good.rs", "pub fn good() -> u32 {\n    1\n}\n"),
    ("repo/src/bad.rs", "pub fn bad( -> {{{\n"),
];

/// A materialized repository, its loaded Cargo project, and the two targets the
/// shared-source cases snapshot.
pub struct RustFixture {
    pub tree: tempfile::TempDir,
    pub project: RustProject,
    pub library: TargetId,
    binary: Option<TargetId>,
}

impl RustFixture {
    /// Materialize [`SHARED_SOURCE_REPOSITORY`] and load it under `limits`.
    pub fn shared(limits: ResolutionLimits) -> Self {
        Self::of(SHARED_SOURCE_REPOSITORY, limits)
    }

    /// Materialize one fixture and load its project under `limits`.
    pub fn of(files: &[FixtureFile], limits: ResolutionLimits) -> Self {
        let tree = build_repository(files, false);
        let project = RustProject::load(&repository_root(&tree), limits)
            .unwrap_or_else(|error| panic!("the fixture should load: {error}"));
        let library = library_of(&project);
        let binary = single_target(&project, CargoTargetKind::Binary);
        Self {
            tree,
            project,
            library,
            binary,
        }
    }

    /// The one binary target this fixture declares.
    pub fn binary(&self) -> TargetId {
        self.binary.expect("this fixture declares a binary target")
    }

    /// Reload the same tree under different ceilings, keeping the fixture.
    pub fn reloaded(&self, limits: ResolutionLimits) -> RustProject {
        RustProject::load(&repository_root(&self.tree), limits)
            .unwrap_or_else(|error| panic!("the fixture should reload: {error}"))
    }

    /// A provider rooted at this fixture, under `limits`.
    ///
    /// The project's root is already canonical, so the constructor's own
    /// canonicalization restates it rather than changing it.
    pub fn provider(&self, limits: ResolutionLimits) -> RustSourceProvider {
        RustSourceProvider::new(self.project.root(), limits)
            .unwrap_or_else(|error| panic!("the fixture root should anchor a provider: {error}"))
    }
}

/// The one library target a fixture project declares.
///
/// Stated once and read from both the fixture and the reloaded projects a
/// ceiling case builds, so no case selects a target its own way.
pub fn library_of(project: &RustProject) -> TargetId {
    single_target(project, CargoTargetKind::Library)
        .expect("a fixture project declares a library target")
}

/// The one target of `kind` a project declares, when it declares one.
fn single_target(project: &RustProject, kind: CargoTargetKind) -> Option<TargetId> {
    let selected: Box<[TargetId]> = project
        .targets()
        .iter()
        .filter(|target| target.kind() == kind)
        .map(|target| target.id())
        .collect();
    match &*selected {
        [] => None,
        [only] => Some(*only),
        found => panic!("a fixture declares at most one {kind:?} target, found {found:?}"),
    }
}
