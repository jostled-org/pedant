//! Real temporary Cargo repositories, and the production path from one to a
//! snapshot-bound resolution.
//!
//! Every fixture owns a `TempDir` and nothing else: no process, no socket, no
//! semantic database, no global cache, and no persistent file. Ordinary cases
//! release it by RAII on success, failure, and panic alike; the isolation case
//! closes it deliberately before it projects.

use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::resolution::rust::{
    CargoTargetKind, ResolutionLimits, RustProject, RustResolutionSnapshot, RustResolver,
    RustTargetResolution, TargetId,
};
use pedant_graph::{CodeGraph, build_rust_graph};

use super::corpus::{BUILD_SCRIPT_CORPUS, GRAPH_CORPUS};

/// One declared target: its owning package, its Cargo kind, and its name.
pub type DeclaredTarget = (&'static str, CargoTargetKind, &'static str);

/// The corpus library root every general case reads.
pub const CORPUS_LIBRARY: DeclaredTarget = ("app", CargoTargetKind::Library, "app");

/// The build-script root, the one target kind whose namespace exposes a build
/// dependency.
const BUILD_SCRIPT_ROOT: DeclaredTarget =
    ("app", CargoTargetKind::BuildScript, "build-script-build");

/// One materialized repository and the project loaded from it.
pub struct Fixture {
    directory: tempfile::TempDir,
    project: RustProject,
}

/// One snapshot and the syntactic resolution validated against it.
pub struct Resolved {
    /// The completed snapshot.
    pub snapshot: RustResolutionSnapshot,
    /// The report bound to that snapshot.
    pub resolution: RustTargetResolution,
}

impl Fixture {
    /// Materialize `files` beneath a fresh temporary directory and load them.
    pub fn build(files: &[(&str, &str)]) -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory should be available");
        for (relative, contents) in files {
            write_file(directory.path(), relative, contents.as_bytes());
        }
        let root = directory.path().join("repo");
        let project = RustProject::load(&root, ResolutionLimits::default())
            .unwrap_or_else(|error| panic!("the fixture project should load: {error}"));
        Self { directory, project }
    }

    /// The repository root inside this fixture.
    pub fn root(&self) -> PathBuf {
        self.directory.path().join("repo")
    }

    /// The identity of one declared target.
    pub fn target(&self, package: &str, kind: CargoTargetKind, name: &str) -> TargetId {
        self.project
            .targets()
            .iter()
            .find(|target| {
                target.kind() == kind
                    && target.name() == name
                    && self
                        .project
                        .package(target.package())
                        .is_some_and(|owner| owner.name() == package)
            })
            .map(|target| target.id())
            .unwrap_or_else(|| panic!("{package} declares no {kind:?} target named {name}"))
    }

    /// The identity of the one library target a single-package fixture holds.
    pub fn sole_library(&self) -> TargetId {
        let libraries: Vec<TargetId> = self
            .project
            .targets()
            .iter()
            .filter(|target| target.kind() == CargoTargetKind::Library)
            .map(|target| target.id())
            .collect();
        match libraries.as_slice() {
            [only] => *only,
            found => panic!("the fixture declares {} library targets", found.len()),
        }
    }

    /// Snapshot and syntactically resolve one target.
    pub fn resolve(&self, target: TargetId) -> Resolved {
        let snapshot = self
            .project
            .snapshot_resolution(target)
            .unwrap_or_else(|error| panic!("the fixture target should snapshot: {error}"));
        let resolution = RustResolver::resolve_syntactic(&snapshot)
            .unwrap_or_else(|error| panic!("the fixture snapshot should resolve: {error}"));
        Resolved {
            snapshot,
            resolution,
        }
    }

    /// Snapshot and resolve the sole library target.
    pub fn resolve_library(&self) -> Resolved {
        self.resolve(self.sole_library())
    }

    /// Snapshot and resolve one declared target.
    ///
    /// A repository stating more than one library names the one it means, so a
    /// corpus that gains a dependency package keeps the root it is read at.
    pub fn resolve_declared(&self, declared: DeclaredTarget) -> Resolved {
        let (package, kind, name) = declared;
        self.resolve(self.target(package, kind, name))
    }

    /// Rewrite one source in place and reload the project from the same root.
    ///
    /// The manifests, the root path, and every target identity are unchanged,
    /// so the reloaded project issues the same identities and only the snapshot
    /// this fixture produces next differs.
    pub fn rewrite(&mut self, relative: &str, contents: &str) {
        self.revise(&[(relative, contents)], &[]);
    }

    /// Write every stated file, remove every stated path, and reload once.
    ///
    /// One revision is one repository state: a rename is a written source, a
    /// removed source, and the declaration that names it, and reloading between
    /// those three would load a repository no case states.
    pub fn revise(&mut self, written: &[(&str, &str)], removed: &[&str]) {
        for (relative, contents) in written {
            write_file(self.directory.path(), relative, contents.as_bytes());
        }
        for relative in removed {
            let path = self.directory.path().join(relative);
            fs::remove_file(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        }
        self.project = RustProject::load(&self.root(), ResolutionLimits::default())
            .unwrap_or_else(|error| panic!("the revised fixture project should load: {error}"));
    }

    /// Release the repository, returning its root so a caller can prove the
    /// directory is gone before it uses what the fixture produced.
    pub fn close(self) -> PathBuf {
        let root = self.root();
        drop(self.project);
        self.directory
            .close()
            .expect("the fixture directory should close");
        root
    }
}

/// Materialize and resolve one corpus in one step.
pub fn resolve_library(files: &[(&str, &str)]) -> (Fixture, Resolved) {
    let fixture = Fixture::build(files);
    let resolved = fixture.resolve_library();
    (fixture, resolved)
}

/// Materialize one corpus and resolve one target it declares.
///
/// The fixture travels with the resolution so the repository outlives every
/// case that reads it, exactly as [`resolve_library`] does.
pub fn resolve_target(files: &[(&str, &str)], declared: DeclaredTarget) -> (Fixture, Resolved) {
    let fixture = Fixture::build(files);
    let resolved = fixture.resolve_declared(declared);
    (fixture, resolved)
}

/// Materialize one corpus, resolve one declared target, and project it.
pub fn project_target(
    files: &[(&str, &str)],
    declared: DeclaredTarget,
) -> (Fixture, Resolved, CodeGraph) {
    let (fixture, resolved) = resolve_target(files, declared);
    let graph = project(&resolved, &format!("{declared:?}"));
    (fixture, resolved, graph)
}

/// The graph one resolution projects, named by the target that produced it.
fn project(resolved: &Resolved, subject: &str) -> CodeGraph {
    build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .unwrap_or_else(|error| panic!("{subject} should project: {error}"))
}

/// The corpus library, resolved but not projected.
pub fn resolve_corpus_library() -> (Fixture, Resolved) {
    resolve_target(GRAPH_CORPUS, CORPUS_LIBRARY)
}

/// The corpus library, resolved and projected.
pub fn project_corpus_library() -> (Fixture, Resolved, CodeGraph) {
    project_target(GRAPH_CORPUS, CORPUS_LIBRARY)
}

/// The build-script root, resolved and projected.
pub fn project_build_script() -> (Fixture, Resolved, CodeGraph) {
    project_target(BUILD_SCRIPT_CORPUS, BUILD_SCRIPT_ROOT)
}

fn write_file(base: &Path, relative: &str, contents: &[u8]) {
    let path = base.join(relative);
    let parent = path.parent().expect("a fixture path has a parent");
    fs::create_dir_all(parent).unwrap_or_else(|error| panic!("{}: {error}", parent.display()));
    fs::write(&path, contents).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}
