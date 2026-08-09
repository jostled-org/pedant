//! Temporary Cargo repositories shared by every resolution case.
//!
//! Each helper materializes files beneath a `TempDir` the caller owns, so the
//! whole fixture is released on drop for success, failure, and panic alike. The
//! project root is always the `repo/` prefix, which leaves room for an
//! out-of-root sibling a confinement case can point at.

use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::resolution::rust::{ResolutionLimits, RustProject, RustProjectError};

/// One fixture file: repository-relative path and exact contents.
pub type FixtureFile = (&'static str, &'static str);

/// Write one fixture file and prove it landed.
pub fn write_file(base: &Path, relative: &str, contents: &[u8]) {
    let path = base.join(relative);
    let parent = path.parent().expect("a fixture path has a parent");
    fs::create_dir_all(parent).unwrap();
    fs::write(&path, contents).unwrap();
    assert!(path.is_file(), "fixture file {relative} was not created");
}

/// Materialize a fixture, creating entries in the order given so a later run
/// can perturb filesystem enumeration order.
pub fn build_repository(files: &[FixtureFile], reversed: bool) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let mut ordered: Vec<&FixtureFile> = files.iter().collect();
    if reversed {
        ordered.reverse();
    }
    for (relative, contents) in ordered {
        write_file(tmp.path(), relative, contents.as_bytes());
    }
    tmp
}

/// The project root inside a materialized fixture.
pub fn repository_root(tmp: &tempfile::TempDir) -> PathBuf {
    tmp.path().join("repo")
}

/// Load the fixture's project under `limits`.
pub fn load_project(
    tmp: &tempfile::TempDir,
    limits: ResolutionLimits,
) -> Result<RustProject, RustProjectError> {
    RustProject::load(&repository_root(tmp), limits)
}

/// Load the fixture's project under the documented defaults.
pub fn load_default(tmp: &tempfile::TempDir) -> RustProject {
    load_project(tmp, ResolutionLimits::default()).unwrap()
}
