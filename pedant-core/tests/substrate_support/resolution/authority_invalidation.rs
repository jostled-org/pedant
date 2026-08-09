//! Fixture construction for identities invalidated by manifest mutation.

use pedant_core::resolution::rust::{RustProject, TargetId};

use crate::resolution::closure_fixtures::MINIMAL_PACKAGE;
use crate::resolution::fixture;
use crate::resolution::views::app_library;

/// A fixture whose manifest changed after its identities were issued: the
/// temporary root, the project indexed before the change, and its library.
pub type Invalidated = (tempfile::TempDir, RustProject, TargetId);

/// Load a fixture, take its library identity, then rewrite the manifest so the
/// identity no longer describes the repository on disk.
pub fn invalidated(version: &str) -> Invalidated {
    let root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let project = fixture::load_default(&root);
    let target = app_library(&project);
    let manifest =
        format!("[package]\nname = \"app\"\nversion = \"{version}\"\nedition = \"2021\"\n");
    fixture::write_file(root.path(), "repo/Cargo.toml", manifest.as_bytes());
    (root, project, target)
}
