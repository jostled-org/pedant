//! The written-down inventory of Go project production owners.
//!
//! The set is stated, never discovered: a discovered set agrees with whatever
//! the tree happens to contain, so it could not reject a module that appeared
//! beside the loader and read outside the root. The comparison below runs the
//! other way too — a file on disk that this list does not name fails the same
//! assertion.

use std::path::PathBuf;

use crate::declaration_scan::crate_path;

/// Every module of the Go resolution surface, relative to `src/resolution/go`.
pub const GO_MODULES: &[&str] = &[
    "directive.rs",
    "error.rs",
    "exclusion.rs",
    "identity.rs",
    "limits.rs",
    "load.rs",
    "manifest.rs",
    "mod.rs",
    "module.rs",
    "paths.rs",
    "project.rs",
    "replacement.rs",
    "requirement.rs",
];

/// The shared resolution owners the Go loader reaches, relative to
/// `src/resolution`.
///
/// They are language-neutral and compile in every configuration, so a claim
/// about what the Go loader may read has to include them: an escape or an
/// environment read hidden here would answer for Go too.
pub const SHARED_MODULES: &[&str] = &["identity.rs", "path_normalization.rs", "paths.rs"];

/// The complete source closure a Go project load runs through.
pub fn source_closure() -> Box<[PathBuf]> {
    let go = crate_path("src/resolution/go");
    let shared = crate_path("src/resolution");
    let mut paths: Vec<PathBuf> = GO_MODULES.iter().map(|name| go.join(name)).collect();
    paths.extend(SHARED_MODULES.iter().map(|name| shared.join(name)));
    for path in &paths {
        assert!(path.is_file(), "{} is modelled but absent", path.display());
    }
    assert_go_directory_is_exactly_modelled(&go);
    paths.into_boxed_slice()
}

/// Nothing sits beside the modelled Go owners.
fn assert_go_directory_is_exactly_modelled(directory: &std::path::Path) {
    let mut found: Vec<String> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| {
            entry
                .expect("a readable directory yields readable entries")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        GO_MODULES,
        "every file beneath {} must be a modelled owner",
        directory.display()
    );
}
