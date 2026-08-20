//! The written-down inventory of Go project production owners.
//!
//! The set is stated, never discovered: a discovered set agrees with whatever
//! the tree happens to contain, so it could not reject a module that appeared
//! beside the loader and read outside the root. The comparison below runs the
//! other way too — a file on disk that this list does not name fails the same
//! assertion.

use std::path::{Path, PathBuf};

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

/// The crate-level modules a Go load reaches outside the resolution tree,
/// relative to `src`.
///
/// `load.rs` mints its project authority through `crate::hash::digest_bytes`,
/// and both it and `manifest.rs` announce their reads through `crate::observe`.
/// Those calls run on every load, so a boundary claim that skipped them would
/// leave the newly wired modules unscanned: a process launch or an environment
/// read placed in the observation hook would answer for Go without changing a
/// single manifest count.
pub const REACHED_MODULES: &[&str] = &[
    "hash.rs",
    "observe/event.rs",
    "observe/mod.rs",
    "observe/probe.rs",
];

/// The directory `REACHED_MODULES` claims whole, relative to `src`.
const REACHED_DIRECTORY: &str = "observe";

/// The complete source closure a Go project load runs through: the Go owners,
/// the shared resolution owners beneath them, and the crate modules they reach.
pub fn source_closure() -> Box<[PathBuf]> {
    let go = crate_path("src/resolution/go");
    let shared = crate_path("src/resolution");
    let source = crate_path("src");
    let mut paths: Vec<PathBuf> = GO_MODULES.iter().map(|name| go.join(name)).collect();
    paths.extend(SHARED_MODULES.iter().map(|name| shared.join(name)));
    paths.extend(REACHED_MODULES.iter().map(|name| source.join(name)));
    for path in &paths {
        assert!(path.is_file(), "{} is modelled but absent", path.display());
    }
    assert_directory_is_exactly_modelled(&go, GO_MODULES);
    assert_directory_is_exactly_modelled(&source.join(REACHED_DIRECTORY), &reached_directory());
    paths.into_boxed_slice()
}

/// The files [`REACHED_MODULES`] names inside [`REACHED_DIRECTORY`].
///
/// Derived rather than written twice: one list states the closure, and a module
/// added beside the observation hook has to join it or fail the exactness check.
fn reached_directory() -> Box<[&'static str]> {
    let prefix = format!("{REACHED_DIRECTORY}/");
    REACHED_MODULES
        .iter()
        .filter_map(|name| name.strip_prefix(&prefix))
        .collect()
}

/// Nothing sits beside the modelled owners in a directory the closure claims
/// whole.
fn assert_directory_is_exactly_modelled(directory: &Path, modelled: &[&str]) {
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
        modelled,
        "every file beneath {} must be a modelled owner",
        directory.display()
    );
}
