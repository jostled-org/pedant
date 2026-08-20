//! Which files a Go package walk admits, and which trees it never enters.
//!
//! The reserved trees are written into the fixture, so an excluded directory is
//! a decision the walk made rather than a directory that was absent. The
//! symlinked rows point at bytes outside the root: the walk must refuse the
//! path, publish no snapshot, and never open the sentinel.

use std::path::Path;

use pedant_core::resolution::ResolutionProbe;
use pedant_core::resolution::go::{GoProject, GoResolutionLimits, GoSnapshotError};

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root};
use crate::resolution::go::fixture::snapshot_default;
use crate::resolution::go::snapshot_fixtures::{REPLACED_MODULE, RESERVED_TREES};
use crate::resolution::go::snapshot_views::{edges, modules, source_paths, units};
use crate::resolution::go::views::borrowed;

/// The only sources [`RESERVED_TREES`] admits: the ordinary one and the
/// generated one.
const ADMITTED_SOURCES: &[&str] = &["main.go", "zz_generated.go"];

/// The single unit those two sources form.
const ADMITTED_UNITS: &[&str] =
    &["example.com/reserved|production|example.com/reserved|main||main.go,zz_generated.go"];

/// Every module, unit, and edge [`REPLACED_MODULE`] states: an admitted local
/// replacement is a second module beside the main one, not a directory folded
/// into it.
const REPLACED_MODULES: &[&str] = &[
    "example.com/root||go.mod|0",
    "example.com/lib|local/lib|local/lib/go.mod|1",
];
const REPLACED_UNITS: &[&str] = &[
    "example.com/root|production|example.com/root|root||root.go",
    "example.com/lib|production|example.com/lib|lib|local/lib|local/lib/lib.go",
];
const REPLACED_EDGES: &[&str] = &["example.com/root|example.com/lib|example.com/lib|v1.0.0"];

/// The out-of-root sentinel every escape row points at and none may read.
const SENTINEL: &str = "outside/secret.go";

/// A repository whose root holds one ordinary source, beside a sibling
/// directory each escape row links into.
const ESCAPE_BASE: &[FixtureFile] = &[
    ("repo/go.mod", "module example.com/escape\n\ngo 1.22\n"),
    ("repo/main.go", "package main\n"),
    (SENTINEL, "package secret\n"),
];

/// 4.T3 (Invariants 4, 6): package discovery admits generated Go sources,
/// excludes every reserved tree and unadmitted nested module, keeps an admitted
/// local replacement a separate module, and refuses any path that resolves
/// outside the repository root.
#[test]
fn go_package_discovery_excludes_reserved_trees_and_retains_generated_go_sources() {
    let (tree, snapshot) = snapshot_default(RESERVED_TREES);
    assert_eq!(
        &*borrowed(&source_paths(&snapshot)),
        ADMITTED_SOURCES,
        "dot, underscore, testdata, vendor, nested-module, and non-Go entries stay out"
    );
    assert_eq!(&*borrowed(&units(&snapshot)), ADMITTED_UNITS);
    drop(tree);

    assert_admitted_replacement_is_a_separate_module();

    assert_escape_is_refused_unread("a symlinked source", |root| {
        symlink(&root.join("../outside/secret.go"), &root.join("link.go"));
    });
    assert_escape_is_refused_unread("a symlinked directory", |root| {
        symlink(&root.join("../outside"), &root.join("linked"));
    });
}

/// A nested `go.mod` the root manifest replaces into is walked as its own
/// module, so its packages and the dependency edge that reached it are stated
/// beside the main module's rather than merged into them.
fn assert_admitted_replacement_is_a_separate_module() {
    let (tree, snapshot) = snapshot_default(REPLACED_MODULE);

    assert_eq!(&*borrowed(&modules(&snapshot)), REPLACED_MODULES);
    assert_eq!(&*borrowed(&units(&snapshot)), REPLACED_UNITS);
    assert_eq!(&*borrowed(&edges(&snapshot)), REPLACED_EDGES);
    assert_eq!(
        snapshot
            .module(snapshot.root_module())
            .expect("the snapshot answers for its own root module")
            .path(),
        "example.com/root",
        "the main module is the snapshot's root module"
    );

    let root = snapshot.root().to_path_buf();
    drop(snapshot);
    drop(tree);
    assert!(
        !root.exists(),
        "the fixture is released with the temporary directory"
    );
}

/// One linked escape refuses the snapshot, and the sentinel behind it is never
/// opened.
#[cfg(unix)]
fn assert_escape_is_refused_unread(subject: &str, link: impl FnOnce(&Path)) {
    let tree = build_repository(ESCAPE_BASE, false);
    let root = repository_root(&tree);
    link(&root);

    let probe = ResolutionProbe::install();
    let project =
        GoProject::load(&root, GoResolutionLimits::default()).expect("the fixture should load");
    let refused = match project.snapshot_resolution() {
        Ok(snapshot) => panic!("{subject}: the escape should refuse, not snapshot: {snapshot:?}"),
        Err(error) => error,
    };
    assert!(
        matches!(refused, GoSnapshotError::OutOfRoot { .. }),
        "{subject}: an escape is refused as OutOfRoot, got {refused:?}"
    );
    let opened = probe.source_reads();
    assert!(
        opened.iter().all(|path| !path.contains("secret")),
        "{subject}: the out-of-root sentinel must never be opened, opened {opened:?}"
    );
    drop(probe);
    drop(project);
    drop(tree);
}

/// Windows needs a privilege for directory symlinks, so the escape claim is
/// carried by the project cases' relative-path row alone there.
#[cfg(not(unix))]
fn assert_escape_is_refused_unread(_subject: &str, _link: impl FnOnce(&Path)) {}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("the fixture can link a sibling path");
}
