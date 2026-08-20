//! Every typed refusal the Go module loader owes its caller.
//!
//! Each row builds its own repository and drops it before the next runs, so no
//! row can read a directory another row wrote.

use std::path::Path;

use pedant_core::resolution::go::{GoProject, GoProjectError, GoResolutionLimits};

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root, write_file};
use crate::resolution::go::fixture::refusal;

/// One refusal row: what it declares, and the error text its loader owes.
type RefusalRow = (&'static str, &'static [FixtureFile], &'static str);

/// The complete refusal table for declarations the loader can decide from the
/// manifests alone.
const DECLARED_REFUSALS: &[RefusalRow] = &[
    (
        "a module path required twice in one manifest",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nrequire example.com/a v1.0.0\nrequire example.com/a v2.0.0\n",
        )],
        "manifest go.mod requires example.com/a more than once",
    ),
    (
        "the same exact exclusion twice",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nexclude example.com/a v1.0.0\nexclude example.com/a v1.0.0\n",
        )],
        "manifest go.mod excludes example.com/a v1.0.0 more than once",
    ),
    (
        "the same replacement key twice",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nreplace example.com/a => ./local/one\nreplace example.com/a => ./local/two\n",
        )],
        "manifest go.mod replaces example.com/a at any version more than once",
    ),
    (
        "an exclusion that matches an admitted requirement",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nrequire example.com/a v1.0.0\n\nexclude example.com/a v1.0.0\n",
        )],
        "requirement example.com/a v1.0.0 is excluded by the root manifest",
    ),
    (
        "a required version that is not a Go version",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nrequire example.com/a 1.0\n",
        )],
        "manifest go.mod declares an invalid version 1.0 for example.com/a",
    ),
    (
        "a replacement to a bare module path with no version",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nreplace example.com/a => example.com/b\n",
        )],
        "failed to parse manifest go.mod at line 3: a replacement without a version must name a directory path",
    ),
    (
        "a manifest with no module directive",
        &[("repo/go.mod", "go 1.22\n")],
        "manifest go.mod declares no module path",
    ),
    (
        "a directive the go.mod grammar does not define",
        &[("repo/go.mod", "module example.com/root\n\nvendorize ./x\n")],
        "failed to parse manifest go.mod at line 3: unknown directive vendorize",
    ),
    (
        "an unclosed directive block",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nrequire (\n\texample.com/a v1.0.0\n",
        )],
        "failed to parse manifest go.mod at line 3: the require block is never closed",
    ),
];

/// The refusal table for replacement targets, which the loader decides only
/// after it has looked at the filesystem.
const TARGET_REFUSALS: &[RefusalRow] = &[
    (
        "a replacement directory that does not exist",
        &[(
            "repo/go.mod",
            "module example.com/root\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ./local/absent\n",
        )],
        "replacement directory local/absent for example.com/a holds no readable go.mod",
    ),
    (
        "a replacement directory that holds no manifest",
        &[
            (
                "repo/go.mod",
                "module example.com/root\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ./local/bare\n",
            ),
            ("repo/local/bare/a.go", "package a\n"),
        ],
        "replacement directory local/bare for example.com/a holds no readable go.mod",
    ),
    (
        "a replacement module that declares another path",
        &[
            (
                "repo/go.mod",
                "module example.com/root\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ./local/other\n",
            ),
            ("repo/local/other/go.mod", "module example.com/other\n"),
        ],
        "replacement directory local/other declares example.com/other, not example.com/a",
    ),
    (
        "a replacement target outside the repository root",
        &[
            (
                "repo/go.mod",
                "module example.com/root\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ../outside\n",
            ),
            ("outside/go.mod", "module example.com/a\n"),
        ],
        "lies outside the project root",
    ),
];

/// 3.T2 (Invariants 4, 26): every conflict, missing manifest, mismatch, and
/// root escape is a typed refusal that publishes no project.
#[test]
fn go_project_refuses_conflicts_missing_manifests_mismatches_and_root_escape() {
    for (subject, files, expected) in DECLARED_REFUSALS.iter().chain(TARGET_REFUSALS) {
        let error = refusal(files);
        let text = error.to_string();
        assert!(
            text.contains(expected),
            "{subject}: expected a refusal naming {expected:?}, got {text:?}"
        );
    }

    assert_conflicting_local_modules();
    assert_unreadable_manifest();
    assert_missing_root_manifest();
    assert_symlinked_escape();
}

/// Two modules requiring one path at two versions, each replaced by its own
/// exact local directory, leave the loader with two answers for one module.
fn assert_conflicting_local_modules() {
    let error = refusal(&[
        (
            "repo/go.mod",
            r#"module example.com/root

require (
	example.com/first v1.0.0
	example.com/twin v1.0.0
)

replace (
	example.com/first => ./local/first
	example.com/twin v1.0.0 => ./local/left
	example.com/twin v2.0.0 => ./local/right
)
"#,
        ),
        (
            "repo/local/first/go.mod",
            "module example.com/first\n\nrequire example.com/twin v2.0.0\n",
        ),
        ("repo/local/left/go.mod", "module example.com/twin\n"),
        ("repo/local/right/go.mod", "module example.com/twin\n"),
    ]);
    let text = error.to_string();
    assert!(
        text.contains("module example.com/twin is declared by local/left and local/right"),
        "two directories may not declare one module path: {text:?}"
    );
}

/// A `go.mod` that is a directory is unreadable, not absent: the loader reports
/// the read rather than treating the module as manifest-free.
fn assert_unreadable_manifest() {
    let tree = build_repository(
        &[(
            "repo/go.mod",
            "module example.com/root\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ./local/a\n",
        )],
        false,
    );
    write_file(
        tree.path(),
        "repo/local/a/go.mod/inner",
        b"not a manifest\n",
    );

    let error = load_error(&repository_root(&tree));
    let text = error.to_string();
    assert!(
        text.contains("failed to read") && text.contains("go.mod"),
        "an unreadable replacement manifest is reported, not skipped: {text:?}"
    );
    drop(tree);
}

/// A root without a readable `go.mod` anchors no main module.
fn assert_missing_root_manifest() {
    let tree = build_repository(&[("repo/main.go", "package main\n")], false);
    let error = load_error(&repository_root(&tree));
    let text = error.to_string();
    assert!(
        text.contains("invalid project root"),
        "a root without go.mod is an invalid root: {text:?}"
    );
    drop(tree);
}

/// A symlinked replacement target resolves outside the root and is refused
/// there, so a link cannot widen what the loader reads.
#[cfg(unix)]
fn assert_symlinked_escape() {
    let tree = build_repository(
        &[
            (
                "repo/go.mod",
                "module example.com/root\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a => ./local/link\n",
            ),
            ("outside/go.mod", "module example.com/a\n"),
        ],
        false,
    );
    std::fs::create_dir_all(tree.path().join("repo/local")).expect("the link's parent exists");
    std::os::unix::fs::symlink(
        tree.path().join("outside"),
        tree.path().join("repo/local/link"),
    )
    .expect("the fixture can link a sibling directory");

    let error = load_error(&repository_root(&tree));
    let text = error.to_string();
    assert!(
        text.contains("lies outside the project root"),
        "a symlinked escape is refused: {text:?}"
    );
    drop(tree);
}

/// Windows needs a privilege for directory symlinks, so the escape claim is
/// carried by the relative-path row alone there.
#[cfg(not(unix))]
fn assert_symlinked_escape() {}

fn load_error(root: &Path) -> GoProjectError {
    match GoProject::load(root, GoResolutionLimits::default()) {
        Ok(project) => panic!("the fixture should be refused, not loaded: {project:?}"),
        Err(error) => error,
    }
}
