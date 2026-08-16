//! The eight-package repository and fake tool set one lifecycle row runs.
//!
//! The tracked packaged-workspace proof reads a release order, clones a Git
//! repository, overlays a working tree, and drives Cargo and release-plz. This
//! module supplies all four in miniature: eight one-file crates, a committed
//! base, an uncommitted final-tree edit, one untracked file, and executables
//! that answer the proof's whole operation protocol without compiling
//! anything.
//!
//! Nothing here asserts. [`super`] owns what a row requires; this owns what a
//! row is given.

use std::path::Path;

use crate::fake_cargo::make_executable;
use crate::fixtures::write;
use crate::process_guard::{Completed, Run, execute};

/// The fixture's release order, which its `release-plz.toml` states and the
/// script must read rather than assume.
pub(super) const RELEASE_ORDER: &[&str] = &[
    "fixture-a",
    "fixture-b",
    "fixture-c",
    "fixture-d",
    "fixture-e",
    "fixture-f",
    "fixture-g",
    "fixture-h",
];

/// The first-party edges the fixture declares, as consumer and dependency.
///
/// Two packages carry an inbound edge and six carry none, so a patch set that
/// covered every member — or only the first one — would be visibly wrong.
const FIRST_PARTY_EDGES: &[(&str, &str)] = &[
    ("fixture-b", "fixture-a"),
    ("fixture-c", "fixture-a"),
    ("fixture-c", "fixture-b"),
    ("fixture-d", "fixture-a"),
    ("fixture-e", "fixture-a"),
    ("fixture-f", "fixture-a"),
    ("fixture-g", "fixture-a"),
    ("fixture-h", "fixture-a"),
];

/// The version the fixture's base commit carries.
const BASE_VERSION: &str = "0.1.0";

/// The version fake release-plz stages, standing in for the bump the real tool
/// computes from the breaking commit the script writes.
const STAGED_VERSION: &str = "0.2.0";

/// Build one row's repository: the committed base, the uncommitted final-tree
/// edit, and the untracked file the overlay must carry. Reports the base the
/// proof is asked to stage onto.
pub(super) fn build_repository(repository: &Path) -> Box<str> {
    write_workspace(repository);
    let base = commit_base(repository);
    apply_final_tree_edit(repository);
    base
}

/// The eight-package workspace the proof stages, before its final-tree edit.
fn write_workspace(repository: &Path) {
    let members: Box<[Box<str>]> = RELEASE_ORDER
        .iter()
        .map(|name| format!("\"{name}\"").into())
        .collect();
    write(
        &repository.join("Cargo.toml"),
        format!(
            "[workspace]\nmembers = [{}]\nresolver = \"3\"\n",
            members.join(", ")
        ),
    );
    write(
        &repository.join("release-plz.toml"),
        &*release_plz_manifest(),
    );
    for name in RELEASE_ORDER {
        write(
            &repository.join(name).join("Cargo.toml"),
            &*package_manifest(name, BASE_VERSION),
        );
        write(
            &repository.join(name).join("src/lib.rs"),
            format!("pub fn {}() {{}}\n", name.replace('-', "_")),
        );
    }
}

/// The release order the script must read rather than assume.
fn release_plz_manifest() -> Box<str> {
    let packages: Box<[Box<str>]> = RELEASE_ORDER
        .iter()
        .map(|name| format!("[[package]]\nname = \"{name}\"\n").into())
        .collect();
    format!(
        "[workspace]\nrelease_always = true\n\n{}",
        packages.join("\n")
    )
    .into()
}

/// One member's manifest at the stated version, carrying its first-party edges
/// at that same version.
fn package_manifest(name: &str, version: &str) -> Box<str> {
    let mut manifest =
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2024\"\n");
    let edges: Box<[&(&str, &str)]> = FIRST_PARTY_EDGES
        .iter()
        .filter(|(consumer, _)| *consumer == name)
        .collect();
    if !edges.is_empty() {
        manifest.push_str("\n[dependencies]\n");
        for (_, dependency) in edges.iter() {
            manifest.push_str(&format!("{dependency} = \"{version}\"\n"));
        }
    }
    manifest.into()
}

/// The manifests and changelogs fake release-plz stages, standing in for the
/// versions and requirements the real tool computes.
pub(super) fn write_staged_tree(staged: &Path) {
    for name in RELEASE_ORDER {
        write(
            &staged.join(name).join("Cargo.toml"),
            &*package_manifest(name, STAGED_VERSION),
        );
        write(
            &staged.join(name).join("CHANGELOG.md"),
            format!("# {name}\n\n## {STAGED_VERSION}\n"),
        );
    }
}

/// Commit the fixture and report the base the proof must overlay onto.
fn commit_base(repository: &Path) -> Box<str> {
    git(repository, &["init", "--quiet", "--initial-branch", "main"]);
    git(repository, &["add", "--all"]);
    git(
        repository,
        &[
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "base",
        ],
    );
    git(repository, &["rev-parse", "HEAD"]).stdout.trim().into()
}

/// The uncommitted change and untracked file the overlay must carry.
fn apply_final_tree_edit(repository: &Path) {
    write(
        &repository.join("fixture-a/src/lib.rs"),
        "pub fn fixture_a() {}\npub fn added_by_the_final_tree() {}\n",
    );
    write(
        &repository.join("notes/untracked.txt"),
        "an untracked, unignored file the overlay must copy\n",
    );
}

/// Run one fixture Git command under the guard and require it to succeed.
///
/// Setup runs under the same guard as the row it prepares: an unbounded
/// `Command` here would let a wedged Git hang a case that owns every other
/// child it starts.
fn git(cwd: &Path, arguments: &[&str]) -> Completed {
    let completed = execute(&Run::program("git", cwd, arguments))
        .unwrap_or_else(|failure| panic!("the guard failed: {failure}"));
    assert!(
        completed.success(),
        "git {arguments:?} failed: {}",
        completed.transcript()
    );
    completed
}

/// Install the fake Cargo the proof finds on `PATH`, and the two tool bodies it
/// copies out when the proof asks Cargo to install them.
///
/// The bodies sit beside the fake Cargo rather than on `PATH`: a tool the proof
/// never installed must not be reachable, because `release-plz update` proving
/// it can see the pinned semver checker is one of the things a row requires.
pub(super) fn write_fake_tools(tools: &Path) {
    write_executable(&tools.join("cargo"), FAKE_CARGO);
    write_executable(
        &tools.join("bodies/cargo-semver-checks"),
        FAKE_SEMVER_CHECKS,
    );
    write_executable(&tools.join("bodies/release-plz"), FAKE_RELEASE_PLZ);
}

fn write_executable(path: &Path, body: &str) {
    write(path, body);
    make_executable(path);
}

/// The stand-in Cargo, which implements the proof's whole operation protocol.
///
/// It records the target root of every call and its own process id, injects at
/// most one fault, and otherwise produces exactly the archives, lockfile, and
/// metadata the proof reads. It never compiles anything: what a row proves is
/// the script's lifecycle, not Cargo's.
const FAKE_CARGO: &str = include_str!("cargo.sh");

/// The stand-in cargo-semver-checks, which only has to be the pinned version.
const FAKE_SEMVER_CHECKS: &str = include_str!("cargo-semver-checks.sh");

/// The stand-in release-plz, which records that the pinned semver checker
/// reached its `PATH` and stages the versions and requirements the real tool
/// would have computed.
const FAKE_RELEASE_PLZ: &str = include_str!("release-plz.sh");
