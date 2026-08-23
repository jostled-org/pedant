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

use crate::fake_cargo::write_executable;
use crate::fixtures::write;
use crate::process_guard::{Completed, Run, execute};

/// The Git environment every command this tree starts must run under.
///
/// Both configuration files are redirected to `/dev/null`, so nothing the
/// operator set globally reaches the fixture's four commands or the clone,
/// commit and `log` the proof drives through them. A `commit.gpgsign` would
/// block or fail the fixture commit, a `core.hooksPath` would run the
/// operator's hooks inside it, and a `log.showSignature` would insert lines
/// into the `git log --format='package onto %s'` reading
/// [`super::verdict`] compares the packaged history against.
pub(super) const ISOLATED_GIT: &[(&str, &str)] = &[
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
];

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

/// The first-party edges the fixture declares, as consumer, dependency, and
/// whether a feature has to select the edge.
///
/// Two packages carry an inbound edge and six carry none, so a patch set that
/// covered every member — or only the first one — would be visibly wrong.
///
/// One edge is optional and feature-gated, because the released workspace holds
/// one: `pedant-core` takes `pedant-syntax` that way, which is why
/// `pedant-syntax` releases first. Cargo replaces a path edge with a registry
/// edge while packaging whether or not a feature selects it, so an optional
/// edge owes the same release order, the same staged requirement, and the same
/// patch entry as an unconditional one — and the fixture has to hold one for a
/// row to say so.
pub(super) const FIRST_PARTY_EDGES: &[(&str, &str, bool)] = &[
    ("fixture-b", "fixture-a", false),
    ("fixture-c", "fixture-a", false),
    ("fixture-c", "fixture-b", true),
    ("fixture-d", "fixture-a", false),
    ("fixture-e", "fixture-a", false),
    ("fixture-f", "fixture-a", false),
    ("fixture-g", "fixture-a", false),
    ("fixture-h", "fixture-a", false),
];

/// The version the fixture's base commit carries.
const BASE_VERSION: &str = "0.1.0";

/// The version fake release-plz stages, standing in for the bump the real tool
/// computes from the breaking commit the script writes.
pub(super) const STAGED_VERSION: &str = "0.2.0";

/// The branch the fixture's base commit sits on, and the only ref it holds.
const FIXTURE_BRANCH: &str = "main";

/// The tracked file the final-tree edit changes and never commits.
const FINAL_TREE_EDIT: &str = "fixture-a/src/lib.rs";

/// The untracked, unignored file the overlay must copy and never commit.
const UNTRACKED_FILE: &str = "notes/untracked.txt";

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
    let edges: Box<[(&str, bool)]> = FIRST_PARTY_EDGES
        .iter()
        .filter(|(consumer, _, _)| *consumer == name)
        .map(|(_, dependency, gated)| (*dependency, *gated))
        .collect();
    format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2024\"\n{}{}",
        feature_section(&edges),
        dependency_section(&edges, version)
    )
    .into()
}

/// The manifest a member carries once release-plz has staged its release.
pub(super) fn staged_manifest(name: &str) -> Box<str> {
    package_manifest(name, STAGED_VERSION)
}

/// The `[features]` table, which exists only where an edge is gated.
fn feature_section(edges: &[(&str, bool)]) -> Box<str> {
    let selections: Box<[Box<str>]> = edges
        .iter()
        .filter(|(_, gated)| *gated)
        .map(|(dependency, _)| format!("optional-{dependency} = [\"dep:{dependency}\"]\n").into())
        .collect();
    match selections.is_empty() {
        true => "".into(),
        false => format!("\n[features]\n{}", selections.join("")).into(),
    }
}

/// The `[dependencies]` table, with a gated edge in the table form Cargo needs
/// to carry `optional`.
fn dependency_section(edges: &[(&str, bool)], version: &str) -> Box<str> {
    let requirements: Box<[Box<str>]> = edges
        .iter()
        .map(|(dependency, gated)| match gated {
            true => {
                format!("{dependency} = {{ version = \"{version}\", optional = true }}\n").into()
            }
            false => format!("{dependency} = \"{version}\"\n").into(),
        })
        .collect();
    match requirements.is_empty() {
        true => "".into(),
        false => format!("\n[dependencies]\n{}", requirements.join("")).into(),
    }
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
    git(
        repository,
        &["init", "--quiet", "--initial-branch", FIXTURE_BRANCH],
    );
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

/// The repository root as Git reports it, which is what the proof calls the
/// original checkout.
///
/// Asked rather than assumed: on this platform the temporary directory sits
/// under a symlink, so the path a row built and the path the proof refuses a
/// member for resolving through are spelled differently.
pub(super) fn original_checkout(repository: &Path) -> Box<str> {
    git(repository, &["rev-parse", "--show-toplevel"])
        .stdout
        .trim()
        .into()
}

/// The uncommitted change and untracked file the overlay must carry.
fn apply_final_tree_edit(repository: &Path) {
    write(
        &repository.join(FINAL_TREE_EDIT),
        "pub fn fixture_a() {}\npub fn added_by_the_final_tree() {}\n",
    );
    write(
        &repository.join(UNTRACKED_FILE),
        "an untracked, unignored file the overlay must copy\n",
    );
}

/// One repository read as labelled lines: the commit `HEAD` names, every ref it
/// holds, and every change its working tree carries.
///
/// Three readings rather than one, because the proof writes three kinds of
/// thing into the clone it owns — commits, a branch and its upstream, and the
/// versions, requirements, changelogs, and lockfile release-plz stages — and a
/// regression that wrote any of them into the caller's checkout instead lands
/// in exactly one of these lines.
pub(super) fn repository_state(repository: &Path) -> Box<[Box<str>]> {
    let mut state: Vec<Box<str>> = vec![
        format!(
            "head {}",
            git(repository, &["rev-parse", "HEAD"]).stdout.trim()
        )
        .into(),
    ];
    let refs = git(repository, &["show-ref"]);
    state.extend(refs.stdout.lines().map(|line| format!("ref {line}").into()));
    let status = git(
        repository,
        &["status", "--porcelain", "--untracked-files=all"],
    );
    state.extend(
        status
            .stdout
            .lines()
            .map(|line| format!("status {line}").into()),
    );
    state.into_boxed_slice()
}

/// The state [`build_repository`] planted, which is what a proof that never
/// wrote into the caller's repository leaves behind.
///
/// Untracked files are listed one by one rather than collapsed into their
/// directory, so a file the proof left in the caller's checkout is named rather
/// than hidden inside a `notes/` entry that was going to be there anyway.
pub(super) fn planted_state(base: &str) -> Box<[Box<str>]> {
    Box::new([
        format!("head {base}").into(),
        format!("ref {base} refs/heads/{FIXTURE_BRANCH}").into(),
        format!("status  M {FINAL_TREE_EDIT}").into(),
        format!("status ?? {UNTRACKED_FILE}").into(),
    ])
}

/// Run one fixture Git command under the guard and require it to succeed.
///
/// Setup runs under the same guard as the row it prepares: an unbounded
/// `Command` here would let a wedged Git hang a case that owns every other
/// child it starts.
fn git(cwd: &Path, arguments: &[&str]) -> Completed {
    let mut run = Run::program("git", cwd, arguments);
    run.env = ISOLATED_GIT;
    let completed = execute(&run)
        .unwrap_or_else(|failure| panic!("git {arguments:?}: the guard failed: {failure}"));
    assert!(
        completed.success(),
        "git {arguments:?} failed: {}",
        completed.transcript()
    );
    completed
}

/// Install the fake Cargo, clock, and sizer the proof finds on `PATH`, and the
/// two tool bodies Cargo copies out when the proof asks it to install them.
///
/// The bodies sit beside the fake Cargo rather than on `PATH`: a tool the proof
/// never installed must not be reachable, because `release-plz update` proving
/// it can see the pinned semver checker is one of the things a row requires.
///
/// The clock and the sizer are installed for every row and stand aside unless a
/// row asks them for a number. They exist because the proof's budget refusals
/// are minutes and gigabytes away from anything a test can spend.
pub(super) fn write_fake_tools(tools: &Path) {
    write_executable(&tools.join("cargo"), FAKE_CARGO);
    write_executable(&tools.join("date"), FAKE_DATE);
    write_executable(&tools.join("du"), FAKE_DU);
    write_executable(
        &tools.join("bodies/cargo-semver-checks"),
        FAKE_SEMVER_CHECKS,
    );
    write_executable(&tools.join("bodies/release-plz"), FAKE_RELEASE_PLZ);
}

/// The stand-in Cargo, which implements the proof's whole operation protocol.
///
/// It records the target root of every call and its own process id, injects at
/// most one fault, and otherwise produces exactly the archives, lockfile, and
/// metadata the proof reads. It never compiles anything: what a row proves is
/// the script's lifecycle, not Cargo's.
const FAKE_CARGO: &str = include_str!("cargo.sh");

/// The stand-in clock, which reports the real time until a row asks it to jump
/// past a runtime budget.
pub(super) const FAKE_DATE: &str = include_str!("date.sh");

/// The stand-in sizer, which measures for real until a row asks it to report a
/// target root or staging root over budget.
pub(super) const FAKE_DU: &str = include_str!("du.sh");

/// The stand-in cargo-semver-checks, which only has to be the pinned version.
const FAKE_SEMVER_CHECKS: &str = include_str!("cargo-semver-checks.sh");

/// The stand-in release-plz, which records that the pinned semver checker
/// reached its `PATH` and stages the versions and requirements the real tool
/// would have computed.
const FAKE_RELEASE_PLZ: &str = include_str!("release-plz.sh");
