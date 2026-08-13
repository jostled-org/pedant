//! Behavioral and structural proofs for the publication workflow.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SHELLCHECK_VERSION: &str = "0.11.0";
const SHELLCHECK_DIGEST: &str = "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198";
const CARGO_DENY_REVISION: &str = "bca0dde53651ee946720e4540b5ce2610bec8f06";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant-core has a workspace parent")
        .to_path_buf()
}

fn read_repository_file(path: &str) -> String {
    fs::read_to_string(repository_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn write_fixture_file(root: &Path, path: &str, contents: &str) {
    let destination = root.join(path);
    fs::create_dir_all(
        destination
            .parent()
            .expect("every fixture file has a parent"),
    )
    .expect("fixture directory is writable");
    fs::write(destination, contents).expect("fixture file is writable");
}

fn run_git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .expect("git is available");
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn commit_all(root: &Path, message: &str) {
    run_git(root, &["add", "."]);
    run_git(root, &["commit", "-m", message]);
}

fn release_readiness(root: &Path) -> Output {
    Command::new(repository_root().join(".github/scripts/check_release_readiness.sh"))
        .current_dir(root)
        .output()
        .expect("release-readiness script is executable")
}

fn initialize_release_fixture(root: &Path) {
    write_fixture_file(
        root,
        "Cargo.toml",
        "[workspace]\nmembers = [\"core\"]\nresolver = \"3\"\n",
    );
    write_fixture_file(
        root,
        "core/Cargo.toml",
        "[package]\nname = \"core\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    write_fixture_file(root, "core/src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    run_git(root, &["init"]);
    run_git(root, &["config", "user.email", "fixture@example.invalid"]);
    run_git(root, &["config", "user.name", "Fixture"]);
    commit_all(root, "initial release");
    run_git(root, &["tag", "core-v0.1.0"]);
}

#[test]
fn release_readiness_requires_new_versions_for_changed_published_sources() {
    let fixture = tempfile::tempdir().expect("release fixture is available");
    initialize_release_fixture(fixture.path());

    assert!(
        release_readiness(fixture.path()).status.success(),
        "an unchanged tagged package is safe"
    );

    write_fixture_file(
        fixture.path(),
        "core/src/lib.rs",
        "pub fn value() -> u8 { 2 }\n",
    );
    commit_all(fixture.path(), "change published source");
    let blocked = release_readiness(fixture.path());
    assert_eq!(blocked.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("core-v0.1.0"),
        "the refusal names the stale published version"
    );

    write_fixture_file(
        fixture.path(),
        "core/Cargo.toml",
        "[package]\nname = \"core\"\nversion = \"0.2.0\"\nedition = \"2024\"\n",
    );
    commit_all(fixture.path(), "prepare release");
    assert!(
        release_readiness(fixture.path()).status.success(),
        "an untagged version is ready for release-plz"
    );
}

#[test]
fn ci_uses_one_pinned_shellcheck_release() {
    let workflow = read_repository_file(".github/workflows/ci.yml");
    let wrapper = read_repository_file(".github/scripts/run_shellcheck.sh");

    assert!(wrapper.contains(&format!("SHELLCHECK_VERSION=\"{SHELLCHECK_VERSION}\"")));
    assert!(workflow.contains(&format!("SHELLCHECK_VERSION: {SHELLCHECK_VERSION}")));
    assert!(workflow.contains(SHELLCHECK_DIGEST));

    let install = workflow
        .find("Install pinned ShellCheck")
        .expect("CI installs the pinned release");
    let lint = workflow
        .find(".github/scripts/run_shellcheck.sh")
        .expect("CI runs the version-checking wrapper");
    assert!(install < lint, "CI installs ShellCheck before linting");
}

#[test]
fn ci_pins_cargo_deny_to_a_locked_source_revision() {
    let workflow = read_repository_file(".github/workflows/ci.yml");
    let install = workflow
        .find("Install pinned cargo-deny")
        .expect("CI names the pinned cargo-deny installation");
    let check = workflow[install..]
        .find("- run: cargo deny check")
        .map(|offset| install + offset)
        .expect("CI runs cargo-deny after installation");
    let installation = &workflow[install..check];

    assert!(installation.contains(&format!("CARGO_DENY_REVISION: {CARGO_DENY_REVISION}")));
    assert!(installation.contains("--git https://github.com/EmbarkStudios/cargo-deny"));
    assert!(installation.contains("--rev \"${CARGO_DENY_REVISION}\""));
    assert!(installation.contains("--locked"));
    assert!(!workflow.contains("cargo install cargo-deny"));
}

#[test]
fn release_job_publishes_only_registry_compatible_trees() {
    let workflow = read_repository_file(".github/workflows/release-plz.yml");
    assert!(
        repository_root()
            .join("pedant-graph/CHANGELOG.md")
            .is_file(),
        "every release-plz package supplies its changelog"
    );
    let readiness = workflow
        .find("id: release_readiness")
        .expect("the release job computes registry readiness");
    let jq_install = workflow
        .find("sudo apt-get install --yes jq")
        .expect("the release job installs its metadata reader");
    let publish = workflow
        .rfind("command: release")
        .expect("the release job invokes release-plz");

    assert!(jq_install < readiness, "jq is installed before readiness");
    assert!(
        readiness < publish,
        "readiness is decided before publication"
    );
    assert_eq!(
        workflow
            .matches("if: steps.release_readiness.outputs.ready == 'true'")
            .count(),
        2,
        "both the immutable-manifest check and publication are gated"
    );
}
