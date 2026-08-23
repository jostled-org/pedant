//! Behavioral and structural proofs for the publication workflow.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use crate::packaged_workspace_claims::{
    function_body, offset_of, read_repository_file, repository_root,
};

const SHELLCHECK_VERSION: &str = "0.11.0";
const SHELLCHECK_DIGEST: &str = "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198";
const CARGO_DENY_REVISION: &str = "bca0dde53651ee946720e4540b5ce2610bec8f06";

/// The one tracked owner of Cargo proof status.
const CARGO_INFRASTRUCTURE_SCRIPT: &str = ".github/scripts/cargo_infrastructure.sh";

/// The complete function inventory that owner may define, sorted.
///
/// `cargo_classify`, `cargo_record`, `cargo_run`, and `cargo_worst` are the API
/// the ignored lifecycle runners already call; `cargo_classify_output` is the
/// same decision for a transcript a caller holds rather than a file it wrote,
/// and `cargo_receipt` is the one way a capture reaches a caller's output
/// directory. A seventh name would be a second place for a runner to look.
const CLASSIFIER_API: &[&str] = &[
    "cargo_classify",
    "cargo_classify_output",
    "cargo_receipt",
    "cargo_record",
    "cargo_run",
    "cargo_worst",
];

/// The signature table, in order, as the one regex owner spells it — with an
/// underscore wherever the owner writes a space.
///
/// The redaction is load-bearing. The classifier this table describes reads
/// Cargo's transcript, and Cargo puts source lines in that transcript: a
/// rustfmt diff, a clippy span, or a compiler error quoting one of these
/// signatures verbatim would make every honest failure of this crate look like
/// an exhausted volume, and the loop would retry a real defect rather than
/// report it. [`expanded`] restores the spaces for the one comparison that
/// needs them.
const INFRASTRUCTURE_SIGNATURES: &[&str] = &[
    "spurious_network_error",
    "failed_to_fetch",
    "Could_not_resolve_host",
    "error:_could_not_download",
    "No_space_left_on_device",
    "Read-only_file_system",
    "failed_to_acquire_package_cache_lock",
    "toolchain_.*_is_not_installed",
    "rustup_could_not_choose_a_version",
];

/// Flags that would fold case and let a near miss claim an absent machine.
const CASE_FOLDING_FLAGS: &[&str] = &[" -i", " --ignore-case", " -S", " --smart-case"];

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

/// One tracked owner classifies Cargo status, and it fails closed: an
/// unclassifiable machine leaves through 75 rather than through a verdict.
///
/// Structure only. `pedant/tests/supply_chain.rs` owns what the script does
/// with a real transcript, including every near miss it must refuse.
#[test]
fn cargo_infrastructure_classifier_is_complete_and_fail_closed() {
    let source = read_repository_file(CARGO_INFRASTRUCTURE_SCRIPT);
    assert_classifier_api(&source);
    assert_signature_table(&source);
    assert_fail_closed_lifecycle(&source);
}

/// The tracked owner defines exactly the compatible API and nothing beside it.
///
/// That this file is a ShellCheck subject exactly once is
/// [`crate::packaged_workspace`]'s claim, which requires the wrapper's whole
/// subject list to equal the duplicate-free tracked inventory.
fn assert_classifier_api(source: &str) {
    let mut defined: Box<[Box<str>]> = source
        .lines()
        .filter_map(|line| line.strip_suffix("() {"))
        .map(Box::from)
        .collect();
    defined.sort();
    let expected: Box<[Box<str>]> = CLASSIFIER_API.iter().map(|name| (*name).into()).collect();
    assert_eq!(
        defined, expected,
        "the tracked classifier's function inventory changed"
    );
    assert!(
        !source.contains("docs/scripts"),
        "the tracked owner must not reach into ignored lifecycle files"
    );
}

/// One regex owner holds the exact table, matched case-sensitively.
fn assert_signature_table(source: &str) {
    let owners: Box<[&str]> = source
        .lines()
        .filter_map(|line| line.strip_prefix("CARGO_INFRASTRUCTURE_PATTERNS="))
        .collect();
    assert_eq!(
        owners.len(),
        1,
        "the signature table needs exactly one owner"
    );
    let declared = owners[0].trim_matches('\'');
    let expected: Box<[Box<str>]> = INFRASTRUCTURE_SIGNATURES
        .iter()
        .map(|signature| expanded(signature))
        .collect();
    assert!(
        expected.join("|") == declared,
        "the signature table reads [{}] rather than [{}]",
        redacted(declared),
        INFRASTRUCTURE_SIGNATURES.join("|")
    );
    assert!(
        source.contains("CARGO_INFRASTRUCTURE_STATUS=75"),
        "the infrastructure status is 75"
    );
    for line in source.lines().filter(|line| line.contains("rg ")) {
        for flag in CASE_FOLDING_FLAGS {
            assert!(
                !line.contains(flag),
                "matching must stay case-sensitive: {}",
                redacted(line)
            );
        }
    }
}

/// One stored signature, with its underscores restored to the spaces the
/// tracked owner writes.
fn expanded(text: &str) -> Box<str> {
    text.replace('_', " ").into()
}

/// One fragment of the script, rendered back into the stored form so a failure
/// message cannot restate a signature. See [`INFRASTRUCTURE_SIGNATURES`].
fn redacted(text: &str) -> Box<str> {
    text.replace(' ', "_").into()
}

/// Infrastructure leaves immediately, an ordinary failure is kept once, and no
/// path keeps a capture.
fn assert_fail_closed_lifecycle(source: &str) {
    let immediate_exit = "exit \"${CARGO_INFRASTRUCTURE_STATUS}\"";
    let record = function_body(source, "cargo_record");
    assert!(
        record.contains(immediate_exit),
        "classified infrastructure must exit immediately"
    );
    assert!(
        record.contains("${cargo_infrastructure_worst}\" -eq 0"),
        "only the first ordinary failure is kept"
    );
    assert!(
        function_body(source, "cargo_worst").contains("${cargo_infrastructure_worst}"),
        "the aggregate is reported from the recorded worst status"
    );
    assert!(
        function_body(source, "cargo_receipt").contains("${PROOF_OUTPUT_DIR}/$1.log"),
        "one owner copies an indexed capture, named for the label it was handed"
    );
    assert_run_owns_its_capture(&function_body(source, "cargo_run"), immediate_exit);
}

/// `cargo_run` allocates before it runs, leaves its indexed receipt through the
/// one owner of that copy, and removes its capture before any status can leave
/// the shell.
fn assert_run_owns_its_capture(run: &str, immediate_exit: &str) {
    let subject = "cargo_run's ownership of its capture";
    let allocation = offset_of(run, "mktemp", subject);
    let invocation = offset_of(run, "\"$@\"", subject);
    let removal = offset_of(run, "rm -f", subject);
    let record = offset_of(run, "cargo_record", subject);
    assert!(
        run.contains(&format!("|| {immediate_exit}")),
        "an unallocatable capture is an unavailable machine"
    );
    assert!(
        run.contains("cargo_receipt \"${label}\""),
        "an indexed run leaves one named receipt"
    );
    assert!(
        allocation < invocation,
        "the capture is allocated before the command runs"
    );
    assert!(
        removal < record,
        "the capture is removed before any status leaves the shell"
    );
}

/// The packaged-workspace proof stages the release finalization will squash,
/// lets release-plz own every version and requirement, and compiles all eight
/// archives through the requirements those archives carry.
///
/// Structure only, and deliberately so: the run this describes installs two
/// pinned tools from Git and talks to the registry, so it belongs to the
/// indexed proof rather than to a scoped test. What a scoped test can own is
/// that the script cannot silently stop being that run — that it cannot package
/// seven members, reuse yesterday's archive, resolve a first-party edge through
/// crates.io, leave its clone behind, or compute a version release-plz did not
/// stage. `pedant/tests/supply_chain.rs` owns what it does with fake tools.
#[test]
fn packaged_workspace_script_is_release_graph_exact() {
    crate::packaged_workspace::assert_release_graph_is_exact();
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
    assert_readiness_gates_publication();
}

/// The release job installs its metadata reader, decides registry readiness,
/// and gates both the immutable-manifest check and publication on that
/// decision — in that order.
///
/// One owner, two callers. The predicate above reads it as workflow behavior;
/// [`crate::release_contract`]'s release-owner predicate requires it as part of
/// the surface every published archive depends on, because an archive that
/// compiles proves nothing about a job that would publish it from a tree whose
/// tagged dependencies still hold older source.
pub(crate) fn assert_readiness_gates_publication() {
    let workflow = read_repository_file(".github/workflows/release-plz.yml");
    let readiness = workflow
        .find("id: release_readiness")
        .expect("the release job computes registry readiness");
    let tool_install = workflow
        .find("sudo apt-get install --yes jq ripgrep")
        .expect("the release job installs every release-check reader");
    let publish = workflow
        .rfind("command: release")
        .expect("the release job invokes release-plz");

    assert!(
        tool_install < readiness,
        "release-check readers are installed before readiness"
    );
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
