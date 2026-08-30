//! Which failures end the build, and which ones it records and continues past.

use pedant_snippet::{CodeIntelligenceError, HealthStatus, IssueStage};

use super::fixture::Repository;
use super::harness::{assert_sorted, indexed, issue_rows, paths, required, rooted, rust_manifest};
use super::sources::{BROKEN_SOURCE, MIXED_REPOSITORY, UNDECODABLE};

/// The failure matrix: a root or an explicit authority is fatal, and every
/// other refusal is a recorded, non-stale issue over an index that still holds
/// everything else.
#[test]
fn code_intelligence_initial_failures_classify_fatal_and_degraded() {
    fatal_roots();
    fatal_explicit_authorities();
    nested_explicit_member_failure_is_fatal();
    automatic_sibling_failure_remains_degraded();
    degraded_project();
    degraded_sources();
}

/// A workspace root selected automatically does not erase the fact that the
/// caller explicitly required one member it claimed.
fn nested_explicit_member_failure_is_fatal() {
    let repository = Repository::of(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"broken\"]\nresolver = \"3\"\n",
        ),
        (
            "broken/Cargo.toml",
            "[package]\nname = \"broken\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("broken/src/lib.rs", "pub mod absent;\n"),
        ("kept.py", "def kept():\n    return 1\n"),
    ]);

    let automatic = indexed(&repository);
    assert_eq!(
        &*issue_rows(&automatic),
        ["project:Cargo.toml|snapshot|snapshot_refused|false"],
        "the nested member's automatic-only failure degrades the selected workspace"
    );

    let explicit = required(&repository, &[rust_manifest("broken/Cargo.toml")]);
    match explicit {
        Err(CodeIntelligenceError::Project {
            authority, stage, ..
        }) => {
            assert_eq!(&*authority, "broken/Cargo.toml");
            assert_eq!(stage, IssueStage::Snapshot);
        }
        Err(error) => panic!("the required member returned the wrong fatal error: {error}"),
        Ok(state) => panic!(
            "the required member failure was degraded after its automatic ancestor claimed it: {:?}",
            issue_rows(&state)
        ),
    }
}

/// A failure belongs to the member that produced it, not every explicitly
/// required member claimed by the same workspace selection.
fn automatic_sibling_failure_remains_degraded() {
    let repository = Repository::of(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"required\", \"broken\"]\nresolver = \"3\"\n",
        ),
        (
            "required/Cargo.toml",
            "[package]\nname = \"required\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("required/src/lib.rs", "pub fn required() {}\n"),
        (
            "broken/Cargo.toml",
            "[package]\nname = \"broken\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("broken/src/lib.rs", "pub mod absent;\n"),
    ]);

    let state = required(&repository, &[rust_manifest("required/Cargo.toml")])
        .expect("an automatic sibling's failure does not make a healthy required member fatal");
    assert_eq!(
        &*issue_rows(&state),
        ["project:Cargo.toml|snapshot|snapshot_refused|false"],
        "the unrelated automatic failure remains degraded"
    );
}

/// A root that is not a readable directory states no index at all, and the
/// directory holding it still is one.
///
/// The control is the same tree the two refusals are spelled against: an
/// `InvalidRoot` for every path is indistinguishable from an `InvalidRoot` for
/// the two that earn it unless the root between them answers.
fn fatal_roots() {
    let repository = Repository::of(&[("a.py", "def run():\n    return 1\n")]);
    let admitted =
        rooted(repository.root()).expect("the directory the two refusals sit in indexes");
    assert_eq!(
        &*paths(&admitted),
        ["a.py"],
        "so a refusal below is the path it names rather than every path"
    );

    let absent = repository.root().join("no-such-directory");
    let refused = rooted(&absent).expect_err("a root that does not exist is fatal");
    assert!(
        matches!(refused, CodeIntelligenceError::InvalidRoot { .. }),
        "an absent root is refused as a root: {refused}"
    );

    let file = repository.root().join("a.py");
    let refused = rooted(&file).expect_err("a root that is a file is fatal");
    assert!(
        matches!(refused, CodeIntelligenceError::InvalidRoot { .. }),
        "a file is refused as a root: {refused}"
    );
}

/// An explicit authority the caller named and the repository cannot supply is
/// fatal.
fn fatal_explicit_authorities() {
    let repository = Repository::of(MIXED_REPOSITORY);

    let missing = required(&repository, &[rust_manifest("absent/Cargo.toml")])
        .expect_err("a missing explicit authority is fatal");
    assert!(
        matches!(missing, CodeIntelligenceError::SourceRead { .. }),
        "a missing explicit authority names the path that is not there: {missing}"
    );

    let directory = required(&repository, &[rust_manifest("crate-a/src")])
        .expect_err("an explicit authority that is a directory is fatal");
    assert!(
        matches!(directory, CodeIntelligenceError::Project { .. }),
        "a directory is refused as an authority: {directory}"
    );

    let malformed = Repository::of(&[
        ("Cargo.toml", "[package\nname = broken\n"),
        ("src/lib.rs", "pub fn f() {}\n"),
    ]);
    let refused = required(&malformed, &[rust_manifest("Cargo.toml")]);
    match refused {
        Ok(state) => panic!(
            "a malformed explicit authority must be fatal, not degraded: {:?}",
            issue_rows(&state)
        ),
        Err(error) => assert!(
            matches!(
                error,
                CodeIntelligenceError::Project { .. } | CodeIntelligenceError::SourceRead { .. }
            ),
            "a malformed explicit authority refuses as a project: {error}"
        ),
    }
}

/// A malformed automatic authority degrades its own project and nothing else.
fn degraded_project() {
    let repository = Repository::of(&[
        ("Cargo.toml", "[package\nname = broken\n"),
        ("src/lib.rs", "pub fn kept() {}\n"),
        ("script.py", "def kept():\n    return 1\n"),
    ]);
    let state = indexed(&repository);

    assert_eq!(
        &*paths(&state),
        ["script.py", "src/lib.rs"],
        "a failed project leaves every readable file eligible for syntax-only navigation"
    );
    assert!(
        state.index().projects().is_empty(),
        "a failed project states no partial slice"
    );
    let rows = issue_rows(&state);
    assert!(
        rows.iter()
            .any(|row| row.starts_with("project:Cargo.toml|authority|authority_unreadable|false")),
        "the refusal is recorded against the authority, and it is not stale: {rows:?}"
    );
    assert_eq!(
        state.health().status(),
        HealthStatus::Degraded,
        "an index carrying issues and no stale scope is degraded"
    );
}

/// A source that cannot be read, decoded, or completely recognized degrades
/// itself alone.
fn degraded_sources() {
    let repository = Repository::of(&[
        ("good.py", "def good():\n    return 1\n"),
        ("broken.py", BROKEN_SOURCE),
    ]);
    repository.write_bytes("undecodable.py", UNDECODABLE);
    let state = indexed(&repository);

    assert_eq!(
        &*paths(&state),
        ["good.py"],
        "only the sources that stated a complete inventory are admitted"
    );
    let rows = issue_rows(&state);
    assert!(
        rows.contains(&"file:broken.py|inventory|inventory_incomplete|false".to_owned()),
        "a parser that recovered cannot claim a complete inventory: {rows:?}"
    );
    assert!(
        rows.contains(&"file:undecodable.py|source|source_encoding|false".to_owned()),
        "bytes that never decode never reach a parser: {rows:?}"
    );
    assert_sorted(&rows, "published issues");
    assert!(
        state.issues().iter().all(|issue| !issue.stale()),
        "an initial build records what it found; nothing is serving an older answer"
    );
    assert_eq!(
        state.health().issues(),
        2,
        "the health counts both refusals"
    );
    assert_eq!(
        state.health().stale_scopes(),
        0,
        "and no scope is stale on an initial build"
    );

    let complete = Repository::of(&[("good.py", "def good():\n    return 1\n")]);
    let clean = indexed(&complete);
    assert_eq!(
        clean.health().status(),
        HealthStatus::Complete,
        "a repository with nothing to record is complete"
    );
    assert_eq!(
        clean.index().revision(),
        state.index().revision(),
        "a file that failed is a file the index does not hold, so the two indexes are equal"
    );
    assert_ne!(
        clean.revision(),
        state.revision(),
        "and the issues alone move the state identity"
    );
}
