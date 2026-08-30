//! No path leaves the root, and nothing outside it is ever opened.

use std::path::Path;

use pedant_snippet::{CodeIntelligenceError, IssueCode, IssueStage};

use super::fixture::Repository;
use super::harness::{indexed, issue_rows, paths, required, rust_manifest};
use super::sources::{KEPT_ONLY, MIXED_REPOSITORY, MIXED_SOURCES, OUTSIDE};

/// Every route that takes a path — authority, query, and corpus — refuses one
/// that leaves the canonical root, and refuses it before the read.
#[test]
fn code_intelligence_root_confinement_precedes_every_read() {
    let repository = Repository::of(MIXED_REPOSITORY);
    let state = indexed(&repository);
    let index = state.index();

    // The corpus is pinned positively before anything below reads a refusal.
    // Every negative claim this root makes — that no hard-excluded directory
    // was entered, that an ignore file kept its subtree out — is also true of
    // an index that admitted nothing, and the rows below state only refusals.
    // Naming the exact admitted set states all of them at once and states them
    // against a corpus that is there.
    assert_eq!(
        &*paths(&state),
        MIXED_SOURCES,
        "the index admits exactly the sources beneath the root: no hard-excluded \
         directory was entered, and the ignore file kept its subtree out"
    );

    // And the same route answers for a path that stays beneath the root, which
    // is the control every refusal below is read against: an index that refused
    // every spelling as an escape satisfies the whole loop.
    let admitted = index
        .file(MIXED_SOURCES[0])
        .expect("a normalized repository path the index admitted selects its own record");
    assert_eq!(
        admitted.path(),
        MIXED_SOURCES[0],
        "the record a normalized path selects is the one it names"
    );

    for spelling in [
        "/etc/passwd",
        "../outside.rs",
        "crate-a/../../outside.rs",
        "./crate-a/src/lib.rs",
        "crate-a//src/lib.rs",
        "crate-a\\src\\lib.rs",
        "",
    ] {
        let refused = index
            .file(spelling)
            .expect_err("a path that is not a normalized repository path is refused");
        assert!(
            matches!(refused, CodeIntelligenceError::PathEscape { .. }),
            "{spelling:?} is refused as a path rather than as a missing file: {refused}"
        );
    }

    let unknown = index
        .file("crate-a/src/absent.rs")
        .expect_err("a normalized path the index never admitted is unknown");
    assert!(
        matches!(unknown, CodeIntelligenceError::UnknownFile { .. }),
        "a normalized path that names nothing is unknown rather than an escape: {unknown}"
    );

    for spelling in ["/etc/passwd", "../outside/Cargo.toml"] {
        let refused = required(&repository, &[rust_manifest(spelling)])
            .expect_err("an authority path that leaves the root is fatal");
        assert!(
            matches!(refused, CodeIntelligenceError::PathEscape { .. }),
            "{spelling:?} is refused before the manifest is opened: {refused}"
        );
    }

    outside_symlinks_are_refused();
    an_outside_target_is_refused_without_being_read();
    a_name_with_no_utf8_spelling_is_refused();
    a_backslash_name_cannot_collide_with_a_normalized_path();
}

/// A host filename containing `\` never becomes an index key.
fn a_backslash_name_cannot_collide_with_a_normalized_path() {
    #[cfg(unix)]
    {
        let repository = Repository::of(&[("a\\b.py", "def hidden():\n    pass\n")]);
        let state = indexed(&repository);
        assert!(state.index().files().is_empty());
        assert!(state.issues().iter().any(|issue| {
            issue.code() == IssueCode::PathEscape && issue.stage() == IssueStage::Confinement
        }));
    }
}

/// The refusal happens before the read, and the operating system is the
/// witness.
///
/// The target outside the root is a directory, so an index that resolved the
/// link and then opened it would come back with a read failure instead of an
/// escape. Asserting the escape is therefore asserting the order, not only the
/// classification.
///
/// A directory rather than a file no mode bits let this process read: mode bits
/// do not apply to every user, so a permission witness is one a privileged host
/// silently fails to make. No host and no user reads a directory as a source
/// file, so this row witnesses the order everywhere it runs at all.
fn an_outside_target_is_refused_without_being_read() {
    let outside = Repository::of(&[OUTSIDE]);
    let repository = linked_to(outside.root());

    let state = indexed(&repository);
    assert_eq!(
        &*paths(&state),
        [KEPT_ONLY.0],
        "the linked source is not admitted"
    );
    let refusal = state
        .issues()
        .iter()
        .find(|issue| issue.scope().name() == "linked.py")
        .expect("the link is recorded");
    assert_eq!(
        refusal.code(),
        IssueCode::SymlinkEscape,
        "a target no process can read as a source is still refused as an escape, so nothing opened it: {}",
        refusal.message()
    );
    assert_eq!(
        refusal.stage(),
        IssueStage::Confinement,
        "at the stage that runs before any read"
    );
}

/// A name beneath the root with no UTF-8 spelling is refused, and the rest of
/// the repository still answers.
///
/// Only where the host has such names to offer: APFS and NTFS reject the byte
/// sequence outright, and a repository that cannot hold the name cannot state
/// the case. Both worlds are asserted — either the name is there and the index
/// refuses it, or the host refused it and the tree holds no name the index
/// could have keyed — so neither branch passes on an assertion it never made.
fn a_name_with_no_utf8_spelling_is_refused() {
    let repository = Repository::of(&[KEPT_ONLY]);
    let Some(name) = repository.write_unspellable("py") else {
        assert_eq!(
            &*spelled_names(repository.root()),
            [KEPT_ONLY.0],
            "a host that refused the name holds none of it, so there is nothing to refuse"
        );
        return;
    };

    let state = indexed(&repository);
    assert_eq!(
        &*paths(&state),
        [KEPT_ONLY.0],
        "a path the index cannot key is a path it does not admit"
    );
    let refusal = state
        .issues()
        .iter()
        .find(|issue| issue.code() == IssueCode::PathEncoding)
        .unwrap_or_else(|| {
            panic!(
                "{name} is recorded rather than dropped: {:?}",
                issue_rows(&state)
            )
        });
    assert_eq!(
        refusal.stage(),
        IssueStage::Confinement,
        "refused before anything opened it"
    );
    assert!(
        !refusal.scope().name().contains(':'),
        "and named by its place beneath the root rather than by the root's own spelling: {}",
        refusal.scope().name()
    );
}

/// Every entry directly beneath `root`, sorted, as the host spells it.
///
/// A name with no UTF-8 spelling is rendered lossily rather than skipped, so a
/// directory that holds one cannot be mistaken here for a directory that does
/// not.
///
/// Boxed rather than a `Vec`, like every other list this tree hands back: the
/// buffer is mutable only while it is being sorted, and the one caller compares
/// it and drops it.
fn spelled_names(root: &Path) -> Box<[String]> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .expect("the fixture root is readable")
        .map(|entry| {
            entry
                .expect("the fixture entry is readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names.into_boxed_slice()
}

/// One repository holding a Python source and a link at `linked.py` to
/// `target`.
///
/// A host that will not create the link fails here rather than returning a
/// repository without one. Both callers are about what the index does with a
/// link, so a fixture holding no link states neither claim, and this plan makes
/// unsupported symlink creation a setup failure rather than a skip.
fn linked_to(target: &Path) -> Repository {
    let repository = Repository::of(&[KEPT_ONLY]);
    assert!(
        repository.symlink("linked.py", target),
        "the host must create the symbolic link this row is about"
    );
    repository
}

/// A symlink whose target leaves the root is refused, and its manifest form is
/// fatal.
///
/// A readable target, unlike the ordering row above: this row is the
/// classification claim, and a link the index could have followed is the one
/// that states it.
fn outside_symlinks_are_refused() {
    let outside = Repository::of(&[OUTSIDE]);
    let repository = linked_to(&outside.root().join(OUTSIDE.0));

    let state = indexed(&repository);
    assert_eq!(
        &*paths(&state),
        [KEPT_ONLY.0],
        "an outside-root symlink is never admitted"
    );
    assert!(
        state.issues().iter().any(|issue| {
            issue.scope().name() == "linked.py" && issue.code() == IssueCode::SymlinkEscape
        }),
        "and the refusal is recorded rather than silent: {:?}",
        issue_rows(&state)
    );

    let manifest = outside.root().join("Cargo.toml");
    std::fs::write(
        &manifest,
        "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
    )
    .expect("the outside manifest is written");
    assert!(
        repository.symlink("linked-manifest.toml", &manifest),
        "a host that created the source link creates this one too"
    );
    let refused = required(&repository, &[rust_manifest("linked-manifest.toml")])
        .expect_err("an authority reached through an outside symlink is fatal");
    assert!(
        matches!(refused, CodeIntelligenceError::SymlinkEscape { .. }),
        "the link is resolved and refused before the manifest is read: {refused}"
    );
}
