//! What a Go snapshot refuses to publish.
//!
//! Capability detection keeps findings from a recovery tree beside an
//! unavailable attribution status, because a partial answer is still security
//! evidence. A resolution snapshot cannot: a missing declaration there becomes
//! a missing definition in a report and a missing node in a graph. So every
//! source a snapshot admits is readable, UTF-8, completely parsed, and states a
//! package clause its directory agrees with.

use pedant_core::resolution::go::{GoResolutionLimits, GoSnapshotError, GoSourceDefect};
use pedant_syntax::SyntaxLanguage;
use pedant_syntax::tree_sitter::parse_bound;

use crate::resolution::fixture::{FixtureFile, build_repository, repository_root};
use crate::resolution::go::fixture::{snapshot, snapshot_refusal};
use crate::resolution::go::snapshot_fixtures::MINIMAL;

/// One row: what the tree states, and the refusal it is owed.
struct RecoveryRow {
    subject: &'static str,
    files: &'static [FixtureFile],
    variant: &'static str,
    message: &'static str,
}

/// Every source defect that must publish no snapshot.
const ROWS: &[RecoveryRow] = &[
    RecoveryRow {
        subject: "a source the parser recovered from",
        files: &[
            ("repo/go.mod", "module example.com/broken\n"),
            ("repo/broken.go", "package broken\n\nfunc Run( {\n"),
        ],
        variant: "IncompleteSource:Recovered",
        message: "the parser recovered from a syntax error",
    },
    RecoveryRow {
        subject: "a source stating no package clause",
        files: &[
            ("repo/go.mod", "module example.com/clauseless\n"),
            ("repo/clauseless.go", "// only a comment\n"),
        ],
        variant: "MissingPackageClause",
        message: "states no package clause",
    },
    RecoveryRow {
        subject: "two package clauses in one directory",
        files: &[
            ("repo/go.mod", "module example.com/split\n"),
            ("repo/first.go", "package first\n"),
            ("repo/second.go", "package second\n"),
        ],
        variant: "ConflictingPackageClause",
        message: "declares both first and second",
    },
    RecoveryRow {
        subject: "a test file naming an unrelated package",
        files: &[
            ("repo/go.mod", "module example.com/stray\n"),
            ("repo/stray.go", "package stray\n"),
            ("repo/stray_test.go", "package unrelated\n"),
        ],
        variant: "ConflictingPackageClause",
        message: "declares both stray and unrelated",
    },
];

/// 4.T6 (Invariant 3): a Go snapshot accepts only an error-free, complete Go
/// source inventory and publishes nothing when any source is incomplete.
#[test]
fn go_capability_fallback_and_snapshot_recovery_contract_is_exact() {
    for row in ROWS {
        let refused = snapshot_refusal(row.files, GoResolutionLimits::default());
        assert_eq!(
            variant_of(&refused),
            row.variant,
            "{}: expected a {} refusal, got {refused:?}",
            row.subject,
            row.variant
        );
        let text = refused.to_string();
        assert!(
            text.contains(row.message),
            "{}: refusal text {text:?} should state {:?}",
            row.subject,
            row.message
        );
    }

    assert_non_utf8_source_is_refused();
    assert_unreadable_source_is_refused();
    assert_the_parser_failed_defect_is_unreachable();

    let (tree, taken) = snapshot(MINIMAL, GoResolutionLimits::default());
    assert!(
        taken.is_ok(),
        "the complete baseline still snapshots: {taken:?}"
    );
    drop(tree);
}

/// No fixture can state the parser-failed defect, and the claim is that fact
/// rather than a missing row.
///
/// `parse_bound` answers `None` for two absences: a grammar this build does not
/// link, and a linked grammar that produced no tree. A `go-resolution` build
/// links the Go grammar, and tree-sitter answers every readable UTF-8 source
/// with a tree — a source it cannot make sense of comes back recovered, not
/// absent. So `Unparsed` guards the grammar-absent build the snapshot path
/// never runs in, and `Recovered` is the incomplete-parse refusal a Go build
/// reaches. Both halves are required here: every source a row states binds a
/// tree, and the two defects stay distinguishable, so a defect that later
/// became reachable could not pass as the one already proven.
fn assert_the_parser_failed_defect_is_unreachable() {
    let stated = ROWS
        .iter()
        .flat_map(|row| row.files.iter().map(move |file| (row.subject, file)))
        .filter(|(_, (path, _))| path.ends_with(".go"));
    for (subject, (path, text)) in stated {
        assert!(
            parse_bound(text, SyntaxLanguage::Go).is_some(),
            "{subject}: {path} binds a tree, so its refusal is the recovered defect"
        );
    }
    assert_ne!(
        GoSourceDefect::Unparsed.to_string(),
        GoSourceDefect::Recovered.to_string(),
        "the two incomplete-parse defects must state different causes"
    );
}

/// A source that is not UTF-8 is refused before its bytes become text.
fn assert_non_utf8_source_is_refused() {
    let tree = build_repository(&[("repo/go.mod", "module example.com/binary\n")], false);
    crate::resolution::fixture::write_file(tree.path(), "repo/binary.go", &[0xff, 0xfe, 0x00]);
    let refused = refusal_at(&tree);
    assert_eq!(
        variant_of(&refused),
        "NonUtf8Source",
        "a non-UTF-8 source is refused as NonUtf8Source, got {refused:?}"
    );
    drop(tree);
}

/// A source the process cannot open is refused with its I/O cause.
#[cfg(unix)]
fn assert_unreadable_source_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let tree = build_repository(
        &[
            ("repo/go.mod", "module example.com/sealed\n"),
            ("repo/sealed.go", "package sealed\n"),
        ],
        false,
    );
    let path = tree.path().join("repo/sealed.go");
    let restore = std::fs::metadata(&path)
        .expect("the fixture source exists")
        .permissions();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("the fixture can seal its own source");

    let refused = refusal_at(&tree);
    std::fs::set_permissions(&path, restore).expect("the fixture restores its own source");
    assert_eq!(
        variant_of(&refused),
        "SourceRead",
        "an unreadable source is refused as SourceRead, got {refused:?}"
    );
    drop(tree);
}

/// A process running as root opens a mode-zero file, so the claim is carried by
/// the other rows where permissions are not a boundary.
#[cfg(not(unix))]
fn assert_unreadable_source_is_refused() {}

/// Load and snapshot the materialized tree, requiring a refusal.
fn refusal_at(tree: &tempfile::TempDir) -> GoSnapshotError {
    let project = pedant_core::resolution::go::GoProject::load(
        &repository_root(tree),
        GoResolutionLimits::default(),
    )
    .expect("the fixture should load");
    match project.snapshot_resolution() {
        Ok(snapshot) => panic!("the fixture should be refused, not snapshotted: {snapshot:?}"),
        Err(error) => error,
    }
}

/// The variant name one refusal carries, so a row states the shape it is owed
/// rather than only the words it renders.
///
/// The incomplete-source variant carries its defect too. One variant covers
/// both an unparsed source and a recovered one, and a row that could not tell
/// them apart would accept either for the other.
fn variant_of(error: &GoSnapshotError) -> &'static str {
    match error {
        GoSnapshotError::OutOfRoot { .. } => "OutOfRoot",
        GoSnapshotError::NonUtf8Path { .. } => "NonUtf8Path",
        GoSnapshotError::PathRead { .. } => "PathRead",
        GoSnapshotError::DirectoryRead { .. } => "DirectoryRead",
        GoSnapshotError::SourceRead { .. } => "SourceRead",
        GoSnapshotError::NonUtf8Source { .. } => "NonUtf8Source",
        GoSnapshotError::IncompleteSource {
            defect: GoSourceDefect::Unparsed,
            ..
        } => "IncompleteSource:Unparsed",
        GoSnapshotError::IncompleteSource {
            defect: GoSourceDefect::Recovered,
            ..
        } => "IncompleteSource:Recovered",
        GoSnapshotError::MissingPackageClause { .. } => "MissingPackageClause",
        GoSnapshotError::MissingStoredSource { .. } => "MissingStoredSource",
        GoSnapshotError::ConflictingPackageClause { .. } => "ConflictingPackageClause",
        GoSnapshotError::FactExtraction { .. } => "FactExtraction",
        GoSnapshotError::DirectoryEntryLimitExceeded { .. } => "DirectoryEntryLimitExceeded",
        GoSnapshotError::UnitLimitExceeded { .. } => "UnitLimitExceeded",
        GoSnapshotError::SourceFileLimitExceeded { .. } => "SourceFileLimitExceeded",
        GoSnapshotError::SourceBytesLimitExceeded { .. } => "SourceBytesLimitExceeded",
        GoSnapshotError::TotalSourceBytesLimitExceeded { .. } => "TotalSourceBytesLimitExceeded",
    }
}
