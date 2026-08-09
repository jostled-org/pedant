//! Contract tests for every `pedant-snippet` interface.
//!
//! This root owns the library boundary, the spawned CLI, and the real stdio MCP
//! server. It stays the crate's only integration executable: the fixtures, the
//! bounded child harness, and both transport journeys reach it through `#[path]`
//! support modules, which Cargo links into this same binary instead of a second
//! one.
//!
//! All three interfaces answer one table, `cases::cases` and `cases::FAILURES`.
//! Each asserts against the same expected declaration and the same expected
//! envelope bytes, so parity is a property of one statement of the facts rather
//! than of three copies agreeing.

#[path = "interfaces_support/cases.rs"]
mod cases;

#[path = "interfaces_support/child.rs"]
mod child;

#[path = "interfaces_support/cli.rs"]
mod cli;

#[path = "interfaces_support/mcp.rs"]
mod mcp;

#[path = "interfaces_support/mcp_journey.rs"]
mod mcp_journey;

mod library {
    use std::io::ErrorKind;

    use pedant_snippet::{Extraction, SnippetError, extract_path};

    use crate::cases::{self, Source, Tree};

    #[test]
    fn extract_path_contract() {
        let tree = Tree::new().expect("temporary fixture tree");

        for case in cases::cases() {
            let extracted = extract_path(&tree.resolve(case.source), case.at)
                .unwrap_or_else(|error| panic!("{}: {error}", case.label));
            assert_eq!(extracted, case.unit, "{}", case.label);

            let rendered = Extraction { unit: extracted }
                .to_json()
                .expect("the extraction serializes");
            assert_eq!(
                &*rendered, case.envelope,
                "{}: the library renders the envelope both transports send",
                case.label
            );
            let restored: Extraction = serde_json::from_str(&rendered)
                .unwrap_or_else(|error| panic!("{}: {rendered:?} parses: {error}", case.label));
            assert_eq!(
                restored.unit, case.unit,
                "{}: the envelope round trips",
                case.label
            );
        }

        for failure in &cases::FAILURES {
            let path = tree.resolve(failure.source);
            let error = extract_path(&path, cases::present_point()).expect_err(failure.label);
            let message = error.to_string();
            match error {
                SnippetError::Read {
                    path: reported,
                    source,
                } => {
                    assert_eq!(
                        &*reported,
                        path.as_path(),
                        "{}: the error keeps the caller's spelling",
                        failure.label
                    );
                    // Nothing canonicalizes the caller's path, so a committed
                    // row comes back relative and a fixture row comes back
                    // under its temporary root. Asserted on what the library
                    // returned, and in both directions: a `Tree` that started
                    // absolutizing committed rows, and a library that resolved
                    // a relative one, each fail here.
                    assert_eq!(
                        matches!(failure.source, Source::Committed(_)),
                        reported.is_relative(),
                        "{}: the returned path keeps the caller's form: {}",
                        failure.label,
                        reported.display()
                    );
                    assert_eq!(
                        source.kind(),
                        failure.kind,
                        "{}: the I/O kind reaches the caller",
                        failure.label
                    );
                    // The reason text is the operating system's, and this
                    // assertion runs in the test runner's own locale rather
                    // than the `LC_ALL=C` every spawned child gets. Composition
                    // is the claim that holds in any locale, and it is the one
                    // the two child journeys cannot make: the outer message
                    // carries the cause verbatim.
                    assert!(
                        message.contains(&source.to_string()),
                        "{}: the message carries the I/O cause: {message}",
                        failure.label
                    );
                }
            }
            assert!(
                message.contains(&*path.display().to_string()),
                "{}: the message names the path: {message}",
                failure.label
            );
        }
    }

    /// Bytes that are not UTF-8 fail the read; malformed source does not.
    ///
    /// Both rows already state their own outcome, and this test restates
    /// neither: it names them and asserts the one thing a row cannot, that the
    /// two sit on opposite sides of the boundary. Source that never decodes
    /// never reaches the parser; malformed source is read and then found to
    /// hold no declaration.
    ///
    /// The `InvalidData` kind is spelled here rather than taken from the row,
    /// so reordering [`cases::FAILURES`] fails this test instead of quietly
    /// swapping the contrast for a different one.
    #[test]
    fn invalid_utf8_is_read_failure() {
        let tree = Tree::new().expect("temporary fixture tree");

        let undecodable = &cases::FAILURES[1];
        let failed = extract_path(&tree.resolve(undecodable.source), cases::present_point())
            .expect_err(undecodable.label);
        let SnippetError::Read { source, .. } = failed;
        assert_eq!(
            source.kind(),
            ErrorKind::InvalidData,
            "{}: source that never decodes never reaches the parser",
            undecodable.label
        );

        let malformed = cases::malformed_case();
        let read = extract_path(&tree.resolve(malformed.source), malformed.at)
            .unwrap_or_else(|error| panic!("{}: {error}", malformed.label));
        assert_eq!(
            read, malformed.unit,
            "{}: the parser rejecting source is absence, not failure",
            malformed.label
        );
    }
}

/// The shared `Language` enum gains Rust, and it names the grammar this crate
/// already links.
///
/// The token is asserted here because `pedant-snippet` links the same syntax
/// substrate every transport reads. Only the token is asserted: the extraction,
/// the envelope, and the round trip are the table's own claims, which
/// [`library::extract_path_contract`] and both transport journeys already run
/// over every case.
#[test]
fn rust_snippet_interfaces_remain_unchanged() {
    use pedant_syntax::{Language, SyntaxLanguage};

    assert_eq!(
        SyntaxLanguage::from(Language::Rust),
        SyntaxLanguage::Rust,
        "the shared Rust token selects the Rust grammar this crate already links"
    );
}
