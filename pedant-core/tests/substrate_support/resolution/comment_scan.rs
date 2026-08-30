//! Which bytes of one Rust source are code, and which are prose.
//!
//! Every negative claim written as a text search needs this. A module that
//! explains why it opens no socket names the socket, and a scan that refused it
//! would push the reasoning out of the code that needs it — so the prose has to
//! be skipped. Skipping it by line shape does not work in either direction: the
//! reading that dropped every line beginning with `*` dropped `*guard = …` with
//! the continuation lines of a block comment, and the reading that kept every
//! line not beginning with `//` searched the trailing comment on the end of a
//! statement as though it were code.
//!
//! So the comments are removed as the language defines them, and the literals
//! are read for exactly one reason: a `"/*"` inside a string opens no comment,
//! and a reader that thought it did would blank the rest of the file and report
//! every claim over it satisfied.
//!
//! Blanked rather than deleted. A comment's bytes become spaces and its
//! newlines stay, so a line number in a failure is the line number in the file.

use super::comment_spans::without_comments;

/// One line of code, paired with the one-based number it holds in its file.
///
/// The number travels with the text because a failure names a line, and the
/// index has already dropped the prose lines between them — so a position in
/// the index is not a position in the file.
pub(crate) type CodeLine = (usize, Box<str>);

/// Every line of one source that carries code, paired with its one-based
/// number, with every comment removed.
///
/// A line whose whole content was prose is dropped rather than kept empty: its
/// callers ask whether a spelling is stated, and a blank line states nothing.
///
/// An index with no line at all refuses, the way every sibling reader in this
/// tree refuses an empty answer. The callers here write negative claims — no
/// module of this product names that route, no source outside the owner states
/// that spelling — and an empty index satisfies every one of them without
/// reading a byte. A Rust source states at least one code line, so an index
/// that holds none is a reading fault rather than a clean scan.
pub(crate) fn code_index(text: &str) -> Box<[CodeLine]> {
    let index: Box<[CodeLine]> = without_comments(text)
        .lines()
        .enumerate()
        .map(|(offset, line)| (offset + 1, line.trim_end()))
        .filter(|(_, line)| !line.is_empty())
        .map(|(number, line)| (number, line.into()))
        .collect();
    assert!(
        !index.is_empty(),
        "this reader found no code line in a {} byte source, so every negative claim over it \
         passes unread",
        text.len()
    );
    index
}

const FIXTURE: &str = r##"//! module prose naming fs::write
/// item prose naming Command::new
fn kept() {
    let held = "/* not a comment */"; // trailing prose naming TcpStream
    *guard = held;
}
/* block prose naming reqwest
 * continued prose naming UdpSocket
 */
fn also_kept() {
    let raw = r#"*/ // still a string"#;
    let tick = '/';
    take(raw, tick);
}
"##;

/// The one-based numbers of the fixture's code lines.
const FIXTURE_CODE_LINES: [usize; 9] = [3, 4, 5, 6, 10, 11, 12, 13, 14];

/// Every spelling the fixture states only in prose.
const FIXTURE_PROSE: [&str; 5] = [
    "fs::write",
    "Command::new",
    "TcpStream",
    "reqwest",
    "UdpSocket",
];

/// The reader keeps every line of code and no line of prose.
///
/// Both halves are the claim, and each is a way a negative scan built on this
/// goes quiet. A reader that kept prose turns a module explaining why it opens
/// no socket into an offender; a reader that dropped code — the `*`-leading
/// deref, or everything after a string that looks like a comment opener — lets a
/// real `fs::write` through and reports the module clean.
#[test]
fn comment_scan_keeps_every_line_of_code_and_no_line_of_prose() {
    let scanned = code_index(FIXTURE);
    let numbers: Box<[usize]> = scanned.iter().map(|(number, _)| *number).collect();
    assert_eq!(
        &*numbers, &FIXTURE_CODE_LINES,
        "the reader must keep exactly the fixture's code lines"
    );

    let kept: String = scanned
        .iter()
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    for prose in FIXTURE_PROSE {
        assert!(
            !kept.contains(prose),
            "{prose} is stated only in prose, and the reader kept it: {kept}"
        );
    }
    for code in [
        "*guard = held;",
        "let held = \"/* not a comment */\";",
        "let raw = r#\"*/ // still a string\"#;",
        "let tick = '/';",
        "take(raw, tick);",
    ] {
        assert!(
            kept.contains(code),
            "the reader dropped the code line [{code}]: {kept}"
        );
    }
}
