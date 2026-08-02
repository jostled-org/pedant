//! The fixture sources every interface case reads, the temporary tree that owns
//! them, and the one table all three interfaces answer.
//!
//! The library, CLI, and MCP journeys report the same outcomes — present,
//! absent, malformed, unsupported, and unreadable — so every fixture, location,
//! expected declaration, and expected envelope is stated once here. Each
//! interface iterates [`cases`] and [`FAILURES`] rather than keeping a second
//! copy of a case, so the three cannot disagree about an answer.

use std::io::ErrorKind;
use std::path::PathBuf;

use pedant_snippet::{LineSpan, Location, SourceUnit, SourceUnitKind};
use tempfile::TempDir;

/// The one tool name the MCP transport lists and dispatches.
pub const TOOL: &str = "enclosing_unit";

/// The description `tools/list` carries for [`TOOL`].
///
/// Written down rather than read from the private constant the server serves.
/// A test that reads the served text compares it against itself, and an edit
/// would then pass while every client's tool picker reads something new.
pub const TOOL_DESCRIPTION: &str = "Return the source declaration enclosing one file location";

/// What the CLI's text format prints when no declaration holds the location.
///
/// A present declaration prints its exact bytes and nothing more, so the
/// terminator belongs to this sentence alone.
pub const NO_UNIT: &str = "no enclosing unit\n";

/// The envelope every absent outcome serializes to.
///
/// Stated as bytes rather than derived: absence is an explicit `null`, never a
/// missing field, and every absent [`Case`] carries this exact text.
pub const ABSENT_ENVELOPE: &str = r#"{"unit":null}"#;

/// The envelope every present case serializes to.
///
/// Every envelope in this table is a literal. Deriving one through
/// `Extraction::to_json` would make the library's serialization assertion
/// compare that function against itself, and a field rename would pass on all
/// three interfaces at once.
pub const PRESENT_ENVELOPE: &str = r#"{"unit":{"kind":"method","name":"retries","span":{"start":6,"end":8},"text":"fn retries(&self) -> usize {\n        self.retries\n    }"}}"#;

/// The envelope [`RELATIVE_SOURCE`] serializes to at [`RELATIVE_LINE`].
pub const RELATIVE_ENVELOPE: &str = r#"{"unit":{"kind":"function","name":"build","span":{"start":1,"end":2},"text":"def build(count):\n    return count + 1"}}"#;

/// A Rust file whose method is the declaration every present case expects.
pub const PRESENT_FILE: &str = "present.rs";

/// The source [`PRESENT_FILE`] holds.
pub const PRESENT_SOURCE: &str = "struct Config {\n    retries: usize,\n}\n\nimpl Config {\n    fn retries(&self) -> usize {\n        self.retries\n    }\n}\n";

/// The byte-exact text the present declaration returns.
pub const PRESENT_TEXT: &str = "fn retries(&self) -> usize {\n        self.retries\n    }";

/// A line inside the present declaration's body.
pub const PRESENT_LINE: usize = 7;

/// The one-based byte column of `self` on [`PRESENT_LINE`].
pub const PRESENT_COLUMN: usize = 9;

/// A column past every byte on [`PRESENT_LINE`].
///
/// The line resolves a declaration without a column and none with this one, so
/// an interface that drops the column answers present where the table says
/// absent. Nothing else in this table makes a supplied column decide an answer.
pub const PAST_COLUMN: usize = 99;

/// The one-based inclusive line span of the present declaration.
pub const PRESENT_SPAN: LineSpan = LineSpan { start: 6, end: 8 };

/// The blank line between [`PRESENT_FILE`]'s two declarations.
pub const ABSENT_LINE: usize = 4;

/// A Python file whose parse fails, leaving an error node in the recovery tree
/// beside a declaration the grammar did recognize.
pub const MALFORMED_FILE: &str = "malformed.py";

/// The source [`MALFORMED_FILE`] holds: one clean function, one broken one.
pub const MALFORMED_SOURCE: &str = "def good(value):\n    return value\n\ndef broken(:\n    pass\n";

/// A line inside [`MALFORMED_FILE`]'s clean function.
///
/// Extraction still answers absent here: an error-bearing tree offers no
/// declaration, and that absence is a success on every interface.
pub const MALFORMED_LINE: usize = 2;

/// A file whose extension names no syntax language.
pub const UNSUPPORTED_FILE: &str = "notes.txt";

/// The source [`UNSUPPORTED_FILE`] holds.
pub const UNSUPPORTED_SOURCE: &str = "check the release order\n";

/// A file whose bytes are not UTF-8.
pub const INVALID_UTF8_FILE: &str = "invalid.rs";

/// The bytes [`INVALID_UTF8_FILE`] holds: valid Rust followed by one stray byte.
pub const INVALID_UTF8_BYTES: &[u8] = b"struct Config {\n    retries: usize,\n}\n\xff\n";

/// A relative path no fixture creates.
pub const MISSING_RELATIVE: &str = "does/not/exist.rs";

/// A committed fixture, named relative to the package root the test runs in.
pub const RELATIVE_SOURCE: &str = "tests/fixtures/relative_source.py";

/// A line inside [`RELATIVE_SOURCE`]'s function.
pub const RELATIVE_LINE: usize = 2;

/// The one-based inclusive line span of [`RELATIVE_SOURCE`]'s function.
pub const RELATIVE_SPAN: LineSpan = LineSpan { start: 1, end: 2 };

/// The byte-exact text [`RELATIVE_SOURCE`]'s function returns.
pub const RELATIVE_TEXT: &str = "def build(count):\n    return count + 1";

/// The I/O reason a missing path reports.
///
/// `std::io::Error`'s `Display` is `strerror_r` on unix, which translates under
/// `LC_MESSAGES`. Every child [`crate::child`] spawns runs with `LC_ALL=C`, so
/// the CLI and MCP journeys read this text by construction. The in-process
/// library journey inherits the test runner's own environment, so it asserts
/// that the message carries its own `source` verbatim rather than reading this
/// text — a claim that holds in every locale.
pub const MISSING_REASON: &str = "No such file or directory";

/// The I/O reason bytes that are not UTF-8 report.
pub const INVALID_UTF8_REASON: &str = "stream did not contain valid UTF-8";

/// A committed directory, named relative to the package root.
///
/// A caller naming a folder is the third way a read fails, and the one an MCP
/// client reaches by completing a path.
pub const FIXTURE_DIRECTORY: &str = "tests/fixtures";

/// The I/O reason a directory reports.
///
/// `EISDIR` is 21 on every platform this workspace builds for, and every child
/// runs under `LC_ALL=C`, so both transports read this text.
pub const DIRECTORY_REASON: &str = "Is a directory";

/// Where every present case reads its source.
///
/// Named beside [`present_point`] so a journey replaying the present case states
/// the file and the point without building a whole [`Case`] to read two fields.
pub const PRESENT_AT: Source = Source::Fixture(PRESENT_FILE);

/// Where one case's source file lives.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// A fixture [`Tree`] writes into its own temporary root.
    Fixture(&'static str),
    /// A committed path, spelled relative to the package root Cargo makes the
    /// working directory of the test and of every child it spawns.
    Committed(&'static str),
}

/// One question every interface answers the same way.
pub struct Case {
    /// What this case proves, for assertion messages.
    pub label: &'static str,
    /// The file to read.
    pub source: Source,
    /// The location to resolve.
    pub at: Location,
    /// The declaration the library returns.
    pub unit: Option<SourceUnit>,
    /// The exact envelope the CLI prints and the MCP tool sends.
    ///
    /// Static text, because every envelope in this table is written down rather
    /// than built: a case states an expectation it never edits.
    pub envelope: &'static str,
}

/// One file no interface can read.
///
/// Extraction has exactly one failure mode and three triggers; all three appear
/// here so every interface proves it reports each one.
pub struct FailureCase {
    /// What this case proves, for assertion messages.
    pub label: &'static str,
    /// The file to read.
    pub source: Source,
    /// The kind the library's `io::Error` carries.
    pub kind: ErrorKind,
    /// The reason text every interface's message carries.
    pub reason: &'static str,
}

/// Every unreadable file, stated once for all three interfaces.
pub static FAILURES: [FailureCase; 3] = [
    FailureCase {
        label: "a missing relative path",
        source: Source::Committed(MISSING_RELATIVE),
        kind: ErrorKind::NotFound,
        reason: MISSING_REASON,
    },
    FailureCase {
        label: "bytes that are not UTF-8",
        source: Source::Fixture(INVALID_UTF8_FILE),
        kind: ErrorKind::InvalidData,
        reason: INVALID_UTF8_REASON,
    },
    FailureCase {
        label: "a directory rather than a file",
        source: Source::Committed(FIXTURE_DIRECTORY),
        kind: ErrorKind::IsADirectory,
        reason: DIRECTORY_REASON,
    },
];

/// Every row of a table produced exactly one outcome.
///
/// Pairing a run with its row at construction settles which row an outcome
/// belongs to; it cannot settle how many ran. A journey that skips a row
/// collects a shorter vector, and an assertion loop over that vector runs one
/// row short and reports clean — the same silent narrowing `zip` gave when the
/// two were separate arrays. Counted against the table, a dropped row fails
/// here.
pub fn assert_every_row_ran(rows: usize, outcomes: usize, interface: &str) {
    assert_eq!(rows, outcomes, "{interface}: every row of the table ran");
}

/// Every fragment a failure's message must carry, named for one interface.
///
/// One claim about one string, stated here rather than in each journey: the
/// message names the path the caller supplied and it carries the I/O reason.
/// The CLI reads it off stderr and the MCP tool off its one content block, so
/// each supplies its own text and its own label — and the two interfaces cannot
/// disagree about what a failure has to say, which is why this table exists.
pub fn assert_carries(text: &str, failure: &FailureCase, path: &str, label: &str) {
    for fragment in [path, failure.reason] {
        assert!(
            text.contains(fragment),
            "{label}: names {fragment:?}: {text}"
        );
    }
}

/// The point every present case resolves.
pub fn present_point() -> Location {
    Location {
        line: PRESENT_LINE,
        column: Some(PRESENT_COLUMN),
    }
}

/// The present case, resolved by exact point.
///
/// Named rather than reached by index because two journeys replay it on their
/// own terms: the CLI runs it with no `--format`, and the MCP server answers it
/// with stdin already closed.
pub fn present_case() -> Case {
    case(
        "byte column inside a method",
        PRESENT_AT,
        present_point(),
        Some(present_unit()),
        PRESENT_ENVELOPE,
    )
}

/// The malformed-source case, resolved by name.
///
/// Named rather than reached by index because `invalid_utf8_is_read_failure`
/// replays it as the absence half of its contrast: this source is read, then
/// found to hold no declaration.
pub fn malformed_case() -> Case {
    absent(
        "a recovered declaration under a parse error",
        Source::Fixture(MALFORMED_FILE),
        MALFORMED_LINE,
    )
}

/// Every outcome extraction reports as success.
pub fn cases() -> [Case; 9] {
    [
        present_case(),
        case(
            "line-only containment",
            Source::Fixture(PRESENT_FILE),
            Location {
                line: PRESENT_LINE,
                column: None,
            },
            Some(present_unit()),
            PRESENT_ENVELOPE,
        ),
        // The one case a supplied column decides. Every other present case
        // answers the same with the column and without it, so an interface that
        // dropped the column on the floor would pass the whole table.
        absent_at(
            "a byte column past the line",
            PRESENT_AT,
            Location {
                line: PRESENT_LINE,
                column: Some(PAST_COLUMN),
            },
        ),
        absent(
            "no declaration on the line",
            Source::Fixture(PRESENT_FILE),
            ABSENT_LINE,
        ),
        absent("zero line", Source::Fixture(PRESENT_FILE), 0),
        absent("line past the source", Source::Fixture(PRESENT_FILE), 99),
        absent(
            "unsupported extension",
            Source::Fixture(UNSUPPORTED_FILE),
            1,
        ),
        malformed_case(),
        case(
            "relative path resolved from the working directory",
            Source::Committed(RELATIVE_SOURCE),
            Location {
                line: RELATIVE_LINE,
                column: None,
            },
            Some(relative_unit()),
            RELATIVE_ENVELOPE,
        ),
    ]
}

/// One case, stating both the declaration and the exact bytes it serializes to.
///
/// `envelope` is a literal rather than `Extraction::to_json` of `unit`, so the
/// library's serialization assertion compares the renderer against written-down
/// bytes instead of against itself.
fn case(
    label: &'static str,
    source: Source,
    at: Location,
    unit: Option<SourceUnit>,
    envelope: &'static str,
) -> Case {
    Case {
        label,
        source,
        at,
        unit,
        envelope,
    }
}

/// One line-only case every interface answers with [`ABSENT_ENVELOPE`].
fn absent(label: &'static str, source: Source, line: usize) -> Case {
    absent_at(label, source, Location { line, column: None })
}

/// One case at an exact location, answered with [`ABSENT_ENVELOPE`].
fn absent_at(label: &'static str, source: Source, at: Location) -> Case {
    Case {
        label,
        source,
        at,
        unit: None,
        envelope: ABSENT_ENVELOPE,
    }
}

/// The declaration every present case expects.
fn present_unit() -> SourceUnit {
    SourceUnit {
        kind: SourceUnitKind::Method,
        name: Some("retries".into()),
        span: PRESENT_SPAN,
        text: PRESENT_TEXT.into(),
    }
}

/// The declaration [`RELATIVE_SOURCE`] returns at [`RELATIVE_LINE`].
fn relative_unit() -> SourceUnit {
    SourceUnit {
        kind: SourceUnitKind::Function,
        name: Some("build".into()),
        span: RELATIVE_SPAN,
        text: RELATIVE_TEXT.into(),
    }
}

/// A temporary root holding every fixture file, removed when it drops.
pub struct Tree {
    root: TempDir,
}

impl Tree {
    /// Write every fixture into a fresh temporary root.
    ///
    /// A root that is not UTF-8 fails here, before any child is spawned, because
    /// [`Tree::argument`] spells a path for a command line and runs while a
    /// server is live.
    pub fn new() -> std::io::Result<Self> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join(PRESENT_FILE), PRESENT_SOURCE)?;
        std::fs::write(root.path().join(MALFORMED_FILE), MALFORMED_SOURCE)?;
        std::fs::write(root.path().join(UNSUPPORTED_FILE), UNSUPPORTED_SOURCE)?;
        std::fs::write(root.path().join(INVALID_UTF8_FILE), INVALID_UTF8_BYTES)?;
        match root.path().to_str() {
            Some(_) => Ok(Self { root }),
            None => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "the temporary root is not UTF-8",
            )),
        }
    }

    /// The path `source` names, resolved against this tree.
    pub fn resolve(&self, source: Source) -> PathBuf {
        match source {
            Source::Fixture(name) => self.root.path().join(name),
            Source::Committed(path) => PathBuf::from(path),
        }
    }

    /// The path `source` names, spelled for a command line or a JSON argument.
    ///
    /// Spelled through `to_str`, not `display`: a lossy conversion would hand a
    /// child a path [`Tree::resolve`] never names, and every assertion comparing
    /// the two would then compare bytes the binary never saw.
    pub fn argument(&self, source: Source) -> Box<str> {
        let path = self.resolve(source);
        path.to_str().expect("the fixture path is UTF-8").into()
    }
}
