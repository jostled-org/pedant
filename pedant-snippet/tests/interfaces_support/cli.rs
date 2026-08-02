//! The spawned-CLI journey over the real binary.
//!
//! Every case comes from [`cases::cases`] and every failure from
//! [`cases::FAILURES`], so this journey states no outcome of its own: it proves
//! the CLI prints the shared envelope, byte for byte, for the same questions the
//! library and the MCP server answer.

use pedant_snippet::Location;

use crate::cases::{self, Case, FailureCase, Source, Tree};
use crate::child::{self, Failure, Output};

/// Every run this journey makes, collected before any assertion so no child is
/// live while a test panics.
///
/// Every run travels with the case that asked for it. An earlier draft kept
/// bare `Box<[Output]>` and paired each against the table with `zip` at the
/// assertion: `zip` stops at the shorter side and reports success, so one
/// skipped row narrowed the whole assertion and left the suite green. Pairing at
/// construction makes the mismatch unrepresentable rather than unlikely.
struct Journey<'a> {
    /// `--format json` for every case, in table order.
    json: Box<[(&'a Case, Output)]>,
    /// `--format text` for the same cases, in the same order.
    text: Box<[(&'a Case, Output)]>,
    /// The present case with no `--format` at all.
    default_format: Output,
    /// `--format json` for every unreadable file, in table order.
    json_failures: Box<[(&'a FailureCase, Output)]>,
    /// `--format text` for the same unreadable files, in the same order.
    text_failures: Box<[(&'a FailureCase, Output)]>,
    /// Every malformed command line, in [`REFUSALS`] order.
    refusals: Box<[(Refusal, Output)]>,
}

/// One command line clap must refuse, and a fragment its refusal names.
#[derive(Clone, Copy)]
struct Refusal {
    /// What this case proves, for assertion messages.
    label: &'static str,
    /// The arguments, exactly as a caller would spell them.
    arguments: &'static [&'static str],
    /// Text the refusal carries, so a run that exits 2 for another reason fails.
    reason: &'static str,
}

/// What the run with no `--format` proves.
///
/// One sentence, read twice by the same run: the case a failure names, and the
/// claim its assertion makes.
const DEFAULT_FORMAT_LABEL: &str = "an omitted --format is exactly --format json";

/// A misspelling of the optional `--column` flag.
///
/// One literal, read twice by the same case: the line a caller spells, and the
/// fragment its refusal must name.
const MISSPELLED_COLUMN: &str = "--colunm";

/// A subcommand this binary does not serve.
///
/// One literal, read twice by the same case, and the CLI's counterpart of the
/// MCP journey's unknown tool name.
const UNKNOWN_SUBCOMMAND: &str = "frobnicate";

/// Every malformed command line, refused before any file is opened.
///
/// The MCP transport refuses an unserved tool name, a missing argument, a
/// misspelled one, and a wrongly typed one as protocol errors; this is the CLI's
/// half of that parity, plus the format flag only this transport has. No path
/// here needs to exist: clap rejects the line before `extract` runs.
static REFUSALS: [Refusal; 5] = [
    Refusal {
        label: "an unknown subcommand",
        arguments: &[UNKNOWN_SUBCOMMAND],
        reason: UNKNOWN_SUBCOMMAND,
    },
    Refusal {
        label: "a missing --file",
        arguments: &["extract", "--line", "7"],
        reason: "--file",
    },
    Refusal {
        label: "a misspelled --column",
        arguments: &[
            "extract",
            "--file",
            "present.rs",
            "--line",
            "7",
            MISSPELLED_COLUMN,
            "9",
        ],
        reason: MISSPELLED_COLUMN,
    },
    Refusal {
        label: "a non-numeric --line",
        arguments: &["extract", "--file", "present.rs", "--line", "seven"],
        reason: "seven",
    },
    Refusal {
        label: "an unknown --format",
        arguments: &[
            "extract",
            "--file",
            "present.rs",
            "--line",
            "7",
            "--format",
            "yaml",
        ],
        reason: "yaml",
    },
];

/// Run every case in both formats, then every unreadable file.
async fn journey<'a>(tree: &Tree, cases: &'a [Case]) -> Result<Journey<'a>, Failure> {
    let mut json = Vec::with_capacity(cases.len());
    let mut text = Vec::with_capacity(cases.len());
    for case in cases {
        let as_json = extract_row(tree, case.source, case.at, "json", case.label).await?;
        let as_text = extract_row(tree, case.source, case.at, "text", case.label).await?;
        json.push((case, as_json));
        text.push((case, as_text));
    }

    let default_format = extract(tree, cases::PRESENT_AT, cases::present_point(), None)
        .await
        .map_err(|failure| failure.during(DEFAULT_FORMAT_LABEL, "no --format"))?;

    // Both formats, because the format decides how a result is printed, never
    // whether a read failure is one. Running json alone left the text path's
    // read failure unasserted on the only interface that has formats.
    let mut json_failures = Vec::with_capacity(cases::FAILURES.len());
    let mut text_failures = Vec::with_capacity(cases::FAILURES.len());
    for row in &cases::FAILURES {
        let at = cases::present_point();
        let as_json = extract_row(tree, row.source, at, "json", row.label).await?;
        let as_text = extract_row(tree, row.source, at, "text", row.label).await?;
        json_failures.push((row, as_json));
        text_failures.push((row, as_text));
    }

    let mut refusals = Vec::with_capacity(REFUSALS.len());
    for refusal in REFUSALS {
        let output = child::run(refusal.arguments)
            .await
            .map_err(|failure| failure.during(refusal.label, &refusal.arguments.join(" ")))?;
        refusals.push((refusal, output));
    }

    Ok(Journey {
        json: json.into(),
        text: text.into(),
        default_format,
        json_failures: json_failures.into(),
        text_failures: text_failures.into(),
        refusals: refusals.into(),
    })
}

/// One table row's `extract` run, named for the row that asked for it.
///
/// A journey that propagates with a bare `?` reports the operation and nothing
/// else, so every one of these runs fails with the same sentence. The fold names
/// the row and the format it ran under, and it runs on the error path only.
async fn extract_row(
    tree: &Tree,
    source: Source,
    at: Location,
    format: &str,
    label: &str,
) -> Result<Output, Failure> {
    extract(tree, source, at, Some(format))
        .await
        .map_err(|failure| failure.during(label, &format!("--format {format}")))
}

/// One `extract` run over the real binary.
///
/// The rendered numbers stay `String`: they are borrowed for one command line
/// and dropped here, so shrinking them to `Box<str>` would buy a reallocation
/// for a value nothing stores.
async fn extract(
    tree: &Tree,
    source: Source,
    at: Location,
    format: Option<&str>,
) -> Result<Output, Failure> {
    let path = tree.argument(source);
    let line = at.line.to_string();
    let column = at.column.map(|column| column.to_string());
    child::run(&arguments(&path, &line, column.as_deref(), format)).await
}

/// The `extract` arguments one run needs, omitting what the case leaves unset.
fn arguments<'a>(
    path: &'a str,
    line: &'a str,
    column: Option<&'a str>,
    format: Option<&'a str>,
) -> Box<[&'a str]> {
    let mut arguments = vec!["extract", "--file", path, "--line", line];
    if let Some(column) = column {
        arguments.extend(["--column", column]);
    }
    if let Some(format) = format {
        arguments.extend(["--format", format]);
    }
    arguments.into()
}

#[tokio::test]
async fn present_absent_and_unreadable_journey() {
    let tree = Tree::new().expect("temporary fixture tree");
    let cases = cases::cases();
    let journey = journey(&tree, &cases)
        .await
        .unwrap_or_else(|failure| panic!("every CLI run completes: {failure}"));

    assert_json_envelopes(&cases, &journey.json);
    assert_text_declarations(&cases, &journey.text);
    assert_default_is_json(&journey.default_format);
    assert_read_failures(&tree, &journey.json_failures, "json");
    assert_read_failures(&tree, &journey.text_failures, "text");
    assert_refusals(&journey.refusals);
}

/// Every malformed command line exits 2, prints no result, and names what was
/// wrong with it.
fn assert_refusals(outcomes: &[(Refusal, Output)]) {
    cases::assert_every_row_ran(REFUSALS.len(), outcomes.len(), "the refused command lines");
    for (refusal, output) in outcomes {
        // Exit 2, not merely non-zero: clap's usage status, distinct from the 1
        // an orderly read failure exits. A refusal that exited 1 would be
        // indistinguishable from a run that reached the file and could not
        // read it.
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}: a usage error exits 2: {:?}: {}",
            refusal.label,
            output.status,
            output.stderr
        );
        assert_eq!(
            &*output.stdout, "",
            "{}: a refusal prints no result",
            refusal.label
        );
        assert!(
            output.stderr.contains(refusal.reason),
            "{}: stderr names {:?}: {}",
            refusal.label,
            refusal.reason,
            output.stderr
        );
    }
}

/// Every `--format json` run prints the shared envelope and one newline.
fn assert_json_envelopes(cases: &[Case], outcomes: &[(&Case, Output)]) {
    cases::assert_every_row_ran(cases.len(), outcomes.len(), "--format json");
    for (case, output) in outcomes {
        assert_json_envelope(output, case.envelope, case.label);
    }
}

/// One answered run prints `envelope` and one newline, and nothing else.
fn assert_json_envelope(output: &Output, envelope: &str, label: &str) {
    assert_answered(output, label);
    assert_eq!(
        output.stdout.strip_suffix('\n'),
        Some(envelope),
        "{label}: JSON output is the shared envelope and one newline: {:?}",
        output.stdout
    );
}

/// Every `--format text` run prints the declaration alone.
fn assert_text_declarations(cases: &[Case], outcomes: &[(&Case, Output)]) {
    cases::assert_every_row_ran(cases.len(), outcomes.len(), "--format text");
    for (case, output) in outcomes {
        assert_answered(output, case.label);
        assert_eq!(
            &*output.stdout,
            case.unit
                .as_ref()
                .map_or(cases::NO_UNIT, |unit| &*unit.text),
            "{}: text output is the declaration alone, with nothing added",
            case.label
        );
    }
}

/// An omitted `--format` prints what `--format json` prints.
fn assert_default_is_json(output: &Output) {
    assert_json_envelope(output, cases::PRESENT_ENVELOPE, DEFAULT_FORMAT_LABEL);
}

/// Every unreadable file exits 1, prints no result, and says why on stderr.
fn assert_read_failures(tree: &Tree, outcomes: &[(&FailureCase, Output)], format: &str) {
    cases::assert_every_row_ran(cases::FAILURES.len(), outcomes.len(), format);
    for (failure, output) in outcomes {
        // Exit code 1, not merely non-zero: `main` returns `Result`, so an
        // orderly read failure exits 1 and a signal death does not.
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}: a read failure exits 1 under --format {format}: {:?}",
            failure.label,
            output.status
        );
        assert_eq!(
            &*output.stdout, "",
            "{}: a read failure prints no result under --format {format}",
            failure.label
        );
        // The claim itself lives beside the table both transports read, so the
        // CLI and the MCP tool cannot disagree about what a refusal must say.
        // This journey supplies only its own surface: stderr, and the format it
        // ran under.
        cases::assert_carries(
            &output.stderr,
            failure,
            &tree.argument(failure.source),
            &format!("{} on stderr under --format {format}", failure.label),
        );
    }
}

/// A run that answers exits zero and stays silent on stderr.
fn assert_answered(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label}: exits zero: {:?}: {}",
        output.status,
        output.stderr
    );
    assert_eq!(
        &*output.stderr, "",
        "{label}: a run that answers writes no diagnostics"
    );
}
