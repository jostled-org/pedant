//! What every spawned child is held to, stated once.
//!
//! Both CLI journeys make the same four claims about a run — it answered, it
//! printed exactly this, it refused with a typed envelope, it refused with a
//! usage error — and two copies of those claims are two chances for one journey
//! to quietly weaken its half.
//!
//! The two claims about a finished *server* live here for the same reason. Four
//! predicates across three journeys stated one bounded, contained, silent exit
//! under four names, and the copy that named the fewest was the one that dropped
//! the containment and the bound.

use std::time::Duration;

use serde_json::Value;

use crate::child::Termination;
use crate::command::{self, Output};
use crate::contained::Descendants;
use crate::failure::Failure;

/// What the CLI exits with when it could not answer.
///
/// Two statuses and no third: clap already exits two for a malformed command
/// line, so an operator scripting the binary reads "the question was not
/// answered" from one number, and the typed envelope on stderr says why.
pub const REFUSED: i32 = 2;

/// The bound every EOF-to-exit sits inside, on every host.
///
/// The teardown this binary contracts is three steps — drop the observation,
/// join the applying thread, exit — and none of them waits on a caller. Ten
/// seconds is far more than that costs on a loaded host and far less than the
/// harness's own thirty-second ceiling, which is the point: a shutdown bounded
/// only by the harness is a shutdown nothing measured.
pub const EXIT_BOUND: Duration = Duration::from_secs(10);

/// One run against one root, named by the case that asked for it.
///
/// The label is the caller's because a journey runs this once per row, and
/// [`Failure`] names the operation rather than the row: "the run failed" is the
/// same sentence for every line of a refusal table. Folded in here rather than
/// by each caller, so no journey has to reassemble the argument vector to name
/// its own row and none labels the failure twice.
pub async fn run(root: &str, arguments: &[&str], label: &str) -> Result<Output, Failure> {
    let mut spelled: Vec<&str> = arguments.to_vec();
    spelled.extend(["--root", root]);
    command::run(&spelled)
        .await
        .map_err(|failure| failure.during(label, &spelled.join(" ")))
}

/// One library answer, rendered as the CLI renders it.
///
/// The expectation this builds is the library's answer to the same question, so
/// it states that the binary is a transport over the library and nothing about
/// the bytes either of them chose. What the wire itself owes is written down in
/// [`crate::journeys::envelopes`], which pins one shape per response type
/// against a document no serializer produced.
pub fn rendered<T: serde::Serialize>(response: &T) -> String {
    format!(
        "{}\n",
        serde_json::to_string(response).expect("the response serializes")
    )
}

/// One answered run prints `expected` and nothing else.
pub fn assert_answer(output: &Output, expected: &str, claim: &str) {
    assert_answered(output, claim);
    assert_eq!(&*output.stdout, expected, "{claim}");
}

/// Every finished run leaves no member of its process tree behind.
///
/// Stated for every CLI row rather than only for the rows that are about
/// process behaviour: a command that leaked would leak wherever it was called
/// from, and a claim made in one journey would say nothing about the others.
/// The harness reads the tree before it kills it, so this is what the run left
/// rather than what the teardown then cleaned up.
pub fn assert_contained(output: &Output, claim: &str) {
    assert_eq!(
        output.descendants,
        Descendants::None,
        "{claim}: the run leaves no member of its process tree behind: {}",
        output.stderr
    );
}

/// A run that answers exits zero, stays silent on stderr, and leaves no tree.
pub fn assert_answered(output: &Output, claim: &str) {
    assert_contained(output, claim);
    assert!(
        output.status.success(),
        "{claim}: exits zero: {:?}: {}",
        output.status,
        output.stderr
    );
    assert_eq!(
        &*output.stderr, "",
        "{claim}: a run that answers writes no diagnostic"
    );
}

/// The answer at `pointer` states something rather than nothing.
///
/// Every expectation these journeys compare against is the library's own answer
/// to the same question, taken from the same repository — so two empty answers
/// agree exactly and prove nothing about either. This is what makes the
/// agreement evidence, and there is one of it: both CLI journeys asked it, four
/// times over, in two spellings that had already drifted — one guarded the
/// single-record case and the other did not.
///
/// One predicate over both shapes a compared answer takes. A list states
/// something when it holds a row; a single record states something when it is
/// there at all. An absent pointer, a null, and an empty list each fail.
pub fn assert_states_something(output: &Output, pointer: &str, claim: &str) {
    assert_answer_states_something(&value(output, claim), pointer, claim);
}

/// One already-parsed answer states something at `pointer`.
///
/// The predicate itself, and the one [`assert_states_something`] is written on,
/// so the two cannot state different rules. Published beside it because
/// [`crate::journeys::parity`] holds the bytes a *refused* run wrote to stderr
/// to the same claim, and no reader of an [`Output`] that exits two will ever
/// hand those bytes back.
pub fn assert_answer_states_something(answered: &Value, pointer: &str, claim: &str) {
    let states = match answered.pointer(pointer) {
        Some(Value::Array(rows)) => !rows.is_empty(),
        Some(Value::Object(_)) => true,
        _ => false,
    };
    assert!(states, "{claim}: {pointer} states something: {answered}");
}

/// The text projection prints one row per item the JSON answer states.
///
/// Three steps both CLI journeys spelled out and had already drifted over: the
/// text run is held to the answering contract before a byte of its stdout is
/// read — a `--format text` run that exited two printing nothing would otherwise
/// satisfy the count against whatever the JSON answer happened to state — the
/// list is required to hold something, and only then are the lines counted.
///
/// Each printed line comes back paired with the item it projects, and the
/// items are owned: the answer they were read from is dropped here, and a
/// caller checking a row's content would otherwise have to run the same
/// question again to reach them.
///
/// Paired here rather than by the caller, because pairing is a `zip` and a
/// `zip` stops at the shorter side and reports success. The one place that can
/// hold is directly under the count equality above, where the two sides are the
/// same two the assertion just proved equal — a caller re-splitting the same
/// stdout is a second derivation of one of them, and the equality it rests on
/// is a function call away.
pub fn assert_one_text_row_per<'text>(
    json: &Output,
    text: &'text Output,
    pointer: &str,
    claim: &str,
) -> Box<[(&'text str, Value)]> {
    let answered = value(json, claim);
    assert_answered(text, claim);
    let stated = answered
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{claim}: {pointer} is an array: {answered}"));
    assert!(
        !stated.is_empty(),
        "{claim}: and the fixture states rows to project: {answered}"
    );
    assert_eq!(
        text.stdout.lines().count(),
        stated.len(),
        "{claim}: the text projection prints one row per item: {:?}",
        text.stdout
    );
    text.stdout.lines().zip(stated.iter().cloned()).collect()
}

/// The parsed answer one successful run printed.
pub fn value(output: &Output, label: &str) -> Value {
    assert_answered(output, label);
    serde_json::from_str(&output.stdout)
        .unwrap_or_else(|error| panic!("{label}: stdout is one JSON answer: {error}"))
}

/// The parsed envelope one refused run wrote to stderr.
pub fn refusal(output: &Output, label: &str) -> Value {
    assert_refused(output, label);
    serde_json::from_str(&output.stderr)
        .unwrap_or_else(|error| panic!("{label}: stderr is one typed envelope: {error}"))
}

/// A run that refused exits two, prints no result, and leaves no tree.
pub fn assert_refused(output: &Output, label: &str) {
    assert_contained(output, label);
    assert_eq!(
        output.status.code(),
        Some(REFUSED),
        "{label}: a refusal exits {REFUSED}: {:?}: {}",
        output.status,
        output.stderr
    );
    assert_eq!(&*output.stdout, "", "{label}: a refusal prints no result");
}

/// A usage error exits two, prints no result, and names what was wrong.
pub fn assert_usage_error(output: &Output, label: &str, reason: &str) {
    assert_refused(output, label);
    assert!(
        output.stderr.contains(reason),
        "{label}: stderr names {reason:?}: {}",
        output.stderr
    );
}

/// One termination that exited inside the bound and left no tree behind.
///
/// Every server row makes both claims, whether or not it exited zero: a refusal
/// that hung or that leaked is the same defect a success would be.
///
/// Both halves are asked of the operating system rather than of this harness's
/// bookkeeping. The tree question is a signal-zero on the process group, or the
/// Job Object's own root, and the elapsed time is measured from the client's EOF
/// to the reap — so a row that only checked the exit status would pass against a
/// server that left a descendant holding the pipes, and a row that only waited
/// would pass against one that took the harness's whole ceiling.
pub fn assert_bounded(termination: &Termination, label: &str) {
    assert_eq!(
        termination.descendants,
        Descendants::None,
        "{label}: the contained tree holds nothing once the server has gone: {}",
        termination.stderr
    );
    assert!(
        termination.elapsed <= EXIT_BOUND,
        "{label}: the server exits inside {EXIT_BOUND:?}, and took {:?}: {}",
        termination.elapsed,
        termination.stderr
    );
}

/// One finished run that ended inside the same bound a session is held to.
///
/// The [`Output`] twin of [`assert_bounded`], and here for the reason that one
/// is: a second `elapsed <= EXIT_BOUND` comparison living in a journey is the
/// copy that can quietly start naming a different bound.
///
/// A row that ends before any client can speak has no EOF to time from, so the
/// mark is the spawn. The bound is still the sessions': a refusal is the
/// cheapest way this binary can end, and one that took longer than a shutdown
/// with a rebuild in flight is a defect wherever it came from. Containment is
/// not restated here — [`assert_refused`] and [`assert_answered`] already ask it
/// of every run.
pub fn assert_run_is_bounded(output: &Output, label: &str) {
    assert!(
        output.elapsed <= EXIT_BOUND,
        "{label}: the run ends inside {EXIT_BOUND:?}, and took {:?}: {}",
        output.elapsed,
        output.stderr
    );
}

/// One termination that stopped cleanly and left nothing to say.
pub fn assert_clean(termination: &Termination, label: &str) {
    assert_bounded(termination, label);
    assert!(
        termination.status.success(),
        "{label}: the server exits cleanly: {:?}: {}",
        termination.status,
        termination.stderr
    );
    assert!(
        termination.trailing.is_empty(),
        "{label}: the server sends nothing the client did not ask for: {}",
        termination.trailing
    );
    assert_eq!(
        &*termination.stderr, "",
        "{label}: a clean run writes no diagnostics"
    );
}
