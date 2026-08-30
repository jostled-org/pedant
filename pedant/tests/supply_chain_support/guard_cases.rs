//! Cross-platform termination paths for the supply-chain process guard.
//!
//! Each row runs this Rust test executable as a fixture parent. The parent
//! waits until containment adoption is complete, starts a lingering Rust
//! descendant, and then exits, times out, or fails. Teardown must end the whole
//! tree before the row may inspect its result.

use std::time::Duration;

use pedant_process_guard::{
    FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV, FIXTURE_ROLE_ENV,
    FIXTURE_TEST_ENV, descendant_pid, wait_until_gone,
};

use crate::fixtures::VendorFixture;
use crate::process_guard::{Completed, Failure, Guard, Run};

const DESCENDANT_BUDGET: Duration = Duration::from_secs(5);
const FIXTURE_TEST: &str = "process_tree_fixture";

/// One termination path the guarded Rust fixture must survive.
pub(crate) struct GuardRow {
    pub(crate) label: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) budget: Duration,
    pub(crate) expected: fn(&Completed) -> bool,
}

pub(crate) const GUARD_ROWS: &[GuardRow] = &[
    GuardRow {
        label: "success",
        outcome: "success",
        budget: Duration::from_secs(120),
        expected: Completed::success,
    },
    GuardRow {
        label: "timeout",
        outcome: "timeout",
        budget: Duration::from_secs(2),
        expected: Completed::timed_out,
    },
    GuardRow {
        label: "early error",
        outcome: "failure",
        budget: Duration::from_secs(120),
        expected: exited_with_error,
    },
];

fn exited_with_error(completed: &Completed) -> bool {
    completed.code().is_some_and(|code| code != 0)
}

/// Run one child after releasing a fixture blocked on post-adoption proof.
///
/// The release has to happen between adoption and the wait, which is why this
/// row drives the guard directly instead of through the shared one-shot helper.
fn execute_released(run: &Run<'_>, release_file: &std::path::Path) -> Result<Completed, Failure> {
    let guard = Guard::spawn(run)?;
    std::fs::write(release_file, b"adopted").map_err(|error| Failure::Io {
        operation: "the fixture release",
        error,
    })?;
    guard.finish(run.budget)
}

/// One guarded run ends its whole process tree before its result is read.
pub(crate) fn guarded_run_leaves_no_descendant(row: &GuardRow) {
    let fixture = VendorFixture::new();
    let pid_file = fixture.script_dir().join("descendant.pid");
    let release_file = fixture.script_dir().join("release");
    let program = std::env::current_exe()
        .expect("the supply-chain test executable should be known")
        .to_string_lossy()
        .into_owned();
    let pid_path = pid_file.to_string_lossy().into_owned();
    let release_path = release_file.to_string_lossy().into_owned();
    let args = ["--exact", FIXTURE_TEST, "--nocapture"];
    let environment = [
        (FIXTURE_ROLE_ENV, "parent"),
        (FIXTURE_TEST_ENV, FIXTURE_TEST),
        (FIXTURE_PID_FILE_ENV, pid_path.as_str()),
        (FIXTURE_RELEASE_FILE_ENV, release_path.as_str()),
        (FIXTURE_OUTCOME_ENV, row.outcome),
    ];
    let mut run = Run::program(&program, fixture.consumer(), &args);
    run.env = &environment;
    run.budget = row.budget;

    let completed = execute_released(&run, &release_file)
        .unwrap_or_else(|failure| panic!("{}: the guard failed: {failure}", row.label));
    assert!(
        (row.expected)(&completed),
        "{}: unexpected outcome {:?}: {}",
        row.label,
        completed.outcome,
        completed.transcript()
    );
    // Which ceiling the wait used, read from the guard rather than from this
    // row's request: the timeout row's outcome is the two agreeing, and a row
    // served under a ceiling it never asked for would still time out somewhere.
    assert_eq!(
        completed.budget, row.budget,
        "{}: the guard bounded the tree by the ceiling this row stated",
        row.label
    );

    let pid = descendant_pid(&pid_file, DESCENDANT_BUDGET)
        .unwrap_or_else(|| panic!("{}: the fixture left no descendant to reap", row.label));
    assert!(
        wait_until_gone(pid, DESCENDANT_BUDGET),
        "{}: descendant {pid} outlived its guard",
        row.label
    );
    // The recorded descendant is the one the fixture named. The tree is every
    // member, including one this row never learned the pid of.
    assert!(
        completed.tree_is_gone(DESCENDANT_BUDGET),
        "{}: tree {} outlived its guard",
        row.label,
        completed.tree_root()
    );
}
