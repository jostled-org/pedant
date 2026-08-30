//! Cross-platform termination paths for the MCP process guard.
//!
//! Each row runs this Rust test executable as a fixture parent. The parent
//! waits until containment adoption is complete, starts a lingering Rust
//! descendant, and then exits, times out, or fails. The MCP guard keeps its
//! protocol-aware drains while the shared containment owns the process tree.

use std::time::Duration;

use pedant_process_guard::{
    FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV, FIXTURE_ROLE_ENV,
    FIXTURE_TEST_ENV, descendant_pid, wait_until_gone,
};

use crate::process_guard::{Completed, Guard, Run};

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

/// One guarded run ends its whole process tree before its result is read.
pub(crate) fn guarded_run_leaves_no_descendant(row: &GuardRow) {
    let temp = tempfile::tempdir().expect("the guard fixture should have a directory");
    let pid_file = temp.path().join("descendant.pid");
    let release_file = temp.path().join("release");
    let program = std::env::current_exe()
        .expect("the MCP integration test executable should be known")
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
    let run = Run {
        program: &program,
        cwd: temp.path(),
        args: &args,
        env: &environment,
        budget: row.budget,
    };

    let guard = Guard::spawn(&run)
        .unwrap_or_else(|failure| panic!("{}: the guard failed to spawn: {failure}", row.label));
    std::fs::write(&release_file, b"adopted")
        .unwrap_or_else(|failure| panic!("{}: fixture release failed: {failure}", row.label));
    // The ceiling is read back from the run the guard was spawned with, so this
    // row states it once. `finish` is then held to it below, because nothing
    // else here observes which bound the wait used: a row whose budget never
    // reached the guard still times out, just at the shared default, and every
    // assertion under it holds.
    let completed = guard
        .finish(run.budget)
        .unwrap_or_else(|failure| panic!("{}: the guard failed: {failure}", row.label));
    assert_eq!(
        completed.budget, row.budget,
        "{}: the guard bounded the child by the ceiling this row stated",
        row.label
    );
    assert!(
        (row.expected)(&completed),
        "{}: unexpected outcome {:?}: {}",
        row.label,
        completed.outcome,
        completed.transcript()
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
