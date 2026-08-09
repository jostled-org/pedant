//! Cross-platform termination paths for the supply-chain process guard.
//!
//! Each row runs this Rust test executable as a fixture parent. The parent
//! waits until containment adoption is complete, starts a lingering Rust
//! descendant, and then exits, times out, or fails. Teardown must end the whole
//! tree before the row may inspect its result.

use std::time::Duration;

use pedant_process_guard::{
    FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV, FIXTURE_ROLE_ENV,
    FIXTURE_TEST_ENV, wait_until_gone,
};

use crate::fake_cargo::descendant_pid;
use crate::fixtures::VendorFixture;
use crate::process_guard::{Completed, Run, execute_released};

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

    let pid = descendant_pid(&pid_file, DESCENDANT_BUDGET)
        .unwrap_or_else(|| panic!("{}: the fixture left no descendant to reap", row.label));
    assert!(
        wait_until_gone(pid, DESCENDANT_BUDGET),
        "{}: descendant {pid} outlived its guard",
        row.label
    );
}
