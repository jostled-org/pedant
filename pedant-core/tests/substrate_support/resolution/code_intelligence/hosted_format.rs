//! The formatter command hosted CI runs.
//!
//! Support modules declared through macros and the workspace-excluded process
//! guard are compiled code even when Cargo's formatter does not discover them.
//! Deliberately malformed and nonconforming fixture files are data instead.
//! The repository formatter must preserve that boundary exactly.

use std::process::Command;

use crate::resolution::tracked_script::{
    assert_checks_are_executable_linted_and_in_ci, tracked_path,
};

const FORMAT_CHECK: &str = ".github/scripts/check_rust_format.sh";
const MACRO_MODULE: &str = "pedant-snippet/tests/interfaces_support/index/keys.rs";
const EXCLUDED_MEMBER: &str = "test-support/process-guard/src/lib.rs";
const FIXTURE_DATA: &str = "pedant-core/tests/fixtures/clean.rs";

#[test]
fn hosted_formatting_follows_cargo_targets_without_reading_fixture_data() {
    assert_checks_are_executable_linted_and_in_ci(&[FORMAT_CHECK]);
    let output = Command::new("bash")
        .arg(tracked_path(FORMAT_CHECK))
        .arg("--list")
        .output()
        .unwrap_or_else(|error| panic!("{FORMAT_CHECK} --list: {error}"));
    assert!(
        output.status.success(),
        "{FORMAT_CHECK} --list must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sources = String::from_utf8_lossy(&output.stdout);
    for source in [MACRO_MODULE, EXCLUDED_MEMBER] {
        assert!(
            sources.lines().any(|listed| listed == source),
            "{FORMAT_CHECK} must format {source}"
        );
    }
    assert!(
        !sources.lines().any(|listed| listed == FIXTURE_DATA),
        "{FORMAT_CHECK} must not format source-shaped fixture data"
    );
    assert!(
        sources
            .lines()
            .all(|listed| !listed.contains("/tests/fixtures/")),
        "{FORMAT_CHECK} must exclude every fixture-data tree"
    );
}
