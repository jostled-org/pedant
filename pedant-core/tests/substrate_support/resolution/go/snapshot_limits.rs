//! Every snapshot ceiling refuses at its own first excess and publishes
//! nothing.
//!
//! The ceilings are lowered one at a time from a baseline that admits the
//! fixture exactly, so a row that passed because a neighbouring ceiling refused
//! first shows up as the wrong refusal text rather than as a pass. The byte
//! ceilings are derived from the fixture's own text: a written-down number would
//! start agreeing with a stale fixture the moment either changed.

use pedant_core::resolution::go::GoResolutionLimits;

use crate::resolution::fixture::FixtureFile;
use crate::resolution::go::fixture::{snapshot, snapshot_refusal};
use crate::resolution::go::snapshot_fixtures::PACKAGE_CONTEXTS;

/// Every directory entry a [`PACKAGE_CONTEXTS`] walk visits: the root's
/// `go.mod`, its three sources, and its `util` directory, then the one source
/// inside `util`.
const ADMITTING_DIRECTORY_ENTRIES: u32 = 6;

/// The package units and distinct sources that fixture holds.
const ADMITTING_UNITS: u32 = 4;
const ADMITTING_SOURCES: u32 = 4;

/// 4.T7 (Invariant 5): every snapshot ceiling refuses at its first excess, and
/// no refusal publishes a partial snapshot.
#[test]
fn go_snapshot_limits_refuse_every_first_excess() {
    for limit in 1..ADMITTING_DIRECTORY_ENTRIES {
        assert_refusal(
            |limits| limits.max_directory_entries = limit,
            &format!("snapshot visits more than {limit} directory entries"),
        );
    }
    for limit in 1..ADMITTING_UNITS {
        assert_refusal(
            |limits| limits.max_units = limit,
            &format!("snapshot holds more than {limit} resolution units"),
        );
    }
    for limit in 1..ADMITTING_SOURCES {
        assert_refusal(
            |limits| limits.max_source_files = limit,
            &format!("snapshot holds more than {limit} source files"),
        );
    }

    let largest = largest_source_bytes();
    assert_refusal(
        |limits| limits.max_source_file_bytes = largest - 1,
        &format!("holds more than {} bytes", largest - 1),
    );
    let total = total_source_bytes();
    assert_refusal(
        |limits| limits.max_total_source_bytes = total - 1,
        &format!("snapshot holds more than {} source bytes", total - 1),
    );
    assert_refusal(
        |limits| limits.max_syntax_depth = 1,
        "the Go syntax depth ceiling of 1 is spent",
    );
    assert_refusal(
        |limits| limits.max_facts_per_source = 1,
        "the Go fact ceiling of 1 is spent",
    );

    let (tree, taken) = snapshot(PACKAGE_CONTEXTS, admitting());
    assert!(
        taken.is_ok(),
        "a ceiling equal to what the fixture holds admits it: {taken:?}"
    );
    drop(tree);
}

/// Snapshot the fixture under one lowered ceiling and require the exact text.
fn assert_refusal(lower: impl FnOnce(&mut GoResolutionLimits), expected: &str) {
    let mut limits = admitting();
    lower(&mut limits);
    let refused = snapshot_refusal(PACKAGE_CONTEXTS, limits).to_string();
    assert!(
        refused.contains(expected),
        "a lowered ceiling should refuse with {expected:?}, got {refused:?}"
    );
}

/// The lowest ceilings that still admit [`PACKAGE_CONTEXTS`], which is what
/// makes each refusal a first excess rather than an unrelated bound.
fn admitting() -> GoResolutionLimits {
    GoResolutionLimits {
        max_directory_entries: ADMITTING_DIRECTORY_ENTRIES,
        max_units: ADMITTING_UNITS,
        max_source_files: ADMITTING_SOURCES,
        max_source_file_bytes: largest_source_bytes(),
        max_total_source_bytes: total_source_bytes(),
        ..GoResolutionLimits::default()
    }
}

fn go_sources() -> impl Iterator<Item = &'static FixtureFile> {
    PACKAGE_CONTEXTS
        .iter()
        .filter(|(path, _)| path.ends_with(".go"))
}

fn largest_source_bytes() -> u64 {
    go_sources()
        .map(|(_, text)| text.len() as u64)
        .max()
        .expect("the fixture states Go sources")
}

fn total_source_bytes() -> u64 {
    go_sources().map(|(_, text)| text.len() as u64).sum()
}
