//! A failed update keeps the last good index and says so on every response.

use pedant_snippet::{
    ChangeKind, CodeIntelligenceError, CodeIntelligenceState, HealthStatus, MatchMode, PageCursor,
    PageRequest, ProjectAuthority, TransactionOutcome,
};

use crate::queries::paging::opening_cursor;
use crate::queries::support::{search, symbols_page};

use super::harness::{
    LIVE_REPOSITORY, Live, NAMED, UNPARSABLE, assert_whole, issue_rows, source_paths,
};
use super::tree::Tree;

/// A source whose bytes are not UTF-8, degraded from the first build onward.
const UNDECODABLE: &str = "scripts/broken.py";

/// A failed rebuild keeps the index, moves the state, marks every scope stale,
/// invalidates cursors, and clears only when the tree is fixed.
#[test]
fn live_index_failure_keeps_last_good_index_and_changes_state_revision() {
    let tree = Tree::of(LIVE_REPOSITORY);
    tree.write_bytes(UNDECODABLE, b"def broken():\n    return \xff\n");
    let live = Live::over(
        tree,
        &[ProjectAuthority::RustManifest {
            path: Box::from(NAMED),
        }],
    );

    let good = live.state();
    assert_eq!(
        good.health().status(),
        HealthStatus::Degraded,
        "one source states no UTF-8, and the first build records that without staleness: {:?}",
        issue_rows(&good)
    );
    assert_eq!(
        good.health().stale_scopes(),
        0,
        "an initial degraded record is not an older answer"
    );
    // Both comparisons this case makes later are between two of the subject's
    // own answers, and two such lists are equal when the subject stopped
    // answering at all. So the corpus is required to be a whole index, and the
    // one issue the tree really states is named here rather than derived: an
    // empty corpus with no issues satisfies every row below it otherwise.
    assert_whole(
        &good,
        "the first build over a repository holding one unreadable source",
    );
    let own = format!("file:{UNDECODABLE}|");
    assert!(
        issue_rows(&good).iter().any(|row| row.starts_with(&own)),
        "and the record it carries is that source's own: {:?}",
        issue_rows(&good)
    );
    // The navigation tree's own search constructor and its own opening-cursor
    // helper. Both questions are asked there over the same types in the same
    // binary, and a second spelling of either is a second chance for this row
    // to mint a cursor the contract would not recognize.
    let every_symbol = search("", MatchMode::Contains);
    let cursor = opening_cursor(
        "search_symbols",
        &|request: &PageRequest| symbols_page(&good, &every_symbol, request),
        1,
    );

    live.tree().write(NAMED, UNPARSABLE);
    let failed = live.apply(&[(NAMED, ChangeKind::Modified)]);

    assert_eq!(
        failed.outcome(),
        TransactionOutcome::Retained,
        "the authority the caller named is fatal when it refuses"
    );
    let held = live.state();
    assert_eq!(
        held.index().revision(),
        good.index().revision(),
        "so the last good index is what a caller still reaches"
    );
    assert_ne!(
        held.revision(),
        good.revision(),
        "but the state over it is a different claim"
    );
    assert_eq!(
        source_paths(&held),
        source_paths(&good),
        "and it answers for exactly the corpus that index held"
    );

    every_scope_is_marked_stale(&held);
    every_response_reports_it(&held);
    the_cursor_no_longer_continues(&held, cursor);
    the_ledger_counts_it(&live);

    the_repair_restores_the_index_it_retained(&live, &good);
}

/// Restoring the bytes restores the index, and clears the issue the refusal
/// raised without disturbing the one the tree really states.
fn the_repair_restores_the_index_it_retained(live: &Live, good: &CodeIntelligenceState) {
    live.tree()
        .write(NAMED, manifest_of(LIVE_REPOSITORY, NAMED));
    let recovered = live.apply(&[(NAMED, ChangeKind::Modified)]);
    assert_eq!(
        recovered.outcome(),
        TransactionOutcome::Published,
        "the restored manifest rebuilds"
    );
    let after = live.state();
    assert_eq!(
        after.index().revision(),
        good.index().revision(),
        "the restored bytes are the original bytes, so the index is the original index"
    );
    assert_eq!(
        issue_rows(&after),
        issue_rows(good),
        "and the project issue clears while the undecodable source keeps its own, unstaled"
    );
    assert_eq!(
        after.health().stale_scopes(),
        0,
        "nothing is serving an older answer once the rebuild succeeded"
    );
}

/// The refusal is recorded against the authority, and what was already degraded
/// is now older than the tree too.
fn every_scope_is_marked_stale(held: &CodeIntelligenceState) {
    let rows = issue_rows(held);
    assert!(
        held.issues()
            .iter()
            .any(|issue| issue.scope().token() == "project"
                && issue.scope().name() == NAMED
                && issue.stale()),
        "the refusal names the authority that stated it: {rows:?}"
    );
    assert!(
        held.issues().iter().all(pedant_snippet::IndexIssue::stale),
        "and every scope this state carries is now answering from before the change: {rows:?}"
    );
    assert_eq!(
        held.health().status(),
        HealthStatus::Stale,
        "which is what the health says: {rows:?}"
    );
    assert_eq!(
        u32::try_from(held.issues().len()).unwrap_or(u32::MAX),
        held.health().stale_scopes(),
        "for every one of them"
    );
}

/// Every answer carries the same health, because every answer comes from the
/// same state.
fn every_response_reports_it(held: &CodeIntelligenceState) {
    let listed = held
        .list_projects(&PageRequest::default())
        .expect("a stale state still answers");
    let searched = held
        .search_symbols(&search("", MatchMode::Contains), &PageRequest::default())
        .expect("and still searches");
    let outlined = held
        .outline_file("crate-a/src/lib.rs")
        .expect("and still outlines");
    for (label, health, revision) in [
        ("list_projects", listed.health(), listed.state_revision()),
        (
            "search_symbols",
            searched.health(),
            searched.state_revision(),
        ),
        ("outline_file", outlined.health(), outlined.state_revision()),
    ] {
        assert_eq!(health, held.health(), "{label} reports the state's health");
        assert_eq!(
            revision,
            held.revision(),
            "{label} names the state it answered from"
        );
    }
}

/// A cursor is a claim about a state, and this is a different state.
fn the_cursor_no_longer_continues(held: &CodeIntelligenceState, cursor: PageCursor) {
    let refused = held
        .search_symbols(
            &search("", MatchMode::Contains),
            &PageRequest {
                size: Some(1),
                cursor: Some(cursor),
            },
        )
        .expect_err("a cursor minted before the issue appeared continues nothing");
    assert!(
        matches!(refused, CodeIntelligenceError::CursorDrift),
        "and says so as drift rather than as an empty page: {refused}"
    );
}

/// The failure is a cost record too, and it is the only one.
fn the_ledger_counts_it(live: &Live) {
    let ledger = live.ledger();
    assert_eq!(
        (ledger.applied(), ledger.published(), ledger.retained()),
        (1, 0, 1),
        "one batch, no publish of a rebuilt index, one last-good retention"
    );
    assert_eq!(
        ledger.last().map(pedant_snippet::LiveTransaction::outcome),
        Some(TransactionOutcome::Retained),
        "and the last transaction says which it was"
    );
}

/// The original bytes of one file in a repository table.
fn manifest_of(files: &'static [(&'static str, &'static str)], path: &str) -> &'static str {
    files
        .iter()
        .find(|(held, _)| *held == path)
        .map(|(_, contents)| *contents)
        .unwrap_or_else(|| panic!("{path} is one of the fixture's own files"))
}
