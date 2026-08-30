//! Every report about one path folds to one row, and a recovered scope clears.

use pedant_snippet::{ChangeKind, TransactionOutcome};

use super::harness::{Live, batch_rows, declared_names, issue_rows};

/// The source the watcher leg breaks and then repairs.
const SUBJECT: &str = "scripts/tool.py";

/// What it holds when it is readable.
const READABLE: &str = "def build():\n    return 1\n";

/// Duplicate reports coalesce into one sorted transaction, and an issue clears
/// exactly when its scope rebuilds.
#[test]
fn live_index_batches_events_once_and_clears_recovered_issues() {
    every_report_about_one_path_folds_to_one_row();
    one_batch_states_each_path_once_in_precedence_order();
    a_repaired_source_clears_exactly_its_own_issue();
}

/// The net effect of a sequence is what the batch states, whatever its length.
fn every_report_about_one_path_folds_to_one_row() {
    let live = Live::opened();

    let folded = live.batch(&[
        ("a.py", ChangeKind::Created),
        ("a.py", ChangeKind::Modified),
        ("a.py", ChangeKind::Modified),
        ("b.py", ChangeKind::Modified),
        ("b.py", ChangeKind::Removed),
        ("c.py", ChangeKind::Removed),
        ("c.py", ChangeKind::Created),
        ("d.py", ChangeKind::Created),
        ("d.py", ChangeKind::Removed),
        ("e.py", ChangeKind::Modified),
    ]);

    assert_eq!(
        &*batch_rows(&folded),
        [
            "source|a.py|created",
            "source|b.py|removed",
            "source|c.py|modified",
            "source|d.py|removed",
            "source|e.py|modified",
        ],
        "a path created and then written is one creation, one written and then deleted is one \
         removal, one deleted and then recreated is a modification, and one created and removed \
         inside the batch is a path that is not there"
    );
}

/// One batch states each path once, with the roles that redefine the corpus
/// first.
fn one_batch_states_each_path_once_in_precedence_order() {
    let live = Live::opened();

    let batch = live.batch(&[
        ("scripts/tool.py", ChangeKind::Modified),
        ("go.mod", ChangeKind::Modified),
        (".gitignore", ChangeKind::Created),
        ("go.mod", ChangeKind::Modified),
        ("crate-a/src/lib.rs", ChangeKind::Modified),
        (".gitignore", ChangeKind::Modified),
        ("crate-a/Cargo.toml", ChangeKind::Modified),
    ]);

    assert_eq!(
        &*batch_rows(&batch),
        [
            "authority|crate-a/Cargo.toml|modified",
            "authority|go.mod|modified",
            "ignore|.gitignore|created",
            "source|crate-a/src/lib.rs|modified",
            "source|scripts/tool.py|modified",
        ],
        "seven reports about five paths are five rows, authorities first"
    );

    // Read before the apply. An ignored transaction states the state it found,
    // so comparing it against the state read afterwards would move both sides
    // together and hold whatever the apply did.
    let before = live.state().revision();
    let empty = live.batch(&[]);
    assert!(empty.is_empty(), "and nothing reported is nothing to do");
    let ignored = live.applied(empty);
    assert_eq!(
        ignored.outcome(),
        TransactionOutcome::Ignored,
        "which rebuilds nothing"
    );
    assert_eq!(
        ignored.state_revision(),
        before,
        "so the state it names is the one that was already published"
    );
    assert_eq!(
        live.state().revision(),
        before,
        "which is still the one a caller reaches"
    );
    assert_eq!(
        live.ledger().published(),
        0,
        "because nothing was published at all"
    );
}

/// An issue belongs to a scope, and it clears when that scope rebuilds cleanly.
fn a_repaired_source_clears_exactly_its_own_issue() {
    let mut live = Live::watching();
    assert!(
        live.state().issues().is_empty(),
        "the fixture repository states no issue to begin with"
    );

    live.tree()
        .write_bytes(SUBJECT, b"def broken():\n    return \xff\n");
    let degraded = live.wait_for("the unreadable source is recorded", |state| {
        (!state.issues().is_empty()).then(|| issue_rows(state))
    });
    assert_eq!(
        &*degraded,
        [format!("file:{SUBJECT}|source|source_encoding|false")],
        "one issue, against the source that stated it, and not stale: the tree really is like that"
    );

    // The wait settles on the subject's own issue being gone, and the assertion
    // is over every issue that survived it. A wait for an empty issue list would
    // decide the claim itself, and a repair that cleared its own issue while
    // raising another would pass it.
    let own = format!("file:{SUBJECT}|");
    live.tree().write(SUBJECT, READABLE);
    let cleared = live.wait_for("the repaired source clears its own issue", |state| {
        let rows = issue_rows(state);
        (!rows.iter().any(|row| row.starts_with(&own))).then_some(rows)
    });
    assert!(
        cleared.is_empty(),
        "a rebuild that succeeded carries nothing forward: {cleared:?}"
    );
    assert_eq!(
        &*declared_names(&live.state(), SUBJECT),
        ["build"],
        "and it is indexed from its new bytes"
    );

    live.stop().expect("the applying thread ends cleanly");
}
