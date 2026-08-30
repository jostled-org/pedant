//! One batch is one transaction, and a transaction is all or none of it.

use pedant_snippet::{ChangeKind, CodeIntelligenceState, TransactionOutcome};

use super::harness::{LIVE_SOURCES, Live, admits, assert_whole, declared_names, source_paths};

/// The source placed while the watcher is live.
const ADDED: (&str, &str) = (
    "crate-a/src/added.rs",
    "pub fn added() -> u32 {\n    1\n}\n",
);

/// What `crate-a/src/lib.rs` holds after the modify.
const EDITED: &str = "pub fn make() -> u32 {\n    2\n}\n\npub fn extra() -> u32 {\n    3\n}\n";

/// The most transactions one burst of real events may reach the index as.
///
/// One, because the burst is made inside a single settle window. Two is
/// admitted rather than required: a host that delivers one of the four reports
/// after the window has closed opens a second batch, and that is a report
/// arriving late rather than a batch the thread failed to coalesce. Anything
/// above it is a thread applying reports as they arrive.
const COALESCED: u64 = 2;

/// A real create, modify, remove, and rename reach one published state each,
/// and no caller ever observes a part-built one.
#[test]
fn live_index_create_modify_remove_and_rename_publish_atomic_states() {
    one_batch_publishes_once_and_atomically();
    a_rename_is_one_removal_and_one_creation();
    a_rebuild_covers_every_admitted_source();
    real_events_reach_the_published_state();
}

/// Four changes in one batch move the state once, and nothing else.
///
/// Stated through the batch a watcher would have handed over rather than
/// through the watcher, because the claim is about the transaction: a host that
/// reported the four changes in four batches would publish four states and be
/// right to, and a transaction that published twice would be wrong whatever
/// reported it.
fn one_batch_publishes_once_and_atomically() {
    let live = Live::opened();
    let before = live.state();

    live.tree().place(ADDED.0, ADDED.1);
    live.tree().write("crate-a/src/lib.rs", EDITED);
    live.tree().remove("scripts/tool.py");
    live.tree().rename("main.go", "renamed.go");

    let transaction = live.apply(&[
        (ADDED.0, ChangeKind::Created),
        ("crate-a/src/lib.rs", ChangeKind::Modified),
        ("scripts/tool.py", ChangeKind::Removed),
        ("main.go", ChangeKind::Removed),
        ("renamed.go", ChangeKind::Created),
    ]);

    assert_eq!(
        transaction.outcome(),
        TransactionOutcome::Published,
        "every change is one this repository can be rebuilt over"
    );
    let ledger = live.ledger();
    assert_eq!(
        (ledger.applied(), ledger.published(), ledger.retained()),
        (1, 1, 0),
        "one batch is one transaction and one publish"
    );

    let after = live.state();
    assert_eq!(
        after.revision(),
        transaction.state_revision(),
        "the state a caller reaches is the one the transaction published"
    );
    assert_ne!(
        before.index().revision(),
        after.index().revision(),
        "and it is not the one that was published before it"
    );
    assert_eq!(
        &*source_paths(&after),
        [ADDED.0, "crate-a/src/lib.rs", "renamed.go"],
        "the created and renamed sources are admitted and the removed one is not"
    );
    assert_whole(&after, "the published state");

    assert_eq!(
        &*source_paths(&before),
        LIVE_SOURCES,
        "and the state held before the transaction still answers for the tree it named"
    );
    assert!(
        before.read_structure(named(&before, "make")).is_ok(),
        "an immutable state answers from what it retained, whatever the tree does next"
    );
}

/// A rename admits the new path and stops admitting the old one.
fn a_rename_is_one_removal_and_one_creation() {
    let live = Live::opened();
    let before = live.state();
    let outlined = before
        .outline_file("main.go")
        .expect("the Go source outlines before it moves");
    // Pinned to what the fixture declares, so the comparison below is between
    // two lists that are known to hold something. Two lists derived from the
    // subject's own answers are equal when the subject stopped answering.
    assert_eq!(
        &*declared_names(&before, "main.go"),
        ["main", "New"],
        "the Go source declares its package and its one function before it moves"
    );
    let moved = outlined
        .result()
        .structures()
        .iter()
        .map(declared)
        .collect::<Box<[String]>>();
    assert_eq!(moved.len(), 2, "and declares nothing else: {moved:?}");

    live.tree().rename("main.go", "cmd/renamed.go");
    live.apply(&[
        ("main.go", ChangeKind::Removed),
        ("cmd/renamed.go", ChangeKind::Created),
    ]);

    let after = live.state();
    assert!(
        after.outline_file("main.go").is_err(),
        "the old path is not a source this revision admits"
    );
    let arrived = after
        .outline_file("cmd/renamed.go")
        .expect("the new path is")
        .result()
        .structures()
        .iter()
        .map(declared)
        .collect::<Box<[String]>>();
    assert_eq!(
        arrived, moved,
        "and it declares exactly what the old one did, because the bytes moved rather than changed"
    );
}

/// A batch names what changed. It does not decide what is rebuilt.
///
/// The rebuild is the whole repository, so a source the batch never named is
/// reindexed from its current bytes too. That is what lets a refusal name its
/// own scope rather than the scope the reports happened to mention, and it is
/// what makes one coalesced batch a complete answer instead of an approximate
/// one: the reports select nothing to skip.
fn a_rebuild_covers_every_admitted_source() {
    let live = Live::opened();

    live.tree().write("crate-a/src/lib.rs", EDITED);
    live.tree().place(ADDED.0, ADDED.1);

    let transaction = live.apply(&[("scripts/tool.py", ChangeKind::Modified)]);
    assert_eq!(
        &*transaction
            .batch()
            .changes()
            .iter()
            .map(|change| change.path().to_owned())
            .collect::<Box<[String]>>(),
        ["scripts/tool.py"],
        "the batch names one path and only that one"
    );

    let after = live.state();
    assert_eq!(
        after
            .outline_file("crate-a/src/lib.rs")
            .expect("the unnamed source still outlines")
            .result()
            .structures()
            .len(),
        2,
        "the source the batch never named is reindexed from the bytes it holds now"
    );
    assert!(
        admits(&after, ADDED.0),
        "and a source the batch never named at all is admitted: {:?}",
        source_paths(&after)
    );
    assert_whole(&after, "the state one unrelated report published");
}

/// The same four changes, reported by the host rather than stated by the test.
///
/// This is the one leg only a real watcher can carry, so it is where the
/// settle window is bounded. Four operations reported by the host reach the
/// index as one transaction; a thread that applied each report as it arrived
/// would publish a revision of a tree that existed for a millisecond, and
/// would converge on exactly the same final state while doing it.
fn real_events_reach_the_published_state() {
    let mut live = Live::watching();

    live.tree().place(ADDED.0, ADDED.1);
    live.tree().write("crate-a/src/lib.rs", EDITED);
    live.tree().remove("scripts/tool.py");
    live.tree().rename("main.go", "renamed.go");

    let expected = [ADDED.0, "crate-a/src/lib.rs", "renamed.go"];
    let settled = live.wait_for("the watcher publishes every real change", |state| {
        (*source_paths(state) == expected).then(|| state.clone())
    });

    assert_eq!(
        settled
            .outline_file("crate-a/src/lib.rs")
            .expect("the edited source outlines")
            .result()
            .structures()
            .len(),
        2,
        "the modified source is reindexed from its new bytes"
    );

    // Read after the join, so the count is every transaction this watcher will
    // ever apply rather than the ones that had landed by the time it was asked.
    live.stop().expect("the applying thread ends cleanly");
    let ledger = live.ledger();
    assert!(
        ledger.published() >= 1 && ledger.retained() == 0,
        "every transaction the watcher applied rebuilt this repository: {ledger:?}"
    );
    // Counted from the watch rather than from the open: establishing the watch
    // is itself a change this index reported and applied.
    //
    // Bounded from below as well as from above. Zero satisfies "at most two",
    // and zero is what a watcher that reported nothing at all would leave — so
    // the upper bound alone was a coalescing claim that the absence of
    // coalescing also passed. The companion line above says nothing about it
    // either: the probe that established the watch is a publish of its own.
    assert!(
        (1..=COALESCED).contains(&live.applied_since_watch()),
        "four changes made inside one settle window are one batch, and a straggler \
         report arriving after it is the only second one a host can produce: {ledger:?}"
    );
}

/// One declaration as a claim about moved bytes reads it.
///
/// Name, kind, and extent, and not the qualified name: a qualified name carries
/// the path, and the whole point of a rename is that the path is the one thing
/// that changed.
fn declared(structure: &pedant_snippet::StructureDescriptor) -> String {
    format!(
        "{:?}|{}|{:?}",
        structure.kind(),
        structure.name().unwrap_or("<anonymous>"),
        structure.span().byte_range()
    )
}

/// The handle one named structure of `crate-a/src/lib.rs` carries.
fn named(state: &CodeIntelligenceState, name: &str) -> pedant_snippet::StructureHandle {
    state
        .outline_file("crate-a/src/lib.rs")
        .expect("the Rust source outlines")
        .result()
        .structures()
        .iter()
        .find(|structure| structure.name() == Some(name))
        .unwrap_or_else(|| panic!("{name} is declared there"))
        .handle()
}
