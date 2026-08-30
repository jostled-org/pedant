//! What an issue moves, and what a handle from another revision may reach.
//!
//! A state claim is an index identity plus the exact sorted issues qualifying
//! it, so every field of every issue has to reach it: two repositories told
//! different things about the same corpus must not answer under one state
//! identity. The rows here move one issue field at a time as far as a real
//! repository can, and [`claims`](super::claims) moves the rest — the stale
//! flag in particular, which no initial build sets and Step 8's live index
//! owns.

use pedant_snippet::{CodeIntelligenceError, ProjectHandle, StructureHandle};

use super::fixture::Repository;
use super::harness::{built, indexed, issue_rows, lowered};
use super::sources::{BROKEN_SOURCE, EDITED, KEPT, SECOND, UNDECODABLE};

/// An issue moves the state identity and nothing else.
pub fn issues_move_only_the_state() {
    an_issue_moves_only_the_state();
    the_scope_an_issue_names_moves_the_state();
    the_stage_and_code_move_the_state();
    the_message_alone_moves_the_state();
    equal_sorted_issues_agree();
}

/// A source that stated no inventory leaves the index equal and the state not.
fn an_issue_moves_only_the_state() {
    let clean = Repository::of(&[KEPT]);
    let degraded = Repository::of(&[KEPT, ("broken.py", BROKEN_SOURCE)]);
    let good = indexed(&clean);
    let bad = indexed(&degraded);

    assert_eq!(
        good.index().revision(),
        bad.index().revision(),
        "a source that stated no inventory is a source the index does not hold"
    );
    assert_ne!(
        good.revision(),
        bad.revision(),
        "but a caller is told something different, so the state identity moves"
    );
    assert_ne!(
        good.revision().to_string(),
        good.index().revision().to_string(),
        "an index claim and a state claim over it are sealed apart"
    );
}

/// Two repositories failing at different paths state different states.
fn the_scope_an_issue_names_moves_the_state() {
    let here = indexed(&Repository::of(&[KEPT, ("b.py", BROKEN_SOURCE)]));
    let there = indexed(&Repository::of(&[KEPT, ("c.py", BROKEN_SOURCE)]));

    assert_eq!(
        here.index().revision(),
        there.index().revision(),
        "neither failed source is admitted, so both indexes hold the same corpus"
    );
    assert_ne!(
        here.revision(),
        there.revision(),
        "and the scope an issue names is part of what the caller was told"
    );
    assert_ne!(
        issue_rows(&here),
        issue_rows(&there),
        "which is visible in the rows themselves: {:?} against {:?}",
        issue_rows(&here),
        issue_rows(&there)
    );
}

/// The same path failing for a different reason states a different state.
fn the_stage_and_code_move_the_state() {
    let unparsed = Repository::of(&[KEPT, ("b.py", BROKEN_SOURCE)]);
    let undecodable = Repository::of(&[KEPT]);
    undecodable.write_bytes("b.py", UNDECODABLE);

    let parsed = indexed(&unparsed);
    let decoded = indexed(&undecodable);
    assert_eq!(
        parsed.index().revision(),
        decoded.index().revision(),
        "the same admitted corpus is the same index"
    );
    assert_eq!(
        issue_rows(&parsed).len(),
        issue_rows(&decoded).len(),
        "each states one issue about the same path"
    );
    assert_ne!(
        issue_rows(&parsed),
        issue_rows(&decoded),
        "at a different stage and under a different code"
    );
    assert_ne!(
        parsed.revision(),
        decoded.revision(),
        "so the two callers were told different things"
    );
}

/// Two refusals equal in scope, stage, code, and staleness still state
/// different states when they say different things.
///
/// A total-byte ceiling is what makes this row possible: the ceiling refuses
/// the second source in both repositories, so both indexes hold exactly the
/// first, both issues sit on the same path under the same code — and the
/// refusal names the count that would have passed the ceiling, which the two
/// repositories do not share. Without the message in the claim these two
/// states are one.
fn the_message_alone_moves_the_state() {
    let ceiling = KEPT.1.len() as u64;
    let refused = |contents: &str| {
        let repository = Repository::of(&[KEPT, ("b.py", contents)]);
        built(
            &repository,
            &[],
            lowered(|limits| limits.max_total_source_bytes = ceiling),
        )
        .expect("a total-byte ceiling degrades the corpus rather than ending the build")
    };

    let shorter = refused(SECOND.1);
    let longer = refused("def b():\n    return 22\n");

    assert_eq!(
        shorter.index().revision(),
        longer.index().revision(),
        "the ceiling admits the same one source in both, so both indexes are equal"
    );
    assert_eq!(
        issue_rows(&shorter),
        issue_rows(&longer),
        "both refusals name the same path, stage, code, and staleness"
    );
    // A two-element array rather than a collected list: the pair is what the
    // row is about, and the arity belongs in the type of the thing it indexes.
    let messages: [&str; 2] = [&shorter, &longer].map(|state| {
        state
            .issues()
            .first()
            .expect("the ceiling recorded its refusal")
            .message()
    });
    assert_ne!(
        messages[0], messages[1],
        "and each states the count that would have passed the ceiling: {messages:?}"
    );
    assert_ne!(
        shorter.revision(),
        longer.revision(),
        "so what the caller was told moves even when every other field is equal"
    );
}

/// Equal issues in equal order state one state identity, whatever order the
/// repository produced them in.
fn equal_sorted_issues_agree() {
    let rows: &[(&str, &str)] = &[KEPT, ("b.py", BROKEN_SOURCE), ("c.py", BROKEN_SOURCE)];
    let first = indexed(&Repository::of(rows));
    let second = indexed(&Repository::of_reversed(rows));
    assert_eq!(
        issue_rows(&first).len(),
        2,
        "both sources refused: {:?}",
        issue_rows(&first)
    );
    assert_eq!(
        first.revision(),
        second.revision(),
        "equal sorted issues over equal indexes are one state"
    );

    let single = indexed(&Repository::of(&[KEPT, ("b.py", BROKEN_SOURCE)]));
    assert_ne!(
        first.revision(),
        single.revision(),
        "and how many issues a state carries is part of it"
    );
}

/// A handle another revision issued refuses before it reads a position.
pub fn stale_handles_refuse_before_lookup() {
    let first = Repository::of(&[KEPT]);
    let second = Repository::of(&[EDITED]);
    let held = indexed(&first);
    let other = indexed(&second);

    let structure = held
        .index()
        .structures()
        .first()
        .expect("the fixture states one structure");
    let handle = StructureHandle::new(held.index().revision(), structure.id().position());
    assert_eq!(
        held.index()
            .structure(handle)
            .expect("its own handle selects it")
            .id(),
        structure.id(),
        "a handle from this revision reads this revision"
    );

    let stale = StructureHandle::new(other.index().revision(), structure.id().position());
    assert!(
        matches!(
            held.index().structure(stale),
            Err(CodeIntelligenceError::StaleRevision)
        ),
        "equal positions in different revisions cannot select each other's structures"
    );
    assert!(
        matches!(
            held.index()
                .structure(StructureHandle::new(held.index().revision(), 4_096)),
            Err(CodeIntelligenceError::UnknownStructure)
        ),
        "and a position this revision does not hold is unknown rather than stale"
    );
    assert!(
        matches!(
            held.index()
                .project(ProjectHandle::new(other.index().revision(), 0)),
            Err(CodeIntelligenceError::StaleRevision)
        ),
        "a project handle is guarded the same way"
    );
    assert!(
        matches!(
            held.index()
                .project(ProjectHandle::new(held.index().revision(), 0)),
            Err(CodeIntelligenceError::UnknownProject)
        ),
        "and a repository with no project states none at position zero"
    );
}
