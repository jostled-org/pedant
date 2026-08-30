//! What a page cursor is bound to, one dimension at a time.
//!
//! Every row here holds every other dimension equal and replays the cursor at
//! the size it was minted for, so a refusal is explained by the dimension the
//! row names and by nothing else. What binds a cursor is one subject:
//! [`paging`](super::paging) states what a page *is* — the default size, the
//! traversal, and the admitted range — and this file states what a cursor
//! stops continuing.
//!
//! Its own module rather than a block inside that one, because the two are read
//! for different questions and one file holding both outran this tree's source
//! ceiling.

use pedant_snippet::PageCursor;

use super::operation::PageCall;
use super::paging::{Paged, answered, assert_cursor_refused, assert_refused, opening_cursor};
use super::support::page;

/// How many hex digits at the end of a rendered cursor state its offset.
///
/// Derived from the width the cursor writes rather than spelled as a number.
/// The offset is a `u32` written big-endian and the token renders one byte as
/// two hex digits, so an offset that grew a byte moves this split here instead
/// of leaving [`the_next_offset_binds_the_cursor`] rewriting the tail of the
/// digest and calling the refusal it earns an offset claim.
const OFFSET_DIGITS: usize = size_of::<u32>() * 2;

/// Every claim about what one cursor is bound to.
pub fn cursor_bindings_hold<
    Call: PageCall,
    Other: PageCall,
    Elsewhere: PageCall,
    Degraded: PageCall,
>(
    paged: &Paged<Call, Other, Elsewhere, Degraded>,
) {
    the_page_size_binds_the_cursor(paged.label, &paged.call);
    the_next_offset_binds_the_cursor(paged.label, &paged.call);
    a_tampered_cursor_refuses(paged.label, &paged.call);
    a_cursor_from_the_other_query_refuses(paged.label, &paged.call, &paged.other);
    the_index_revision_binds_the_cursor(paged);
    the_state_revision_binds_the_cursor(paged);
    a_malformed_cursor_never_reaches_the_query();
}

/// A cursor whose bytes were changed continues nothing.
fn a_tampered_cursor_refuses<Call: PageCall>(label: &str, call: &Call) {
    let cursor = opening_cursor(label, call, 1);
    let rendered = serde_json::to_string(&cursor).expect("a cursor serializes");
    // The quotes are not the cursor, so the walk runs between them — and a
    // rendering of two characters or fewer leaves it nothing to change. Stated
    // before the range is built, because an empty rendering makes the bound
    // itself an underflow rather than a walk of no rows.
    assert!(
        rendered.len() > 2,
        "{label}: a rendered cursor holds digits between its quotes to change: {rendered}"
    );

    let mut refused = 0_usize;
    for position in 1..rendered.len() - 1 {
        let tampered = flipped(&rendered, position);
        let parsed: PageCursor =
            serde_json::from_str(&tampered).expect("a flipped hex digit is still a cursor");
        assert_cursor_refused(label, call, parsed, 1, "a cursor with one changed digit");
        refused += 1;
    }
    assert_eq!(
        refused,
        rendered.len() - 2,
        "{label}: every digit between the quotes was changed, and every one of them refused"
    );
}

/// The other paged operation's cursor continues nothing here.
///
/// Both cursors are minted at a page of one and replayed at a page of one over
/// the same state, so the two revisions, the size, and the offset all agree and
/// the operation that minted it is the only thing that differs.
fn a_cursor_from_the_other_query_refuses<Call: PageCall, Other: PageCall>(
    label: &str,
    call: &Call,
    other: &Other,
) {
    let foreign = opening_cursor(label, other, 1);
    assert_cursor_refused(
        label,
        call,
        foreign,
        1,
        "a cursor from the other paged query",
    );
}

/// A cursor another index minted continues nothing here.
///
/// The guard above the replay is what makes the row a row: two fixtures that
/// happened to state one index would refuse nothing for the reason this claims,
/// and a caller that supplied the same repository twice would still go green.
fn the_index_revision_binds_the_cursor<
    Call: PageCall,
    Other: PageCall,
    Elsewhere: PageCall,
    Degraded: PageCall,
>(
    paged: &Paged<Call, Other, Elsewhere, Degraded>,
) {
    assert_ne!(
        paged.elsewhere_revisions.index, paged.revisions.index,
        "{}: the two fixtures are two indexes",
        paged.label
    );
    let foreign = opening_cursor(paged.label, &paged.elsewhere, 1);
    assert_cursor_refused(
        paged.label,
        &paged.call,
        foreign,
        1,
        "a cursor another index minted",
    );
}

/// A cursor survives no health transition, even where the index is equal.
///
/// The cursor is minted over the degraded state and replayed over this
/// operation's own, which is the transition in the direction a caller meets it:
/// a page taken while an issue stood, continued after the issue went away. The
/// index identities are asserted equal first, because a cursor refused by a
/// state whose index also moved would say nothing about health.
fn the_state_revision_binds_the_cursor<
    Call: PageCall,
    Other: PageCall,
    Elsewhere: PageCall,
    Degraded: PageCall,
>(
    paged: &Paged<Call, Other, Elsewhere, Degraded>,
) {
    assert_eq!(
        paged.degraded_revisions.index, paged.revisions.index,
        "{}: a source that stated no inventory is a source neither index holds",
        paged.label
    );
    assert_ne!(
        paged.degraded_revisions.state, paged.revisions.state,
        "{}: but the two callers were told different things",
        paged.label
    );
    let minted = opening_cursor(paged.label, &paged.degraded, 1);
    assert_cursor_refused(
        paged.label,
        &paged.call,
        minted,
        1,
        "a cursor minted while an issue stood",
    );
}

/// A cursor minted for one page size continues no other size.
///
/// Both replays hold every other dimension equal: the same state, the same
/// query, and the offset the cursor itself carries. The omitted size is the
/// second row because a request that states no size is a request for fifty. A
/// binding that read the request rather than the admitted size would let a
/// cursor minted at one continue there.
fn the_page_size_binds_the_cursor<Call: PageCall>(label: &str, call: &Call) {
    let cursor = opening_cursor(label, call, 1);
    assert_refused(
        call(&page(Some(2), Some(cursor))),
        &format!("{label}: a cursor minted for a page of one, continued at two"),
    );
    assert_refused(
        call(&page(None, Some(cursor))),
        &format!("{label}: a cursor minted for a page of one, continued at the omitted default"),
    );
}

/// The offset a cursor carries is part of it, so no caller rewinds or advances
/// one by hand.
///
/// The last [`OFFSET_DIGITS`] hex digits are the offset. Rewriting them leaves a
/// well-formed cursor this query never minted, which is the only way a caller
/// asks for a page nobody offered.
///
/// The rewind is the row that owns the binding. Zero is an offset every
/// traversal above answers at, so no range guard explains its refusal — only
/// the offset having entered the claim does. The advance past the end is the
/// second row: a truncated result presented as complete is the one answer a
/// paged contract must never give, so it must refuse rather than state an empty
/// page.
fn the_next_offset_binds_the_cursor<Call: PageCall>(label: &str, call: &Call) {
    let first = opening_cursor(label, call, 1);
    let second = answered(label, call, &page(Some(1), Some(first)))
        .next
        .unwrap_or_else(|| panic!("{label}: the second page of one leaves a third"));
    let rendered = serde_json::to_string(&second).expect("a cursor serializes");
    assert_ne!(
        serde_json::to_string(&first).expect("a cursor serializes"),
        rendered,
        "{label}: two offsets are two cursors"
    );

    let digits = rendered.trim_matches('"');
    let head = digits
        .len()
        .checked_sub(OFFSET_DIGITS)
        .and_then(|cut| digits.get(..cut))
        .expect("a cursor states more than its offset");
    for (offset, why) in [
        (0, "a cursor rewound to the page it already answered"),
        (u32::MAX, "a cursor advanced past every item it could state"),
    ] {
        let rewritten: PageCursor = serde_json::from_str(&format!(
            "\"{head}{offset:0digits$x}\"",
            digits = OFFSET_DIGITS
        ))
        .expect("an offset written by hand is still a well-formed cursor");
        assert_cursor_refused(label, call, rewritten, 1, why);
    }
}

/// A token that is not a cursor never becomes one.
fn a_malformed_cursor_never_reaches_the_query() {
    for malformed in ["\"\"", "\"zz\"", "\"0011\"", "\"0011ZZ\"", "12"] {
        assert!(
            serde_json::from_str::<PageCursor>(malformed).is_err(),
            "{malformed} is not a page cursor"
        );
    }
}

/// One serialized cursor with the hex digit at `position` changed.
fn flipped(rendered: &str, position: usize) -> String {
    let mut bytes = rendered.as_bytes().to_vec();
    let digit = bytes[position];
    bytes[position] = match digit {
        b'0' => b'1',
        _ => b'0',
    };
    String::from_utf8(bytes).expect("a hex digit swap stays UTF-8")
}
