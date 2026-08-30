//! The paged contract, stated once for every paged operation.
//!
//! `list_projects` and `search_symbols` page over different records and answer
//! to the same rules: the default size, the traversal, the size bounds, and the
//! refusal a cursor that does not continue this query earns. Writing those five
//! claims twice would let one operation's page contract drift from the other's,
//! which is the failure a shared response envelope exists to prevent.
//!
//! The last of the five is [`binding`](super::binding), which this file's entry
//! point calls and which reads its vocabulary and its call helpers from here.
//! Two files, because what a page *is* and what a cursor *stops continuing* are
//! read for different questions — and one file holding both outran this tree's
//! source ceiling.
//!
//! The page size, the next offset, and the two revisions are stated by that
//! table for the same reason the rows here are stated once. None of them is a
//! parameter of any query. The sizes are the two fields a `PageRequest` carries
//! whatever it is paging over, and the revisions are the two identities every
//! answer carries whatever it is answering. An operation holding its own copy
//! of those rows would be restating this contract, and an operation holding
//! none of them would be the one whose cursor stopped binding them.
//!
//! What stays with each caller is the drift table over the parameters that
//! operation selects by, because those are its own and this file does not know
//! them, and the fixtures the revision rows are taken over, because only the
//! caller knows what a second index of its own records looks like.
//!
//! One row is the caller's for a third reason.
//! [`a_default_cursor_continues_at_fifty`] needs a result that outruns one
//! default page, and an operation whose fixture states four records has none.
//! So the caller states whether its fixture is long enough, the contract checks
//! that statement against the result and takes the row where it says yes, and a
//! caller that said no owes the row over a longer fixture of its own. Stated
//! rather than measured, because a row taken only where the length happened to
//! allow it disappears in silence the day the fixture shrinks.

use pedant_snippet::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, CodeIntelligenceState, IndexRevision,
    PageCursor, PageRequest, StateRevision,
};

use super::answer::Answer;
use super::binding::cursor_bindings_hold;
use super::operation::PageCall;
use super::support::page;

/// The two identities one state publishes with every answer it gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revisions {
    /// The identity of the index the answer was taken over.
    pub index: IndexRevision,
    /// The identity of the state, which the issues qualifying that index move.
    pub state: StateRevision,
}

impl Revisions {
    /// The two identities one built state publishes.
    pub fn of(state: &CodeIntelligenceState) -> Self {
        Self {
            index: state.index().revision(),
            state: state.revision(),
        }
    }
}

/// One paged operation, the operation whose cursors it must refuse, and the two
/// states whose cursors it must refuse for a revision it does not share.
///
/// The two revision fixtures are supplied rather than described: this file
/// states what a cursor is bound to, and the caller states which records make a
/// second index and which make a second health over one index.
pub struct Paged<Call: PageCall, Other: PageCall, Elsewhere: PageCall, Degraded: PageCall> {
    /// What this operation is called in a failure message.
    pub label: &'static str,
    /// Run one page of it.
    pub call: Call,
    /// The two identities the state `call` pages over publishes.
    pub revisions: Revisions,
    /// Run one page of the other paged operation over the same state.
    pub other: Other,
    /// Run one page of this operation over a state holding another index.
    pub elsewhere: Elsewhere,
    /// The two identities that state publishes.
    pub elsewhere_revisions: Revisions,
    /// Run one page of this operation over a state holding an equal index and
    /// a different health.
    pub degraded: Degraded,
    /// The two identities that state publishes.
    pub degraded_revisions: Revisions,
    /// Whether this operation's whole result outruns one default page.
    ///
    /// Stated by the caller and checked against the result, so the one row a
    /// short fixture cannot take is owned rather than skipped: a table that
    /// simply took the row where the result happened to be long enough went
    /// quiet the day its fixture shrank, and nothing said so.
    pub outruns_default: bool,
}

/// The largest page the host admits, which is the published `max_page_items`.
///
/// Published, because the operations that page over a whole result ask for it
/// by name too, and a second `200` written at those call sites is a second
/// place the host's own ceiling has to be revisited.
pub const CEILING: u32 = 200;

/// The page a request that states no size asks for.
const DEFAULT_SIZE: u32 = 50;

/// Everything the paged contract states, whichever operation is paging.
pub fn paged_contract_holds<
    Call: PageCall,
    Other: PageCall,
    Elsewhere: PageCall,
    Degraded: PageCall,
>(
    paged: &Paged<Call, Other, Elsewhere, Degraded>,
) {
    let whole = whole_result(paged.label, &paged.call);
    assert!(
        whole.len() > 2,
        "{}: the fixture states three items or more, or a page of one leaves no \
         second cursor for the offset row to rewrite",
        paged.label
    );

    assert_eq!(
        paged.outruns_default,
        whole.len() > DEFAULT_SIZE as usize,
        "{}: the caller states whether its fixture outruns one default page, and it holds \
         {} items",
        paged.label,
        whole.len()
    );

    the_default_page_size_is_fifty(paged.label, &paged.call, &whole);
    if paged.outruns_default {
        a_default_cursor_continues_at_fifty(paged.label, &paged.call, &whole);
    }
    every_size_traverses_every_item_once(paged.label, &paged.call, &whole);
    sizes_outside_the_range_refuse_before_lookup(paged.label, &paged.call);
    cursor_bindings_hold(paged);
}

/// One page of `call`, or a panic naming what refused.
///
/// Published beside the contract because the cursor-binding table pages the
/// same operations through it, and a second spelling there would be a second
/// place a refusal is reported from.
pub fn answered<Call: PageCall>(label: &str, call: &Call, request: &PageRequest) -> Answer {
    call(request).unwrap_or_else(|error| panic!("{label}: this page should answer: {error}"))
}

/// Every item this operation states, taken in one page.
pub fn whole_result<Call: PageCall>(label: &str, call: &Call) -> Box<[String]> {
    let answer = answered(label, call, &page(Some(CEILING), None));
    assert!(
        answer.next.is_none(),
        "{label}: the fixture fits in one maximum page, or this table proves nothing"
    );
    answer.identities
}

/// The cursor one page of `size` items from the start of this operation leaves.
pub fn opening_cursor<Call: PageCall>(label: &str, call: &Call, size: u32) -> PageCursor {
    answered(label, call, &page(Some(size), None))
        .next
        .unwrap_or_else(|| panic!("{label}: a page of {size} leaves a continuation"))
}

/// One supplied cursor is refused at the size it was minted for, and nothing is
/// answered from it.
///
/// The replay size is the minted size on purpose. A cursor replayed at another
/// size drifts for two reasons at once, and the page size is a dimension
/// `the_page_size_binds_the_cursor` owns on its own — a row that varied both
/// would leave the one it names unproven.
pub fn assert_cursor_refused<Call: PageCall>(
    label: &str,
    call: &Call,
    cursor: PageCursor,
    minted_at: u32,
    why: &str,
) {
    assert_refused(
        call(&page(Some(minted_at), Some(cursor))),
        &format!("{label}: {why}"),
    );
}

/// One attempted continuation states that this cursor does not continue it.
pub fn assert_refused(outcome: Result<Answer, CodeIntelligenceError>, why: &str) {
    match outcome {
        Err(CodeIntelligenceError::CursorDrift) => {}
        Err(other) => panic!("{why} refuses as a drifted cursor, not: {other}"),
        Ok(answer) => panic!(
            "{why} must not continue this query, but answered {} items",
            answer.identities.len()
        ),
    }
}

/// An omitted page size is fifty, and continues exactly when fifty would.
///
/// Whether the page continues is asserted against the result's own length
/// rather than left to a branch. A row that only replayed the cursor it happened
/// to be handed reported green over an operation whose fixture fits inside one
/// default page, because it never took the claim at all — and only the caller
/// knows which of its fixtures outruns fifty.
fn the_default_page_size_is_fifty<Call: PageCall>(label: &str, call: &Call, whole: &[String]) {
    let implied = answered(label, call, &page(None, None));
    let explicit = answered(label, call, &page(Some(DEFAULT_SIZE), None));
    let size = DEFAULT_SIZE as usize;
    assert_eq!(
        implied.identities, explicit.identities,
        "{label}: an omitted page size states the same page an explicit fifty does"
    );
    assert_eq!(
        implied.identities.len(),
        whole.len().min(size),
        "{label}: and that page holds fifty items or the whole result"
    );
    assert_eq!(
        implied.next.is_some(),
        explicit.next.is_some(),
        "{label}: and continues on the same terms"
    );
    assert_eq!(
        implied.next.is_some(),
        whole.len() > size,
        "{label}: and continues exactly when the whole result outruns one default page"
    );
}

/// A cursor minted under the omitted default continues under an explicit fifty.
///
/// Published, because it is the one row of this contract an operation's own
/// fixture can leave untaken: a result that fits inside one default page leaves
/// no continuation to replay. `paged_contract_holds` takes it wherever the
/// caller states its fixture is long enough, and a caller whose fixture is
/// shorter owes this row over one that is not.
///
/// The claim is that the admitted size is what a cursor records. A binding that
/// wrote down "no size was stated" instead would refuse this replay, and the
/// caller who omitted the size on the first page and spelled it on the second
/// would be stranded there.
///
/// The second page is compared to the items the whole result holds after the
/// first fifty, not merely asked to be non-empty. A binding that accepted the
/// cursor and then restarted at offset zero answers fifty items and satisfies
/// an emptiness check, which is the one failure this row exists to catch.
pub fn a_default_cursor_continues_at_fifty<Call: PageCall>(
    label: &str,
    call: &Call,
    whole: &[String],
) {
    let size = DEFAULT_SIZE as usize;
    let cursor = answered(label, call, &page(None, None))
        .next
        .unwrap_or_else(|| panic!("{label}: a result past one default page leaves a continuation"));
    let continued = answered(label, call, &page(Some(DEFAULT_SIZE), Some(cursor)));
    assert_eq!(
        &*continued.identities,
        &whole[size..whole.len().min(size * 2)],
        "{label}: a cursor minted under the default size continues at the item the first \
         page stopped at"
    );
}

/// Every admitted page size traverses every item exactly once, in one order.
fn every_size_traverses_every_item_once<Call: PageCall>(
    label: &str,
    call: &Call,
    whole: &[String],
) {
    for size in [1_u32, 50, CEILING] {
        assert_eq!(
            &*traversed(label, call, size, whole.len()),
            whole,
            "{label}: pages of {size} traverse every item exactly once, in the whole result's order"
        );
    }
}

/// Every item pages of `size` state, in the order they state them.
///
/// One page per item is the most any admitted size can need, and the bound is
/// what makes a cursor that never terminates a failure rather than a hung run.
/// A traversal that ran past it states more items than the whole result holds,
/// and one that stopped early states fewer, so the caller's comparison names
/// either as the same failure it names a reordering.
fn traversed<Call: PageCall>(label: &str, call: &Call, size: u32, items: usize) -> Box<[String]> {
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<PageCursor> = None;
    for _ in 0..=items {
        let answer = answered(label, call, &page(Some(size), cursor));
        assert!(
            answer.identities.len() <= size as usize,
            "{label}: a page of {size} never states more than {size} items"
        );
        seen.extend(answer.identities);
        match answer.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    seen.into_boxed_slice()
}

/// A page size below one or above the host ceiling refuses before any record is
/// read.
fn sizes_outside_the_range_refuse_before_lookup<Call: PageCall>(label: &str, call: &Call) {
    match call(&page(Some(0), None)) {
        Err(CodeIntelligenceError::EmptyPage) => {}
        other => panic!(
            "{label}: a page of zero states a page nobody can read: {}",
            answered_items(&other)
        ),
    }

    match call(&page(Some(CEILING + 1), None)) {
        Err(CodeIntelligenceError::Capacity {
            owner: CapacityOwner::Repository,
            collection: CapacityCollection::PageItem,
            observed,
            limit,
        }) => {
            assert_eq!(observed, u64::from(CEILING) + 1, "{label}");
            assert_eq!(limit, u64::from(CEILING), "{label}");
        }
        other => panic!(
            "{label}: a page above the host ceiling is a capacity refusal: {}",
            answered_items(&other)
        ),
    }
}

/// One attempted page as a failure message names it.
///
/// Named apart from `support::rendered` rather than shadowing it: the two
/// differ only in the `Ok` arm, and a reader of a panic message could not tell
/// which of the two produced it. This one reports how many items answered,
/// which is the number a size or capacity row is about.
fn answered_items(outcome: &Result<Answer, CodeIntelligenceError>) -> String {
    match outcome {
        Ok(answer) => format!("{} items", answer.identities.len()),
        Err(error) => error.to_string(),
    }
}
