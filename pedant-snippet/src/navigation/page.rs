//! The one page contract every paged operation runs under.
//!
//! Two operations page, over different records, and both answer to the same
//! rules: one is the default size, one is the admitted range, and one is the
//! binding a continuation has to satisfy. Stated once here, because a second
//! copy is how one operation's page contract drifts from the other's.
//!
//! Order is the contract too. The size is checked before anything is selected,
//! and the cursor is checked before any record is read, so a refusal costs
//! nothing and states no partial page.

use crate::index::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, CodeIntelligenceState, CursorBinding,
    QueryField, RevisionClaim, RevisionClaimInput, capacity,
};

use super::cursor::PageCursor;
use super::page_request::PageRequest;
use super::paged_query::PagedRequest;

/// How many items a page carries when the request states no size.
///
/// Published because both transports advertise it: the schema a client reads
/// and the help a CLI prints both name this number, and a second copy of it is
/// a second thing to change. The CLI is a separate crate from this library, so
/// crate-private is not far enough for the one sentence they share.
pub const DEFAULT_PAGE_SIZE: u32 = 50;

/// One validated page: where it starts and how many items it carries.
pub(super) struct Window {
    offset: u32,
    size: u32,
}

impl Window {
    /// Validate one page request against the state and the query it continues.
    ///
    /// The ceiling is read from the state rather than taken from the caller.
    /// Every pager answers to the one admitted range this module states, and a
    /// pager that supplied its own would be a second page contract under the
    /// first one's name.
    pub(super) fn opened(
        state: &CodeIntelligenceState,
        query: &impl PagedRequest,
        request: &PageRequest,
    ) -> Result<Self, CodeIntelligenceError> {
        let size = admitted(
            request.size,
            state.index().limits().repository.max_page_items,
        )?;
        let offset = match request.cursor {
            None => 0,
            Some(cursor) => resumed(state, query, size, cursor)?,
        };
        Ok(Self { offset, size })
    }

    /// The items this page carries out of every matching item.
    ///
    /// The range and the slice are taken together, so no caller can compute one
    /// and apply the other. A pager that took the range and sliced for itself
    /// had to answer for a range its own items did not hold, and answering with
    /// an empty slice turned an out-of-range window into a page the continuation
    /// cursor below then presented as one of many.
    ///
    /// A cursor whose binding held cannot name an offset past the result it was
    /// minted from, because both revisions and every parameter are part of that
    /// binding. The guard is still a refusal rather than an empty page: a
    /// truncated result presented as complete is the one answer a paged
    /// contract must never give.
    pub(super) fn page<'items, T>(
        &self,
        items: &'items [T],
    ) -> Result<&'items [T], CodeIntelligenceError> {
        let offset = self.offset as usize;
        items
            .get(offset..offset.saturating_add(self.size as usize).min(items.len()))
            .ok_or(CodeIntelligenceError::CursorDrift)
    }

    /// The cursor that continues this page, absent when it is the last one.
    pub(super) fn next(
        &self,
        state: &CodeIntelligenceState,
        query: &impl PagedRequest,
        total: usize,
    ) -> Option<PageCursor> {
        let next = self.offset.saturating_add(self.size);
        ((next as usize) < total)
            .then(|| PageCursor::minted(bound(state, query, self.size, next), next))
    }
}

/// The page size one request states, or why it states none this host admits.
fn admitted(requested: Option<u32>, ceiling: u32) -> Result<u32, CodeIntelligenceError> {
    let size = requested.unwrap_or(DEFAULT_PAGE_SIZE);
    match (size, size > ceiling) {
        (0, _) => Err(CodeIntelligenceError::EmptyPage),
        (_, true) => Err(capacity(
            CapacityOwner::Repository,
            CapacityCollection::PageItem,
            u64::from(size),
            u64::from(ceiling),
        )),
        _ => Ok(size),
    }
}

/// The offset one supplied cursor continues at, or why it continues nothing.
fn resumed(
    state: &CodeIntelligenceState,
    query: &impl PagedRequest,
    size: u32,
    cursor: PageCursor,
) -> Result<u32, CodeIntelligenceError> {
    let offset = cursor.offset();
    match cursor.continues(bound(state, query, size, offset)) {
        true => Ok(offset),
        false => Err(CodeIntelligenceError::CursorDrift),
    }
}

/// The binding one state, query, page size, and offset seal.
///
/// The query's own kind is not written here. It is the argument
/// [`RevisionClaim::seal_cursor`] takes, so this function cannot forget it.
///
/// The size and the offset are written as numbers rather than as their decimal
/// spellings. Both are claimed on every page a request touches — once to check
/// the cursor that arrived and once to mint the cursor that continues — so a
/// spelled parameter cost up to six `String`s per request to hand the encoder
/// digits it hashes as bytes either way.
fn bound(
    state: &CodeIntelligenceState,
    query: &impl PagedRequest,
    size: u32,
    offset: u32,
) -> CursorBinding {
    let index = state.index().revision();
    let published = state.revision();
    let mut claim = RevisionClaim::new();
    claim.write(RevisionClaimInput::IndexIdentity(&index));
    claim.write(RevisionClaimInput::StateIdentity(&published));
    query.claim(&mut claim);
    claim.write(RevisionClaimInput::QueryNumber {
        field: QueryField::PageSize,
        value: u64::from(size),
    });
    claim.write(RevisionClaimInput::QueryNumber {
        field: QueryField::Offset,
        value: u64::from(offset),
    });
    claim.seal_cursor(query.kind())
}
