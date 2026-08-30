//! The page every paged operation answers with, reduced to what the contract
//! reads.
//!
//! Its own module because it is the vocabulary rather than a claim or a call
//! shape: the contract states its rows over it, `operation` names it in the
//! bound every operation is passed as, and each caller builds one from whatever
//! response its own query returns. Stated where any of those three lives, the
//! other two would import their vocabulary from a file about something else.

use pedant_snippet::PageCursor;

/// One page of some paged operation.
pub struct Answer {
    /// One identity per item, in the order the page states them.
    ///
    /// Built by one `collect` and then read: no producer appends to it and no
    /// consumer mutates it, so it owns its exact length.
    pub identities: Box<[String]>,
    /// The cursor that continues this page, absent at the end.
    pub next: Option<PageCursor>,
}
