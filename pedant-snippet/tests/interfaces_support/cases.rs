//! The guard every table-driven case in this root closes its loop with.
//!
//! A journey collects one outcome per row and then asserts something about each
//! collected outcome. Nothing in that shape states how many rows there were, so
//! a row that never ran at all — skipped by a filter, dropped by a `zip` that
//! stopped at the shorter side, lost to a `continue` — narrows the whole claim
//! and reports success. The length equality is what refuses that, and it belongs
//! to one owner: written inline, it is a line a reader can delete without
//! deleting anything that looks like an assertion.
//!
//! Named `cases` because that is where the retired single-file case table kept
//! it. The table left; the guard it carried is what every successor still owes.

/// Every stated row produced an outcome.
///
/// `subject` names the table, so a failure says which loop narrowed rather than
/// only that two numbers differ.
pub(crate) fn assert_every_row_ran<Outcome, Row>(ran: &[Outcome], stated: &[Row], subject: &str) {
    assert_eq!(
        ran.len(),
        stated.len(),
        "{subject}: {} of {} rows produced an outcome, so the assertions below \
         range over fewer rows than the table states",
        ran.len(),
        stated.len()
    );
}
