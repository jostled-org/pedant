//! One bounded poll, shared by every wait this crate makes.
//!
//! Three waits ask different questions — is a tree gone, does the release file
//! exist yet, what pid did the fixture record — and all three ask on the same
//! schedule against the same kind of budget. Written out at each wait, the
//! schedule and the overflow rule were three chances to disagree about how long
//! a caller's budget lasts. They are stated once here instead, so a wait added
//! later cannot get either wrong.

use std::time::{Duration, Instant};

/// How long a poll sleeps between two readings of its question.
const POLL: Duration = Duration::from_millis(25);

/// Ask one question until it answers or the budget expires.
///
/// `Some` is the answer and ends the wait; `None` is "not yet". A budget that
/// runs out with the question still unanswered is reported as `None` rather
/// than waited past.
///
/// A budget no clock can name is an unbounded wait, not a panic: `Instant`
/// addition ends the process on overflow, and neither a library polling on a
/// caller's duration nor a fixture waiting on its own file may take a test host
/// down over one.
pub(crate) fn until_answered<T>(question: impl Fn() -> Option<T>, budget: Duration) -> Option<T> {
    let deadline = Instant::now().checked_add(budget);
    loop {
        match (
            question(),
            deadline.is_some_and(|deadline| Instant::now() >= deadline),
        ) {
            (Some(answer), _) => return Some(answer),
            (None, true) => return None,
            (None, false) => std::thread::sleep(POLL),
        }
    }
}
