//! Bounded waits over the two liveness questions each host answers.
//!
//! Both questions are the host's — one about a process, one about the tree a
//! guarded child rooted — and both are polled the same way, so the polling is
//! stated once rather than beside each host's answer. The schedule and the
//! budget are [`crate::poll`]'s, which the fixture's own waits share.

use std::time::Duration;

use super::{ContainedProcessTree, process_is_running};
use crate::poll::until_answered;

/// Wait until a watched process is gone or the budget expires.
pub fn wait_until_gone(pid: u32, budget: Duration) -> bool {
    wait_until_absent(|| process_is_running(pid), budget)
}

/// Wait until every member of a contained tree is gone or the budget expires.
pub fn wait_until_released(tree: &ContainedProcessTree, budget: Duration) -> bool {
    wait_until_absent(|| tree.is_running(), budget)
}

/// Whether a contained tree still holds a member, asked through its owner.
///
/// The tree is borrowed so its operating-system containment object remains
/// live while the question is answered.
pub fn tree_is_live(tree: &ContainedProcessTree) -> bool {
    tree.is_running()
}

/// Poll one liveness question until it answers absent or the budget expires.
///
/// Absence is what this wait is waiting for, so absence is what it hands the
/// poll as an answer: a question still reporting the subject present has not
/// answered yet. The budget, the schedule, and what an unnameable deadline
/// means are [`until_answered`]'s.
fn wait_until_absent(present: impl Fn() -> bool, budget: Duration) -> bool {
    let absence = || match present() {
        true => None,
        false => Some(()),
    };
    until_answered(absence, budget).is_some()
}
