//! What a refused adoption does with the child it could not contain.
//!
//! Adoption is the last thing that can fail before a caller holds a guard, and
//! a child left behind by that failure is uncontained by definition. Both hosts
//! end it the same way and report it the same way, so the ending and the
//! reporting are both stated once here.

use std::process::Child;

use super::error::ContainmentError;

/// Report the cleanup a refused adoption had to perform, where it performed one.
///
/// The wrapping is unconditional in the refusal: every refusal a host can state
/// during adoption leaves the same uncontained child behind, so none of them is
/// a case where a cleanup failure may go unreported. A child already gone needs
/// no cleanup, and the refusal travels alone.
pub(super) fn with_cleanup(refusal: ContainmentError, child: &mut Child) -> ContainmentError {
    match cleanup_uncontained_child(child) {
        Some(cleanup) => ContainmentError::Cleanup {
            refusal: Box::new(refusal),
            cleanup,
        },
        None => refusal,
    }
}

/// Kill and reap a child no guard ended up owning, if it is still live.
///
/// Reports the failure that stopped the cleanup, and nothing when there was
/// nothing to clean up: a child that already exited needs no killing.
fn cleanup_uncontained_child(child: &mut Child) -> Option<std::io::Error> {
    match child.try_wait() {
        Ok(Some(_)) => None,
        Ok(None) => kill_and_reap(child),
        Err(error) => Some(error),
    }
}

fn kill_and_reap(child: &mut Child) -> Option<std::io::Error> {
    match child.kill() {
        Ok(()) => child.wait().err(),
        Err(error) => Some(error),
    }
}
