//! Adoption of a child this process owns rather than merely names.
//!
//! `adopting` takes a name and cleans nothing up, because a caller that named a
//! child rather than lending one is the only owner in a position to end it. A
//! caller that lends its own `Child` *is* in that position, so this is where the
//! refused adoption's cleanup belongs.
//!
//! Stated once over the naming each host supplies. The two hosts differ in what
//! a live child is named by and in nothing else, so a per-host copy of this
//! function was a second place for the cleanup rule to be written and to go
//! stale.

use std::process::Child;

use super::cleanup::with_cleanup;
use super::error::ContainmentError;
#[cfg(unix)]
use super::unix::{ContainedProcessTree, naming};
#[cfg(windows)]
use super::windows::{ContainedProcessTree, naming};

/// Adopt a child this process owns, killing it if containment refuses.
pub fn adopt_child(child: &mut Child) -> Result<ContainedProcessTree, ContainmentError> {
    ContainedProcessTree::adopting(naming(child)).map_err(|refusal| with_cleanup(refusal, child))
}
