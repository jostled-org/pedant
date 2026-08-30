//! The call shape every paged operation is passed to the contract as.
//!
//! Named so each operation is one bound rather than the same signature written
//! out at every function that takes one, and stated apart from the contract so
//! that file holds claims and this one holds the shape they are made about.

use pedant_snippet::{CodeIntelligenceError, PageRequest};

use super::answer::Answer;

/// One page of a paged operation, taken over a state the contract never holds.
pub trait PageCall: Fn(&PageRequest) -> Result<Answer, CodeIntelligenceError> {}

impl<Call: Fn(&PageRequest) -> Result<Answer, CodeIntelligenceError>> PageCall for Call {}
