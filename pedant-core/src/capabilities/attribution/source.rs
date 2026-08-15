//! The callable owner each capability-source fact family states.
//!
//! Every family stamps the same `FileIr::functions` index during extraction, so
//! detection reads it through one route rather than repeating a field access
//! per family.

use crate::ir::facts::{AttributeFact, ExternBlockFact, StringLitFact, UnsafeFact, UsePathFact};

/// The callable owner one capability-source fact states.
pub(crate) trait CapabilitySourceFact {
    /// Index into `FileIr::functions`, or `None` at module scope.
    fn containing_fn(&self) -> Option<usize>;
}

impl CapabilitySourceFact for UsePathFact {
    fn containing_fn(&self) -> Option<usize> {
        self.containing_fn
    }
}

impl CapabilitySourceFact for UnsafeFact {
    fn containing_fn(&self) -> Option<usize> {
        self.containing_fn
    }
}

impl CapabilitySourceFact for ExternBlockFact {
    fn containing_fn(&self) -> Option<usize> {
        self.containing_fn
    }
}

impl CapabilitySourceFact for AttributeFact {
    fn containing_fn(&self) -> Option<usize> {
        self.containing_fn
    }
}

impl CapabilitySourceFact for StringLitFact {
    fn containing_fn(&self) -> Option<usize> {
        self.containing_fn
    }
}
