//! The one capability finding every non-resolution case starts from.
//!
//! Four case modules assert about the same record shape. Stating it once means
//! a field the model gains appears in one place, and a case that varies a field
//! says so by overriding it rather than by restating the other six.

use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, SourceLocation};

/// A finding with every optional field absent, at the given site.
pub fn sample_finding(capability: Capability, file: &str, line: usize) -> CapabilityFinding {
    CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::from(file),
            line,
            column: 1,
        },
        evidence: Arc::from("test evidence"),
        origin: None,
        language: None,
        execution_context: None,
        reachable: None,
    }
}
