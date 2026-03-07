use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Capability;

/// A source code location.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SourceLocation {
    /// File path relative to the crate root.
    pub file: Arc<str>,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub column: usize,
}

/// A single capability finding at a specific location.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityFinding {
    /// The capability detected.
    pub capability: Capability,
    /// Where in source the capability was found.
    pub location: SourceLocation,
    /// Human-readable evidence (e.g. the function call or expression).
    pub evidence: Arc<str>,
}
