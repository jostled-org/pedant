use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Capability;

/// File, line, and column of a capability finding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    /// Absolute path; `Arc` because many findings share the same file.
    pub file: Arc<str>,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub column: usize,
}

/// Evidence that a specific capability is exercised at a source location.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityFinding {
    /// Which capability this finding represents.
    pub capability: Capability,
    /// Source position of the triggering expression or import.
    pub location: SourceLocation,
    /// Snippet of the triggering code (e.g., the import path or literal).
    pub evidence: Arc<str>,
    /// `true` when the finding comes from a `build.rs` (compile-time execution).
    #[serde(default, skip_serializing_if = "is_false")]
    pub build_script: bool,
    /// Reachability from a public entry point.
    ///
    /// `None` when DataFlow analysis is unavailable. `Some(true)` when
    /// reachable, `Some(false)` when dead code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
}

fn is_false(v: &bool) -> bool {
    !v
}
