use std::sync::Arc;

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Capability, ExecutionContext, FindingOrigin, Language};

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
#[derive(Serialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityFinding {
    /// Which capability this finding represents.
    pub capability: Capability,
    /// Source position of the triggering expression or import.
    pub location: SourceLocation,
    /// Snippet of the triggering code (e.g., the import path or literal).
    pub evidence: Arc<str>,
    /// How the capability was detected (import, string literal, attribute, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<FindingOrigin>,
    /// Source language of the analyzed file, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// When during the lifecycle this code executes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_context: Option<ExecutionContext>,
    /// Reachability from a public entry point.
    ///
    /// `None` when DataFlow analysis is unavailable. `Some(true)` when
    /// reachable, `Some(false)` when dead code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
}

impl<'de> Deserialize<'de> for CapabilityFinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            capability: Capability,
            location: SourceLocation,
            evidence: Arc<str>,
            #[serde(default)]
            origin: Option<FindingOrigin>,
            #[serde(default)]
            language: Option<Language>,
            #[serde(default)]
            execution_context: Option<ExecutionContext>,
            #[serde(default)]
            build_script: Option<bool>,
            #[serde(default)]
            reachable: Option<bool>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let execution_context = match (raw.execution_context, raw.build_script) {
            (Some(ExecutionContext::BuildHook), Some(true)) => Some(ExecutionContext::BuildHook),
            (Some(ExecutionContext::BuildHook), Some(false)) => {
                return Err(D::Error::custom(
                    "execution_context=build_hook contradicts legacy build_script=false",
                ));
            }
            (Some(ctx), Some(true)) => {
                return Err(D::Error::custom(format!(
                    "execution_context={ctx:?} contradicts legacy build_script=true"
                )));
            }
            (Some(ctx), Some(false) | None) => Some(ctx),
            (None, Some(true)) => Some(ExecutionContext::BuildHook),
            (None, Some(false) | None) => None,
        };
        Ok(Self {
            capability: raw.capability,
            location: raw.location,
            evidence: raw.evidence,
            origin: raw.origin,
            language: raw.language,
            execution_context,
            reachable: raw.reachable,
        })
    }
}

impl CapabilityFinding {
    /// Returns `true` when this finding comes from a build-time execution context
    /// (e.g., `build.rs` or equivalent).
    pub fn is_build_hook(&self) -> bool {
        self.execution_context == Some(ExecutionContext::BuildHook)
    }
}
