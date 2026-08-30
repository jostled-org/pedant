//! What kind of evidence one answer rests on.
//!
//! The point of the type is the last variant pair. A syntax-only source has a
//! complete outline and no resolved references, and a graph query over it must
//! say so rather than return an empty neighborhood — an empty answer and "this
//! language has no resolver in this build" are the same bytes and opposite
//! facts.

use serde::Deserialize;

use super::serialize::serialize_token;

/// What evidence stands behind one structure, slice, or answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructureCoverage {
    /// A resolver proved the evidence.
    Resolved,
    /// A resolver stated candidates it could not narrow to one.
    Possible,
    /// The source has a complete structure inventory and no resolver.
    SyntaxOnly,
    /// No evidence of this kind exists for the requested entity.
    Unavailable,
}

impl StructureCoverage {
    /// The stable token this coverage is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Possible => "possible",
            Self::SyntaxOnly => "syntax_only",
            Self::Unavailable => "unavailable",
        }
    }
}

serialize_token!(StructureCoverage);
