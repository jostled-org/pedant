//! Why one Go fact extraction refused.

use std::fmt;

use crate::language::SyntaxLanguage;

/// Why a bound session states no Go fact inventory.
///
/// Every variant is a refusal that retains nothing: the extraction returns this
/// instead of a [`GoFileFacts`](super::GoFileFacts), so no caller can mistake a
/// truncated walk for a complete one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoFactError {
    /// The bound session parsed another grammar, so its tree states no Go
    /// facts.
    LanguageMismatch {
        /// The grammar the session was bound to.
        language: SyntaxLanguage,
    },
    /// Descent would have passed the deepest admitted tree level.
    SyntaxDepthExceeded {
        /// The ceiling the walk ran beneath.
        limit: u32,
    },
    /// Retaining one more fact would have passed the largest admitted
    /// inventory.
    FactCapacityExceeded {
        /// The ceiling the walk ran beneath.
        limit: u32,
    },
}

impl fmt::Display for GoFactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LanguageMismatch { language } => {
                write!(formatter, "the bound session parsed {language:?}, not Go")
            }
            Self::SyntaxDepthExceeded { limit } => {
                write!(formatter, "the Go syntax depth ceiling of {limit} is spent")
            }
            Self::FactCapacityExceeded { limit } => {
                write!(formatter, "the Go fact ceiling of {limit} is spent")
            }
        }
    }
}

impl std::error::Error for GoFactError {}
