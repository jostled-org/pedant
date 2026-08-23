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
    /// A receiver binding named a declaration the inventory does not hold.
    ///
    /// Defensive. The walk links a receiver to the declaration index its own
    /// `admit` just minted against the same inventory, so the lookup cannot
    /// miss while that holds. It refuses rather than passing, because dropping
    /// the link would leave a method answering "no receiver" — an answer that
    /// reads as a plain function and carries no sign that anything failed.
    DeclarationMapping {
        /// The declaration index the receiver named.
        declaration: u32,
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
            Self::DeclarationMapping { declaration } => write!(
                formatter,
                "a receiver names Go declaration {declaration}, which this inventory does not hold"
            ),
        }
    }
}

impl std::error::Error for GoFactError {}
