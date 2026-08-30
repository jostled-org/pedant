//! Why one source states no structure inventory.

use std::fmt;

use crate::language::SyntaxLanguage;
use crate::location::Location;

/// Why a source states no complete structure inventory.
///
/// Every variant is a refusal that retains nothing: the walk returns this
/// instead of a [`StructureInventory`](super::StructureInventory), so no caller
/// can mistake a truncated or recovered walk for a complete one. An empty
/// inventory is a real answer — a source that declares nothing — and it is
/// exactly the answer these refusals must not be confused with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructureError {
    /// This build links no backend for the requested language.
    BackendUnavailable {
        /// The language whose backend is absent.
        language: SyntaxLanguage,
    },
    /// The parser produced no tree at all.
    Unparsed {
        /// The language whose parser refused.
        language: SyntaxLanguage,
        /// Where the parser stopped, when it reported a position.
        ///
        /// `syn` names the span it could not read, so the Rust route carries a
        /// line and a column an operator can open the file at. A tree-sitter
        /// parser that produces no tree at all names no node and therefore no
        /// position, which is what the absence means — not that the file is
        /// broken everywhere.
        at: Option<Location>,
    },
    /// The parser recovered from at least one syntax error.
    ///
    /// A recovery tree still holds recognizable declarations, and that is the
    /// hazard: the ones it dropped look exactly like declarations the source
    /// never had.
    Recovered {
        /// The language whose parser recovered.
        language: SyntaxLanguage,
    },
    /// Descent would have passed the deepest admitted level.
    SyntaxDepthExceeded {
        /// The ceiling the walk ran beneath.
        limit: u32,
    },
    /// Retaining one more structure would have passed the largest admitted
    /// inventory.
    StructureCapacityExceeded {
        /// The ceiling the walk ran beneath.
        limit: u32,
    },
    /// The Go fact inventory this projection reads refused.
    ///
    /// Carried rather than re-spelled: Go declarations belong to
    /// [`GoFileFacts`](crate::go::GoFileFacts), so its refusal is the exact
    /// answer about why no structure set exists.
    #[cfg(feature = "ts-go")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ts-go")))]
    GoFacts {
        /// The refusal the Go walk stated.
        source: crate::go::GoFactError,
    },
}

impl fmt::Display for StructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable { language } => {
                write!(formatter, "this build links no {language:?} backend")
            }
            Self::Unparsed { language, at } => unparsed(formatter, *language, *at),
            Self::Recovered { language } => write!(
                formatter,
                "the {language:?} parser recovered, so no complete inventory exists"
            ),
            Self::SyntaxDepthExceeded { limit } => {
                write!(formatter, "the syntax depth ceiling of {limit} is spent")
            }
            Self::StructureCapacityExceeded { limit } => {
                write!(formatter, "the structure ceiling of {limit} is spent")
            }
            #[cfg(feature = "ts-go")]
            Self::GoFacts { source } => {
                write!(formatter, "the Go fact inventory refused: {source}")
            }
        }
    }
}

impl std::error::Error for StructureError {}

/// Say a parser produced no tree, naming where it stopped when it said.
///
/// A position is written as `line:column` after the sentence rather than inside
/// it, so the sentence a reader searches for is the same one in both cases.
fn unparsed(
    formatter: &mut fmt::Formatter<'_>,
    language: SyntaxLanguage,
    at: Option<Location>,
) -> fmt::Result {
    write!(formatter, "the {language:?} parser produced no tree")?;
    match at {
        Some(Location { line, column: None }) => write!(formatter, " at line {line}"),
        Some(Location {
            line,
            column: Some(column),
        }) => write!(formatter, " at {line}:{column}"),
        None => Ok(()),
    }
}
