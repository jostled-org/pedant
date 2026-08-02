//! The one-based line range a returned declaration covers.

use serde::{Deserialize, Serialize};

/// A one-based inclusive range of lines.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LineSpan {
    /// One-based first line of the declaration.
    pub start: usize,
    /// One-based last line of the declaration, inclusive.
    pub end: usize,
}
