//! The one-based source point a caller asks about.

use serde::{Deserialize, Serialize};

/// A point in a source file.
///
/// Both values are one-based. A `column` is a UTF-8 byte offset within its
/// line, matching the byte model both parser families use. A column-absent
/// location selects by line containment instead of by exact point.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Location {
    /// One-based line number.
    pub line: usize,
    /// One-based UTF-8 byte offset within the line, when the caller has one.
    pub column: Option<usize>,
}
