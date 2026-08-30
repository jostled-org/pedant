//! The extent one Go grammar fact occupies inside its source.

use std::ops::Range;

use crate::tree_sitter::Node;

/// Where one Go fact sits in the source it was extracted from.
///
/// Both a byte range and the positions its ends fall at, because the two
/// consumers ask different questions: selection and slicing index bytes, while
/// a resolution report and a graph span state lines and columns. Deriving
/// either from the other would need the source string, which a fact does not
/// carry.
///
/// Lines and columns are zero-based, and a column is a UTF-8 byte offset within
/// its line — the same model
/// [`SourcePosition`](pedant_types::SourcePosition) states, without
/// a file path, because a fact names a position inside one already-known
/// source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoFactSpan {
    start_byte: usize,
    end_byte: usize,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

impl GoFactSpan {
    /// The extent one grammar node covers.
    ///
    /// The only constructor. A span therefore always names a node the bound
    /// tree held, so its byte range indexes the source that tree was parsed
    /// from.
    pub(super) fn of_node(node: Node<'_>) -> Self {
        let range = node.byte_range();
        let start = node.start_position();
        let end = node.end_position();
        Self {
            start_byte: range.start,
            end_byte: range.end,
            start_line: start.row,
            start_column: start.column,
            end_line: end.row,
            end_column: end.column,
        }
    }

    /// The byte range this span covers, as a slice index.
    pub fn byte_range(self) -> Range<usize> {
        self.start_byte..self.end_byte
    }

    /// The byte offset of the span's first byte.
    pub fn start_byte(self) -> usize {
        self.start_byte
    }

    /// The byte offset one past the span's last byte.
    pub fn end_byte(self) -> usize {
        self.end_byte
    }

    /// The zero-based line the span opens on.
    pub fn start_line(self) -> usize {
        self.start_line
    }

    /// The zero-based UTF-8 byte column the span opens at.
    pub fn start_column(self) -> usize {
        self.start_column
    }

    /// The zero-based line the span closes on.
    pub fn end_line(self) -> usize {
        self.end_line
    }

    /// The zero-based UTF-8 byte column the span closes at.
    pub fn end_column(self) -> usize {
        self.end_column
    }
}
