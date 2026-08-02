//! Checked translation between source positions and byte offsets.
//!
//! Every location the public API accepts and every position a parser reports
//! passes through this one index, so both parser families share one definition
//! of "line 3, column 7".

use std::ops::Range;

use crate::span::LineSpan;

/// The byte offset of every line start in one source string.
pub(crate) struct SourceIndex<'s> {
    source: &'s str,
    line_starts: Box<[usize]>,
}

impl<'s> SourceIndex<'s> {
    /// Index `source` by line start.
    ///
    /// A trailing newline closes the last line; it opens no further one, so it
    /// is dropped before the scan rather than after. Counting the rest sizes
    /// the table exactly: `match_indices` reports no length, so an unreserved
    /// `extend` grows by doubling and the spare capacity then costs a
    /// reallocation and a copy of the whole table at `into_boxed_slice`.
    pub(crate) fn new(source: &'s str) -> Self {
        let opened = source.strip_suffix('\n').unwrap_or(source);
        let mut line_starts =
            Vec::with_capacity(opened.bytes().filter(|&b| b == b'\n').count() + 1);
        line_starts.push(0);
        line_starts.extend(opened.match_indices('\n').map(|(offset, _)| offset + 1));
        Self {
            source,
            line_starts: line_starts.into_boxed_slice(),
        }
    }

    /// The indexed source.
    pub(crate) fn source(&self) -> &'s str {
        self.source
    }

    /// The byte extent of one-based `line`: its first byte through the first
    /// byte of the next line, or the source's end.
    ///
    /// Absent when the source does not hold the line, so a caller resolving a
    /// location reads existence from the same call that gives it the extent.
    pub(crate) fn line_extent(&self, line: usize) -> Option<Range<usize>> {
        let start = *self.line_starts.get(line.checked_sub(1)?)?;
        let end = self
            .line_starts
            .get(line)
            .copied()
            .unwrap_or(self.source.len());
        Some(start..end)
    }

    /// The byte offset of a one-based UTF-8 byte column on a one-based line.
    ///
    /// Rejects a zero column, a column past the line's bytes, and a column
    /// inside a UTF-8 code point.
    pub(crate) fn offset_at_byte_column(&self, line: usize, column: usize) -> Option<usize> {
        let (start, text) = self.line_at(line)?;
        let within = column.checked_sub(1)?;
        let addressable = within < text.len() && text.is_char_boundary(within);
        addressable.then_some(start + within)
    }

    /// The byte offset of a zero-based character column, as `proc-macro2`
    /// reports parser span positions.
    ///
    /// A column one past the line's last character resolves to the line's end
    /// offset, which is how a span's exclusive end arrives.
    #[cfg(feature = "rust")]
    pub(crate) fn offset_at_char_column(&self, line: usize, column: usize) -> Option<usize> {
        let (start, text) = self.line_at(line)?;
        let within = text
            .char_indices()
            .map(|(offset, _)| offset)
            .chain(std::iter::once(text.len()))
            .nth(column)?;
        Some(start + within)
    }

    /// The one-based inclusive line span a byte range covers.
    pub(crate) fn line_span(&self, range: &Range<usize>) -> LineSpan {
        let last = range.end.saturating_sub(1).max(range.start);
        LineSpan {
            start: self.line_of(range.start),
            end: self.line_of(last),
        }
    }

    /// The start offset and terminator-free text of one-based `line`.
    fn line_at(&self, line: usize) -> Option<(usize, &'s str)> {
        let extent = self.line_extent(line)?;
        let text = self.source.get(extent.clone())?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        Some((extent.start, text.strip_suffix('\r').unwrap_or(text)))
    }

    /// The one-based line holding `offset`.
    fn line_of(&self, offset: usize) -> usize {
        self.line_starts.partition_point(|&start| start <= offset)
    }
}
