//! Checked translation between source positions and byte offsets.
//!
//! Every location the public API accepts and every position a parser reports
//! passes through this one index, so both parser families share one definition
//! of "line 3, column 7".

use std::ops::Range;

#[cfg(feature = "_ts")]
use crate::location::Location;
use crate::span::LineSpan;

/// The byte offset of every line start in one source string.
pub(crate) struct SourceIndex<'s> {
    source: &'s str,
    line_starts: Box<[usize]>,
}

impl<'s> SourceIndex<'s> {
    /// Index `source` by line start.
    ///
    /// Counting first sizes the line-start table exactly.
    pub(crate) fn new(source: &'s str) -> Self {
        let mut line_starts = Vec::with_capacity(line_count(source));
        line_starts.push(0);
        line_starts.extend(
            opened(source)
                .match_indices('\n')
                .map(|(offset, _)| offset + 1),
        );
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

    /// The one-based line and UTF-8 byte column of `offset`.
    ///
    /// Absent when the source does not address `offset` — past its end, or
    /// inside a code point — so a position built from a parser range is checked
    /// against the same index every caller location is.
    #[cfg(feature = "_ts")]
    pub(crate) fn position_at(&self, offset: usize) -> Option<Location> {
        if !self.source.is_char_boundary(offset) {
            return None;
        }
        let line = self.line_of(offset);
        // The line's own start, read from the one call that owns that answer.
        // Deriving it from `line_starts` here would state the one-based-to-index
        // conversion a second time, and its two absences are unreachable
        // besides: `line_of` returns a partition point of at least one.
        let start = self.line_extent(line)?.start;
        Some(Location {
            line,
            column: Some(offset - start + 1),
        })
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

/// How many lines `source` holds, counting a source of no bytes as one.
///
/// The crate's one line-count derivation. The line index sizes its table with
/// it and the file-module structure states its own closing line with it, so a
/// source that gained a terminator cannot be one line longer to one reader and
/// the same length to the other.
pub(crate) fn line_count(source: &str) -> usize {
    opened(source).bytes().filter(|&byte| byte == b'\n').count() + 1
}

/// `source` with a trailing newline dropped.
///
/// A terminator closes the last line rather than opening a further one, and
/// both the count and the offset scan read that same rule from here.
fn opened(source: &str) -> &str {
    source.strip_suffix('\n').unwrap_or(source)
}

/// The source byte range one `syn` span covers, read through `index`.
///
/// A free function rather than a method on either Rust walk: both the structure
/// inventory and the enclosing-unit selector map a span the same way, and the
/// only thing that differed between their copies was which of them owned the
/// index. Absent when either end names a position the source cannot address, and
/// for an empty extent, which states no declaration.
#[cfg(feature = "rust")]
pub(crate) fn span_range(index: &SourceIndex<'_>, span: proc_macro2::Span) -> Option<Range<usize>> {
    let start = span.start();
    let end = span.end();
    let from = index.offset_at_char_column(start.line, start.column)?;
    let to = index.offset_at_char_column(end.line, end.column)?;
    (from < to).then_some(from..to)
}

/// The source text one `syn` span covers, read through `index`.
#[cfg(feature = "rust")]
pub(crate) fn span_text<'s>(index: &SourceIndex<'s>, span: proc_macro2::Span) -> Option<&'s str> {
    index.source().get(span_range(index, span)?)
}
