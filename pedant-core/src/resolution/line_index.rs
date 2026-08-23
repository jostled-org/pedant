//! The byte offset each line of one source starts at.
//!
//! A report states zero-based lines and zero-based UTF-8 byte columns, and both
//! producing one of those coordinates and proving one exists need the same
//! table over the same exact bytes. One owner, because every language's snapshot
//! binding asks the same question of its own sources.
//!
//! The table borrows the text it indexed rather than being handed it again per
//! call. A table and a text that arrive separately can arrive mismatched, and
//! neither the caller nor this module could tell.

use std::collections::BTreeMap;

use super::identity::index_of;

/// Where each line of one exact source text begins.
pub(crate) struct LineIndex<'source> {
    source: &'source str,
    starts: Box<[usize]>,
}

/// Every snapshotted source's line table, keyed by its repository-relative
/// path.
pub(crate) type SourceLines<'snapshot> = BTreeMap<&'snapshot str, LineIndex<'snapshot>>;

/// One snapshotted source, as a line table is built over it.
///
/// Two answers rather than a whole source view: every language's snapshot holds
/// far more per source than a coordinate needs, and a table built from those
/// extra fields could only serve the language that has them.
pub(crate) trait SnapshotSource {
    /// The repository-relative, `/`-separated path.
    fn path(&self) -> &str;

    /// The exact UTF-8 text the snapshot read.
    fn text(&self) -> &str;

    /// The line table over this source's exact bytes.
    fn lines(&self) -> LineIndex<'_> {
        LineIndex::new(self.text())
    }
}

impl<'source> LineIndex<'source> {
    /// Index the lines of one exact source text.
    ///
    /// The line breaks are counted before the table is built. `match_indices`
    /// reports no size hint, so a growing table doubles and then copies every
    /// offset it already held into its final allocation.
    pub(crate) fn new(source: &'source str) -> Self {
        let breaks = source.bytes().filter(|byte| *byte == b'\n').count();
        let mut starts = Vec::with_capacity(breaks.saturating_add(1));
        starts.push(0_usize);
        starts.extend(source.match_indices('\n').map(|(index, _)| index + 1));
        Self {
            source,
            starts: starts.into_boxed_slice(),
        }
    }

    /// Whether one zero-based line and UTF-8 byte column exists in this source
    /// and sits on a code-point boundary.
    ///
    /// A trailing line break opens one more line, and column zero of it is
    /// admitted. That is the intended reading: a report states an exclusive
    /// span end, so the position one past the final byte is the only coordinate
    /// that can close a span reaching the end of a source that ends in a break.
    /// A source that does not end in one states no such line and refuses it.
    pub(crate) fn holds(&self, line: u32, column: u32) -> bool {
        let line = index_of(line);
        let column = index_of(column);
        self.line_bounds(line)
            .is_some_and(|bounds| self.within(bounds, column))
    }

    /// The byte offsets one zero-based line spans, its line break excluded.
    pub(crate) fn line_bounds(&self, line: usize) -> Option<(usize, usize)> {
        let start = self.starts.get(line).copied()?;
        let end = match self.starts.get(line + 1) {
            Some(next) => next.saturating_sub(1),
            None => self.source.len(),
        };
        Some((start, end))
    }

    /// The exact text this table was built over.
    pub(crate) fn source(&self) -> &'source str {
        self.source
    }

    fn within(&self, bounds: (usize, usize), column: usize) -> bool {
        let (start, end) = bounds;
        let offset = start.saturating_add(column);
        offset <= end && self.source.is_char_boundary(offset)
    }
}

/// One line table per snapshot source, in the snapshot's own order.
///
/// A source is instantiated once per unit and read by several passes, so
/// indexing per instance rescanned the same bytes many times over to produce a
/// table that depends on the text alone.
pub(crate) fn index_sources(sources: &[impl SnapshotSource]) -> Box<[LineIndex<'_>]> {
    sources.iter().map(SnapshotSource::lines).collect()
}

/// The same tables, keyed by the paths their sources are named under.
pub(crate) fn keyed_lines<'snapshot>(
    sources: &'snapshot [impl SnapshotSource],
    lines: Box<[LineIndex<'snapshot>]>,
) -> SourceLines<'snapshot> {
    sources
        .iter()
        .map(SnapshotSource::path)
        .zip(lines.into_vec())
        .collect()
}

/// One keyed table per snapshot source, indexed on the spot.
///
/// For a caller that holds no tables yet. A resolver that already built one
/// per source hands them to [`keyed_lines`] instead, rather than scanning every
/// source byte a second time.
pub(crate) fn source_lines(sources: &[impl SnapshotSource]) -> SourceLines<'_> {
    keyed_lines(sources, index_sources(sources))
}
