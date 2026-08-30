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
    /// The line breaks are counted before the table is built.
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

    /// The byte offset one zero-based line and zero-based *character* column
    /// names in this source.
    ///
    /// `syn` counts columns in characters, so the answer is the byte the
    /// requested character starts at rather than the column added to the line's
    /// own start. Absent when this source states no such line, or when the
    /// line's own bounds do not slice it.
    ///
    /// A column past the line's last character answers the line's end. That is
    /// the position a report's exclusive span end takes, and it is the widest
    /// extent the line can state.
    ///
    /// One owner, because a coordinate resolved twice is two answers to "where
    /// does this `syn` column sit", and the one that saturates and the one that
    /// propagates absence would each be reading a different source position.
    pub(crate) fn char_offset(&self, line: usize, column: usize) -> Option<usize> {
        let (start, _) = self.line_bounds(line)?;
        Some(start.saturating_add(self.char_column(line, column)?))
    }

    /// The same answer, measured from the line's own start rather than the
    /// source's.
    ///
    /// A caller that reports a zero-based column wants this and nothing else.
    /// Asking [`char_offset`](Self::char_offset) for it meant looking the line's
    /// bounds up a second time and subtracting the start back off, so the two
    /// spellings walked the table twice to reach one number.
    pub(crate) fn char_column(&self, line: usize, column: usize) -> Option<usize> {
        let (start, end) = self.line_bounds(line)?;
        let content = self.source.get(start..end)?;
        Some(
            content
                .char_indices()
                .nth(column)
                .map_or(content.len(), |(offset, _)| offset),
        )
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

/// The source at `path`, when the sorted slice holds one.
///
/// Beside the trait that already states `path()`, because the search reads
/// nothing else. Every language sorts its snapshot sources by that same
/// normalized path, so a second copy of this search was a second chance for one
/// language to look a source up by a key its own slice was not ordered on.
pub(crate) fn find<'sources, S: SnapshotSource>(
    sources: &'sources [S],
    path: &str,
) -> Option<&'sources S> {
    sources
        .binary_search_by(|source| source.path().cmp(path))
        .ok()
        .and_then(|index| sources.get(index))
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
///
/// The tables arrive separately from the sources they were built over, which is
/// the one mismatch this module's borrow-the-text design cannot rule out on its
/// own: `zip` stops at the shorter side, so a short table would key some sources
/// and drop the rest with nothing said. Both callers derive the tables from the
/// same slice they pass here, under one `'snapshot` lifetime — [`source_lines`]
/// below by construction, and the resolver by handing over the [`index_sources`]
/// result for the slice it is about to key. A refusal is not the answer: this
/// returns a map, no caller states a third outcome for it, and the production
/// surface takes no assertion route.
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
