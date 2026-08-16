//! Narrowest-declaration selection, shared by every backend.
//!
//! A backend recognizes declarations and offers them; this module decides
//! which one a location falls in and owns the conversion to the public
//! boundary value. Candidates stay borrowed until one wins.

use std::ops::Range;

use crate::extract::index::SourceIndex;
use crate::location::Location;
use crate::unit::{SourceUnit, SourceUnitKind};

/// What a caller's [`Location`] resolved to.
enum Target {
    /// One exact byte offset, from a column-bearing location.
    Point(usize),
    /// The byte extent of a column-absent location's line, resolved once so
    /// containment is a comparison rather than a binary search per candidate.
    Line(Range<usize>),
}

/// One recognized declaration a backend offered.
struct Candidate<'s> {
    kind: SourceUnitKind,
    name: Option<&'s str>,
    range: Range<usize>,
}

/// Keeps the narrowest recognized declaration containing one location.
pub(crate) struct UnitSelector<'s> {
    index: SourceIndex<'s>,
    target: Target,
    best: Option<Candidate<'s>>,
}

impl<'s> UnitSelector<'s> {
    /// Resolve `at` against `source`.
    ///
    /// Returns `None` for a zero line or column, a line the source does not
    /// hold, a column past its line, and a column inside a UTF-8 code point.
    pub(crate) fn new(source: &'s str, at: Location) -> Option<Self> {
        let index = SourceIndex::new(source);
        let target = resolve(&index, at)?;
        Some(Self {
            index,
            target,
            best: None,
        })
    }

    /// Keep one recognized declaration covering `range`, if it is the narrowest
    /// offered so far, so an inner method beats its class, trait, or impl.
    ///
    /// Containment is the caller's question, asked through [`Self::contains`]:
    /// both backends already ask it to skip work a declaration that misses the
    /// location does not need — pruning a subtree, or resolving a name only the
    /// winner uses — so asking it again here would repeat an answer the caller
    /// holds. The debug assertion holds the invariant that only a containing
    /// range is ever kept.
    pub(crate) fn keep(
        &mut self,
        kind: SourceUnitKind,
        name: Option<&'s str>,
        range: Range<usize>,
    ) {
        debug_assert!(
            self.contains(&range),
            "a kept declaration contains the target"
        );
        if self
            .best
            .as_ref()
            .is_some_and(|best| best.range.len() <= range.len())
        {
            return;
        }
        self.best = Some(Candidate { kind, name, range });
    }

    /// The byte offset of a zero-based character column, for parser spans.
    #[cfg(feature = "rust")]
    pub(crate) fn offset_at_char_column(&self, line: usize, column: usize) -> Option<usize> {
        self.index.offset_at_char_column(line, column)
    }

    /// The source this selector resolves against.
    ///
    /// A backend that slices its own text reads it from here rather than
    /// carrying a second reference, so one string answers both the offsets and
    /// the slices.
    #[cfg(feature = "rust")]
    pub(crate) fn source(&self) -> &'s str {
        self.index.source()
    }

    /// The winning declaration as an owned boundary value.
    ///
    /// The only `None` this reports is "no declaration held the location". The
    /// slice below cannot fail: every offered range is either a tree-sitter
    /// node's byte range or a `proc-macro2` span mapped through the same index,
    /// and both land on character boundaries inside the indexed source. It is
    /// asserted rather than described, so a future range source that does not
    /// hold that property fails a test instead of reporting absence.
    pub(crate) fn finish(self) -> Option<SourceUnit> {
        let candidate = self.best?;
        let span = self.index.line_span(&candidate.range);
        let text = self.index.source().get(candidate.range);
        debug_assert!(
            text.is_some(),
            "a candidate range slices the indexed source"
        );
        let text = text?;
        Some(SourceUnit {
            kind: candidate.kind,
            name: candidate.name.map(Box::from),
            span,
            text: Box::from(text),
        })
    }

    /// The winning declaration as an anchor: its kind, its name, and where it
    /// opens.
    ///
    /// The same selection [`Self::finish`] reports, without copying the
    /// declaration's bytes. `None` means either that no declaration held the
    /// location or that the winner opens at an offset the indexed source does
    /// not address, which no current backend produces.
    #[cfg(feature = "_ts")]
    pub(crate) fn finish_anchor(self) -> Option<crate::tree_sitter::SourceUnitAnchor> {
        let candidate = self.best?;
        let start = self.index.position_at(candidate.range.start)?;
        Some(crate::tree_sitter::SourceUnitAnchor {
            kind: candidate.kind,
            name: candidate.name.map(Box::from),
            start,
        })
    }

    /// Whether the resolved target falls inside `range`.
    ///
    /// The one containment test in the crate, and every backend's gate before
    /// [`Self::keep`]. Public to the crate so a backend can also prune with it:
    /// a declaration's children are byte-contained in it, so a parent that
    /// misses cannot hold the target in any descendant.
    ///
    /// A line target holds when the range opens before the line ends and closes
    /// at or after the line opens — the two comparisons the line's byte extent
    /// makes possible, in place of the line span a binary search per bound
    /// would build. `last` is the range's final byte, as the span it replaces
    /// computed it.
    pub(crate) fn contains(&self, range: &Range<usize>) -> bool {
        match &self.target {
            Target::Point(offset) => range.contains(offset),
            Target::Line(line) => {
                let last = range.end.saturating_sub(1).max(range.start);
                range.start < line.end && line.start <= last
            }
        }
    }
}

/// Resolve one caller location into a selection target.
fn resolve(index: &SourceIndex<'_>, at: Location) -> Option<Target> {
    match at.column {
        Some(column) => index
            .offset_at_byte_column(at.line, column)
            .map(Target::Point),
        None => index.line_extent(at.line).map(Target::Line),
    }
}
