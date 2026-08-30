//! Narrowest-declaration selection, shared by every backend.
//!
//! A backend recognizes declarations and offers them; this module decides
//! which one a location falls in and owns the conversion to the public
//! boundary value. Candidates stay borrowed until one wins.
//!
//! One selector answers for a whole slice of locations, not for one. Each
//! location gets a slot: its resolved target, and the narrowest declaration
//! offered for it so far. The single-location form is that same selector with
//! one slot, so the crate holds one containment rule, one narrowness rule, one
//! unaddressable-location rule, and one conversion rule rather than a batch
//! copy beside a single copy of each.
//!
//! That shape is why the selector keeps owning its [`SourceIndex`] instead of
//! borrowing one. A borrowed index would let a caller resolve many locations
//! against one index, but it would leave the per-target bookkeeping — which
//! slots a candidate covers, and which of them it is narrow enough to win —
//! either duplicated per caller or in a second selector type beside this one.
//! One index per selector, many targets per index, keeps both the scan and the
//! rule single.

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

impl Target {
    /// Whether this target falls inside `range`.
    ///
    /// The one containment test in the crate. A line target holds when the
    /// range opens before the line ends and closes at or after the line opens —
    /// the two comparisons the line's byte extent makes possible, in place of
    /// the line span a binary search per bound would build. `last` is the
    /// range's final byte, as the span it replaces computed it.
    fn contains(&self, range: &Range<usize>) -> bool {
        match self {
            Self::Point(offset) => range.contains(offset),
            Self::Line(line) => {
                let last = range.end.saturating_sub(1).max(range.start);
                range.start < line.end && line.start <= last
            }
        }
    }
}

/// One recognized declaration a backend offered.
struct Candidate<'s> {
    kind: SourceUnitKind,
    name: Option<&'s str>,
    range: Range<usize>,
}

/// Keeps the narrowest recognized declaration containing each of one or more
/// locations.
pub(crate) struct UnitSelector<'s> {
    index: SourceIndex<'s>,
    /// One slot per caller location, in the caller's order. A location the
    /// source cannot address holds `None` and collects nothing, so one
    /// unaddressable location in a batch costs the others nothing.
    targets: Box<[Option<Target>]>,
    /// The narrowest declaration offered for each slot so far, aligned with
    /// [`Self::targets`].
    best: Box<[Option<Candidate<'s>>]>,
}

impl<'s> UnitSelector<'s> {
    /// Resolve one location against `source`.
    ///
    /// Returns `None` for a zero line or column, a line the source does not
    /// hold, a column past its line, and a column inside a UTF-8 code point.
    /// A batch reports that same absence per slot instead, because one bad
    /// location there must not discard the rest.
    pub(crate) fn new(source: &'s str, at: Location) -> Option<Self> {
        let selector = Self::over(source, std::slice::from_ref(&at));
        matches!(selector.targets.first(), Some(Some(_))).then_some(selector)
    }

    /// Resolve every location in `at` against one index of `source`.
    ///
    /// The index is built once here, whatever `at`'s length, which is the whole
    /// point of the batch: a caller with many locations in one file pays one
    /// scan of the source and one backend walk rather than one of each per
    /// location.
    pub(crate) fn over(source: &'s str, at: &[Location]) -> Self {
        let index = SourceIndex::new(source);
        let targets: Box<[Option<Target>]> = at.iter().map(|&at| resolve(&index, at)).collect();
        let best = std::iter::repeat_with(|| None)
            .take(targets.len())
            .collect();
        Self {
            index,
            targets,
            best,
        }
    }

    /// Keep one recognized declaration covering `range` in every slot it is the
    /// narrowest offered for so far, so an inner method beats its class, trait,
    /// or impl.
    ///
    /// Containment against the batch as a whole is the caller's question, asked
    /// through [`Self::contains`]: both backends already ask it to skip work a
    /// declaration that misses every location does not need — pruning a
    /// subtree, or resolving a name only a winner uses — so asking it again
    /// here would repeat an answer the caller holds. The debug assertion holds
    /// the invariant that only a containing range is ever offered. Which of the
    /// slots the range covers is this loop's question, and no caller can hold
    /// that answer.
    pub(crate) fn keep(
        &mut self,
        kind: SourceUnitKind,
        name: Option<&'s str>,
        range: Range<usize>,
    ) {
        debug_assert!(
            self.contains(&range),
            "a kept declaration contains at least one target"
        );
        for (target, best) in self.targets.iter().zip(&mut self.best) {
            let Some(target) = target else {
                continue;
            };
            if !target.contains(&range) {
                continue;
            }
            if best
                .as_ref()
                .is_some_and(|held| held.range.len() <= range.len())
            {
                continue;
            }
            *best = Some(Candidate {
                kind,
                name,
                range: range.start..range.end,
            });
        }
    }

    /// The line index this selector resolves against.
    ///
    /// A backend that maps parser positions reads the index from here rather
    /// than carrying a second one, so the offsets it computes, the text it
    /// slices, and the targets it is being compared against all come from one
    /// scan of one string.
    #[cfg(feature = "rust")]
    pub(crate) fn index(&self) -> &SourceIndex<'s> {
        &self.index
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
        let Self { index, best, .. } = self;
        debug_assert_eq!(
            best.len(),
            1,
            "a unit is finished from a single-location selector"
        );
        let candidate = best.into_iter().next()??;
        let span = index.line_span(&candidate.range);
        let text = index.source().get(candidate.range);
        debug_assert!(
            text.is_some(),
            "a candidate range slices the indexed source"
        );
        Some(SourceUnit {
            kind: candidate.kind,
            name: candidate.name.map(Box::from),
            span,
            text: Box::from(text?),
        })
    }

    /// Every slot's winning declaration as an anchor, in the caller's order.
    ///
    /// The same selection [`Self::finish`] reports, without copying any
    /// declaration's bytes. A slot is `None` when its location was
    /// unaddressable and when no declaration held it.
    #[cfg(feature = "_ts")]
    pub(crate) fn finish_anchors(self) -> Box<[Option<crate::tree_sitter::SourceUnitAnchor>]> {
        let Self { index, best, .. } = self;
        best.into_iter()
            .map(|candidate| anchor(&index, candidate?))
            .collect()
    }

    /// Whether any resolved target falls inside `range`.
    ///
    /// Every backend's gate before [`Self::keep`]. Public to the crate so a
    /// backend can also prune with it: a declaration's children are
    /// byte-contained in it, so a parent that holds no target can hold none in
    /// any descendant either.
    pub(crate) fn contains(&self, range: &Range<usize>) -> bool {
        self.targets
            .iter()
            .flatten()
            .any(|target| target.contains(range))
    }
}

/// One winning candidate as an anchor: its kind, its name, and where it opens.
///
/// The offset below is a range start the backend already offered, so the index
/// addresses it. That is asserted rather than described, so a range source that
/// does not hold the property fails a test instead of reporting the finding's
/// owner as absent.
#[cfg(feature = "_ts")]
fn anchor(
    index: &SourceIndex<'_>,
    candidate: Candidate<'_>,
) -> Option<crate::tree_sitter::SourceUnitAnchor> {
    let start = index.position_at(candidate.range.start);
    debug_assert!(
        start.is_some(),
        "a candidate range opens at an addressable offset"
    );
    Some(crate::tree_sitter::SourceUnitAnchor {
        kind: candidate.kind,
        name: candidate.name.map(Box::from),
        start: start?,
    })
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
