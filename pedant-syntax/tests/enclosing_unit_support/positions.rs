//! Where a fixture's text sits: needle to line and byte column.
//!
//! Every test that names a declaration names it by a substring, so one module
//! turns a needle into coordinates. Separate from the fixtures themselves,
//! which describe languages rather than arithmetic.
//!
//! A declaration's line span is not computed here. Every expectation writes its
//! span down instead, so a backend that returns the wrong extent fails rather
//! than matching a span rebuilt from the same text.

use pedant_syntax::Location;

/// A position a fixture names: both coordinates known.
///
/// [`Location`] carries an optional column, because a caller may name a line
/// alone. A resolved point never can, so its column is a plain `usize` and
/// column arithmetic cannot quietly fall back to the line-only form.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    /// The one-based line the needle starts on.
    pub line: usize,
    /// The one-based byte column of the needle's first byte.
    pub column: usize,
}

impl Point {
    /// This point's line with no column, the containment form of the same probe.
    pub fn line_only(self) -> Location {
        Location {
            line: self.line,
            column: None,
        }
    }
}

impl From<Point> for Location {
    fn from(point: Point) -> Self {
        Location {
            line: point.line,
            column: Some(point.column),
        }
    }
}

/// The one-based line and one-based byte column of `needle`'s first byte.
pub fn point_of(source: &str, needle: &str) -> Point {
    let offset = unique_offset(source, needle);
    let start = source[..offset].rfind('\n').map_or(0, |index| index + 1);
    Point {
        line: source[..offset].matches('\n').count() + 1,
        column: offset - start + 1,
    }
}

/// The byte offset of `needle`, which must occur exactly once.
///
/// One scan answers both questions: the first match is the offset, and a second
/// match is the failure. Counting first and then searching again walks the
/// source twice for an answer the count already fixed, and leaves the search's
/// own failure message unreachable.
fn unique_offset(source: &str, needle: &str) -> usize {
    let mut found = source.match_indices(needle);
    let (offset, _) = found
        .next()
        .unwrap_or_else(|| panic!("{needle:?} occurs in the source"));
    assert!(found.next().is_none(), "{needle:?} occurs exactly once");
    offset
}
