//! Source ranges and path spellings shared by the site collector.

use crate::ir::PATH_SEPARATOR;
use crate::ir::sites::IrRange;

use super::syn_helpers::span_from;

/// The range one token or node occupies.
pub(super) fn range_of(span: proc_macro2::Span) -> IrRange {
    IrRange {
        start: span_from(span.start()),
        end: span_from(span.end()),
    }
}

/// The range from the start of `start` to the end of `end`.
pub(super) fn range_between(start: proc_macro2::Span, end: proc_macro2::Span) -> IrRange {
    IrRange {
        start: span_from(start.start()),
        end: span_from(end.end()),
    }
}

/// The identifiers one path names, with `crate`, `super`, and `self` retained.
pub(super) fn path_segments(path: &syn::Path) -> Box<[Box<str>]> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string().into_boxed_str())
        .collect()
}

/// The `::`-joined spelling of a segment list.
///
/// The destination is sized from the segments and separators before writing.
pub(super) fn path_text(segments: &[Box<str>]) -> Box<str> {
    let mut text = String::with_capacity(joined_width(segments));
    for segment in segments {
        if !text.is_empty() {
            text.push_str(PATH_SEPARATOR);
        }
        text.push_str(segment);
    }
    text.into_boxed_str()
}

/// The exact byte width the joined spelling of `segments` occupies.
fn joined_width(segments: &[Box<str>]) -> usize {
    let separators = segments.len().saturating_sub(1) * PATH_SEPARATOR.len();
    separators + segments.iter().map(|segment| segment.len()).sum::<usize>()
}

/// The range a path's identifiers occupy, generic arguments excluded.
///
/// A path with no segments occupies nothing, so it states no range rather than
/// a fabricated one.
pub(super) fn path_range(path: &syn::Path) -> Option<IrRange> {
    let first = path.segments.first().map(|segment| segment.ident.span());
    let last = path.segments.last().map(|segment| segment.ident.span());
    match (first, last) {
        (Some(start), Some(end)) => Some(range_between(start, end)),
        _ => None,
    }
}
