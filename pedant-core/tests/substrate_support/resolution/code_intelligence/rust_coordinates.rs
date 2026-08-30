//! Where one Rust site closes when its coordinate does not resolve.
//!
//! [`rust_sites`](super::rust_sites) states which declarations one extraction
//! retains; this file states where each retained declaration's bytes begin and
//! end. The two are split because the second question is answered by a
//! resolution a parse cannot reach: `syn` numbers lines from one and reports
//! coordinates inside the text it parsed, so the fallbacks that decide an
//! unresolvable site's extent have no fixture at
//! [`RustFileInventory::of_source`](pedant_core::resolution::rust::RustFileInventory::of_source).
//!
//! Those fallbacks are not decoration. A site's owner is a position in the
//! retained list, so a coordinate that failed to resolve may not drop its site —
//! dropping one would re-point every owner recorded after it. Each fallback
//! therefore closes at the widest extent the text can state, which is the extent
//! a containment test refuses first, and this is the layer that holds them to
//! it.

use pedant_core::resolution::rust::{source_offset_at, source_span_between};

/// A source with a multibyte character, two lines, and no trailing break.
///
/// The multibyte character is what separates a column counted in characters
/// from one added to the line's own start: the two agree on every ASCII line
/// and disagree here.
const TEXT: &str = "let é = 1;\nlet b = 2;";

/// The byte one past the last character of [`TEXT`]'s first line, which is the
/// break itself.
const FIRST_LINE_END: usize = 11;

/// The byte the second line of [`TEXT`] starts at, past that break.
const SECOND_LINE: usize = FIRST_LINE_END + 1;

/// Every coordinate a site can state resolves to a byte inside the text, and
/// every one that cannot closes at the widest extent the text states.
#[test]
fn rust_site_coordinates_resolve_in_bytes_or_close_at_the_widest_extent() {
    a_column_is_counted_in_characters_and_answered_in_bytes();
    unresolvable_coordinates_close_at_the_widest_extent_the_text_states();
    a_span_whose_end_precedes_its_start_is_empty_rather_than_inverted();
    a_resolved_span_states_the_lines_it_was_asked_for();
}

/// `syn` counts columns in characters, so a resolved offset names the byte the
/// requested character begins at.
fn a_column_is_counted_in_characters_and_answered_in_bytes() {
    assert_eq!(
        source_offset_at(TEXT, (1, 5)),
        6,
        "the character before column five is two bytes wide, so it names byte six"
    );
    assert_eq!(
        source_offset_at(TEXT, (2, 0)),
        SECOND_LINE,
        "and a later line starts past the break"
    );
}

/// A coordinate this text cannot place still takes a position, and that
/// position is the widest one the text can state.
fn unresolvable_coordinates_close_at_the_widest_extent_the_text_states() {
    assert_eq!(
        source_offset_at(TEXT, (0, 0)),
        0,
        "a line before the first one opens at the start rather than underflowing"
    );
    assert_eq!(
        source_offset_at(TEXT, (99, 0)),
        TEXT.len(),
        "a line this text does not have closes at the end of it"
    );
    assert_eq!(
        source_offset_at(TEXT, (1, 99)),
        FIRST_LINE_END,
        "a column past the line's characters closes at the end of that line"
    );
}

/// A range whose endpoints arrive out of order states no bytes rather than a
/// backwards slice.
fn a_span_whose_end_precedes_its_start_is_empty_rather_than_inverted() {
    let span = source_span_between(TEXT, (2, 0), (1, 0));
    let bytes = span.byte_range();

    assert_eq!(
        bytes.start, SECOND_LINE,
        "the span opens where its start resolved"
    );
    assert_eq!(
        bytes.start, bytes.end,
        "a range that would slice backwards states no bytes at all"
    );
}

/// A resolved span carries the lines it was asked for, so a containment test
/// reads the same two coordinates the extraction did.
fn a_resolved_span_states_the_lines_it_was_asked_for() {
    let span = source_span_between(TEXT, (1, 0), (2, 10));

    assert_eq!(
        span.byte_range(),
        0..TEXT.len(),
        "the whole text is the extent between its first and last coordinates"
    );
    assert_eq!(
        span.start_line(),
        1,
        "the span states the line it opened on"
    );
    assert_eq!(span.end_line(), 2, "and the line it closed on");
}
