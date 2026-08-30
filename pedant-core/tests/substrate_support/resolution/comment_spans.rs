//! Which byte runs of one Rust source are prose, so a scan can skip them.
//!
//! Skipping prose by line shape does not work in either direction: the reading
//! that dropped every line beginning with `*` dropped `*guard = …` with the
//! continuation lines of a block comment, and the reading that kept every line
//! not beginning with `//` searched the trailing comment on the end of a
//! statement as though it were code. So the comments are removed as the
//! language defines them.
//!
//! The literals are read for exactly one reason: a `"/*"` inside a string opens
//! no comment, and a reader that thought it did would blank the rest of the
//! file and report every claim over it satisfied. Nothing here reads what a
//! literal says; what matters is that its bytes never open a comment.
//!
//! Blanked rather than deleted. A comment's bytes become spaces and its
//! newlines stay, so a line number in a failure is the line number in the file.
//! That is the whole reason this is a separate owner from
//! [`comment_scan`](super::comment_scan): where the prose is, is a question
//! about Rust's grammar, and which lines carry code is a question about what a
//! claim may be searched in.

/// One source text with every comment byte replaced by a space.
pub(super) fn without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let end = match span_at(bytes, at) {
            Span::Comment(end) => blank(bytes, at, end, &mut kept),
            Span::Kept(end) => copy(bytes, at, end, &mut kept),
        };
        at = end;
    }
    String::from_utf8(kept).expect("blanking a comment leaves the source's own remaining bytes")
}

/// What the run of bytes starting at one offset is.
enum Span {
    /// A `//` or `/* … */` comment, which is blanked.
    Comment(usize),
    /// One literal, or one byte of ordinary code, which is kept whole.
    Kept(usize),
}

/// Where the run starting at `at` ends, and whether it is prose.
///
/// A literal is recognized only so that it can be skipped intact. Nothing here
/// reads what a literal says; what matters is that its bytes never open a
/// comment.
fn span_at(bytes: &[u8], at: usize) -> Span {
    match (bytes[at], bytes.get(at + 1)) {
        (b'/', Some(b'/')) => Span::Comment(line_comment_end(bytes, at)),
        (b'/', Some(b'*')) => Span::Comment(block_comment_end(bytes, at)),
        (b'"', _) => Span::Kept(quoted_end(bytes, at + 1)),
        (b'\'', _) => Span::Kept(tick_end(bytes, at)),
        (b'r' | b'b', _) if !continues_a_word(bytes, at) => {
            Span::Kept(prefixed_literal_end(bytes, at))
        }
        _ => Span::Kept(at + 1),
    }
}

/// Whether the byte before this one is part of the same word.
///
/// `for` ends in the raw-string prefix and `sub` ends in the byte-string one, so
/// a prefix is only a prefix where a new token can begin.
fn continues_a_word(bytes: &[u8], at: usize) -> bool {
    at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_')
}

/// Where a `//` comment ends, which is the newline it stops before.
fn line_comment_end(bytes: &[u8], at: usize) -> usize {
    bytes[at..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| at + offset)
}

/// Where a `/* … */` comment ends, counting the nested ones Rust admits.
fn block_comment_end(bytes: &[u8], at: usize) -> usize {
    let mut cursor = at + 2;
    let mut depth = 1usize;
    while cursor < bytes.len() {
        match (bytes[cursor], bytes.get(cursor + 1)) {
            (b'/', Some(b'*')) => {
                depth += 1;
                cursor += 2;
            }
            // The outermost close is its own arm: it ends the scan rather than
            // shrinking the depth, so the two answers a `*/` can give are two
            // rows here rather than one row that branches.
            (b'*', Some(b'/')) if depth == 1 => return cursor + 2,
            (b'*', Some(b'/')) => {
                depth -= 1;
                cursor += 2;
            }
            _ => cursor += 1,
        }
    }
    bytes.len()
}

/// Where an ordinary string ends, given the offset just past its opening quote.
fn quoted_end(bytes: &[u8], from: usize) -> usize {
    let mut cursor = from;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

/// Where the run opened by a `'` ends.
///
/// A tick opens a character literal or a lifetime, and only the first can hold a
/// `/*`. A lifetime keeps the tick alone, so the name after it is read as the
/// ordinary code it is; a multi-byte character literal takes the same route and
/// is read as two lifetimes, which skips nothing and hides nothing.
fn tick_end(bytes: &[u8], at: usize) -> usize {
    match (bytes.get(at + 1), bytes.get(at + 2)) {
        (Some(b'\\'), _) => escaped_char_end(bytes, at),
        (Some(_), Some(b'\'')) => at + 3,
        _ => at + 1,
    }
}

/// Where a character literal whose body is an escape ends.
fn escaped_char_end(bytes: &[u8], at: usize) -> usize {
    let mut cursor = at + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'\'' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

/// Where a literal opened by a `b` or `r` prefix ends, or the next byte when the
/// prefix opens none.
///
/// `r#` is also how a raw identifier is written, so the hashes are only a raw
/// string's when a quote closes them.
fn prefixed_literal_end(bytes: &[u8], at: usize) -> usize {
    let mut cursor = at + usize::from(bytes[at] == b'b');
    if bytes.get(cursor) == Some(&b'"') {
        return quoted_end(bytes, cursor + 1);
    }
    if bytes.get(cursor) != Some(&b'r') {
        return at + 1;
    }
    cursor += 1;
    let hashes = bytes[cursor..].iter().take_while(|it| **it == b'#').count();
    match bytes.get(cursor + hashes) {
        Some(b'"') => raw_end(bytes, cursor + hashes + 1, hashes),
        _ => at + 1,
    }
}

/// Where a raw string closed by a quote and `hashes` hashes ends.
fn raw_end(bytes: &[u8], from: usize, hashes: usize) -> usize {
    let mut cursor = from;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' && closes_raw(bytes, cursor + 1, hashes) {
            return cursor + 1 + hashes;
        }
        cursor += 1;
    }
    bytes.len()
}

/// Whether the raw string's closing hashes stand here.
fn closes_raw(bytes: &[u8], from: usize, hashes: usize) -> bool {
    bytes[from..]
        .iter()
        .take(hashes)
        .filter(|byte| **byte == b'#')
        .count()
        == hashes
}

/// Blank one run, keeping its newlines so every later line keeps its number.
///
/// A blanked comment leaves the code above and below it where it was, so a
/// negative scan that reads a line number reads the file's own.
fn blank(bytes: &[u8], at: usize, end: usize, kept: &mut Vec<u8>) -> usize {
    let end = end.min(bytes.len());
    kept.extend(bytes[at..end].iter().map(|byte| match byte {
        b'\n' => b'\n',
        _ => b' ',
    }));
    end
}

/// Keep one run exactly as the source states it.
fn copy(bytes: &[u8], at: usize, end: usize, kept: &mut Vec<u8>) -> usize {
    let end = end.min(bytes.len());
    kept.extend_from_slice(&bytes[at..end]);
    end
}
