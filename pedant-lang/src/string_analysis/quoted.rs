//! Quoted-string scanning shared by Python and shell analysis.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommentStyle {
    Always,
    ShellWord,
}

fn opens_comment(bytes: &[u8], position: usize, style: CommentStyle) -> bool {
    match (style, position) {
        (CommentStyle::Always, _) | (CommentStyle::ShellWord, 0) => true,
        (CommentStyle::ShellWord, _) => matches!(
            bytes[position - 1],
            b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'('
        ),
    }
}

pub(crate) fn scan_string_literals(
    source: &str,
    comments: CommentStyle,
) -> Box<[(Box<str>, usize, usize)]> {
    let mut results = Vec::new();
    let bytes = source.as_bytes();
    let mut position = 0;
    let mut line = 1usize;
    let mut line_start = 0usize;

    while position < bytes.len() {
        match bytes[position] {
            b'\n' => {
                line += 1;
                line_start = position + 1;
                position += 1;
            }
            b'#' if opens_comment(bytes, position, comments) => {
                position = skip_to_eol(bytes, position);
            }
            b'\'' | b'"' => {
                let column = position - line_start + 1;
                let (literal_content, end) = extract_string_body(bytes, position);
                position = end;
                results.extend(literal_content.map(|value| (value, line, column)));
            }
            _ => position += 1,
        }
    }
    results.into_boxed_slice()
}

pub(super) fn skip_to_eol(bytes: &[u8], start: usize) -> usize {
    let mut position = start;
    while position < bytes.len() && bytes[position] != b'\n' {
        position += 1;
    }
    position
}

pub(super) fn extract_string_body(bytes: &[u8], start: usize) -> (Option<Box<str>>, usize) {
    let quote = bytes[start];
    let mut cursor = start + 1;
    let mut literal = String::new();

    while cursor < bytes.len() {
        match (bytes[cursor], bytes[cursor] == quote) {
            (b'\\', _) if cursor + 1 < bytes.len() => cursor += 2,
            (b'\n', _) => return (None, cursor),
            (_, true) if literal.is_empty() => return (None, cursor + 1),
            (_, true) => return (Some(literal.into_boxed_str()), cursor + 1),
            _ => {
                literal.push(bytes[cursor] as char);
                cursor += 1;
            }
        }
    }
    (None, cursor)
}
