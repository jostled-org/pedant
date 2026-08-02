//! C-family and Go string literal scanners.

use super::quoted::{extract_string_body, skip_to_eol};

fn skip_block_comment(
    bytes: &[u8],
    start: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> usize {
    let mut position = start;
    while position + 1 < bytes.len() {
        match bytes[position] {
            b'\n' => {
                *line += 1;
                *line_start = position + 1;
                position += 1;
            }
            b'*' if bytes[position + 1] == b'/' => return position + 2,
            _ => position += 1,
        }
    }
    bytes.len()
}

fn skip_interpolation(
    bytes: &[u8],
    start: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> usize {
    let mut cursor = start;
    let mut depth = 1u32;
    while cursor < bytes.len() && depth > 0 {
        match bytes[cursor] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b'\n' => {
                *line += 1;
                *line_start = cursor + 1;
            }
            _ => {}
        }
        cursor += 1;
    }
    cursor
}

fn extract_template_literal(
    bytes: &[u8],
    start: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> (Option<Box<str>>, usize) {
    let mut cursor = start;
    let mut literal = String::new();
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'`' if literal.is_empty() => return (None, cursor + 1),
            b'`' => return (Some(literal.into_boxed_str()), cursor + 1),
            b'\\' if cursor + 1 < bytes.len() => cursor += 2,
            b'$' if cursor + 1 < bytes.len() && bytes[cursor + 1] == b'{' => {
                cursor = skip_interpolation(bytes, cursor + 2, line, line_start);
            }
            b'\n' => {
                *line += 1;
                *line_start = cursor + 1;
                literal.push('\n');
                cursor += 1;
            }
            _ => {
                literal.push(bytes[cursor] as char);
                cursor += 1;
            }
        }
    }
    (None, cursor)
}

fn extract_raw_string(
    bytes: &[u8],
    start: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> (Option<Box<str>>, usize) {
    let mut cursor = start;
    let mut literal = String::new();
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'`' if literal.is_empty() => return (None, cursor + 1),
            b'`' => return (Some(literal.into_boxed_str()), cursor + 1),
            b'\n' => {
                *line += 1;
                *line_start = cursor + 1;
                literal.push('\n');
                cursor += 1;
            }
            _ => {
                literal.push(bytes[cursor] as char);
                cursor += 1;
            }
        }
    }
    (None, cursor)
}

fn skip_rune_literal(bytes: &[u8], start: usize) -> usize {
    let mut position = start + 1;
    while position < bytes.len() {
        match bytes[position] {
            b'\'' => return position + 1,
            b'\\' if position + 1 < bytes.len() => position += 2,
            b'\n' => return position,
            _ => position += 1,
        }
    }
    position
}

fn try_skip_comment(
    bytes: &[u8],
    position: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> Option<usize> {
    match bytes.get(position + 1)? {
        b'/' => Some(skip_to_eol(bytes, position)),
        b'*' => Some(skip_block_comment(bytes, position + 2, line, line_start)),
        _ => None,
    }
}

pub(crate) fn scan_js_string_literals(source: &str) -> Box<[(Box<str>, usize, usize)]> {
    scan_c_family_literals(source, BacktickStyle::JavaScript, false)
}

pub(crate) fn scan_go_string_literals(source: &str) -> Box<[(Box<str>, usize, usize)]> {
    scan_c_family_literals(source, BacktickStyle::Go, true)
}

#[derive(Clone, Copy)]
enum BacktickStyle {
    JavaScript,
    Go,
}

fn scan_c_family_literals(
    source: &str,
    backtick_style: BacktickStyle,
    skips_runes: bool,
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
            b'/' => {
                position = try_skip_comment(bytes, position, &mut line, &mut line_start)
                    .unwrap_or(position + 1);
            }
            b'"' => {
                let column = position - line_start + 1;
                let (content, end) = extract_string_body(bytes, position);
                position = end;
                results.extend(content.map(|value| (value, line, column)));
            }
            b'\'' if skips_runes => position = skip_rune_literal(bytes, position),
            b'\'' => {
                let column = position - line_start + 1;
                let (content, end) = extract_string_body(bytes, position);
                position = end;
                results.extend(content.map(|value| (value, line, column)));
            }
            b'`' => {
                let column = position - line_start + 1;
                let (content, end) = extract_backtick_literal(
                    bytes,
                    position,
                    backtick_style,
                    &mut line,
                    &mut line_start,
                );
                position = end;
                results.extend(content.map(|value| (value, line, column)));
            }
            _ => position += 1,
        }
    }
    results.into_boxed_slice()
}

fn extract_backtick_literal(
    bytes: &[u8],
    position: usize,
    style: BacktickStyle,
    line: &mut usize,
    line_start: &mut usize,
) -> (Option<Box<str>>, usize) {
    match style {
        BacktickStyle::JavaScript => {
            extract_template_literal(bytes, position + 1, line, line_start)
        }
        BacktickStyle::Go => extract_raw_string(bytes, position + 1, line, line_start),
    }
}
