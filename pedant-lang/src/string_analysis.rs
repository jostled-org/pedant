//! Language-agnostic string literal analysis helpers.
//!
//! Duplicated from `pedant-core/src/capabilities.rs` per design spec:
//! these are the small pure helpers needed for multi-language scanning.
//! If this utility surface grows, it moves to a dedicated shared crate.

use std::borrow::Cow;
use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin, Language, SourceLocation};

const URL_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];

/// Heuristic: URLs, IPv4 with port, or IPv6 addresses.
pub(crate) fn check_string_for_endpoint(value: &str) -> bool {
    if value.len() < 8 {
        return false;
    }
    URL_SCHEMES.iter().any(|s| value.starts_with(s))
        || looks_like_ipv4(value)
        || looks_like_ipv6(value)
}

fn strip_port_suffix(s: &str) -> Option<&str> {
    let pos = s.rfind(':')?;
    let (host, port) = s.split_at(pos);
    port[1..].parse::<u16>().ok().map(|_| host)
}

fn looks_like_ipv4(s: &str) -> bool {
    let host = match (s.rfind(':'), strip_port_suffix(s)) {
        (Some(_), Some(h)) => h,
        (Some(_), None) => return false,
        (None, _) => s,
    };
    let mut parts = host.split('.');
    let mut count = 0;
    let valid = parts.all(|p| {
        count += 1;
        p.parse::<u8>().is_ok()
    });
    valid && count == 4
}

fn extract_ipv6_body(s: &str) -> &str {
    match s.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .or_else(|| inner.rfind("]:").map(|pos| &inner[..pos]))
            .unwrap_or(inner),
        None => s,
    }
}

fn looks_like_ipv6(s: &str) -> bool {
    let trimmed = extract_ipv6_body(s);
    if trimmed.len() < 3 {
        return false;
    }
    let mut groups = trimmed.split(':');
    let mut count = 0;
    let valid = groups.all(|g| {
        count += 1;
        g.is_empty() || g.chars().all(|c| c.is_ascii_hexdigit())
    });
    valid && count > 2
}

/// Heuristic: PEM block header prefix.
pub(crate) fn check_string_for_pem(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

/// Truncate long evidence strings to avoid leaking full keys.
///
/// Strings <= 40 chars are returned unchanged. Longer strings return the first
/// 16 chars, an ellipsis, and the last 4 chars.
pub(crate) fn truncate_evidence(value: &str) -> Cow<'_, str> {
    match value.len() <= 40 {
        true => Cow::Borrowed(value),
        false => {
            let char_count = value.chars().count();
            let tail_offset = char_count.saturating_sub(4);
            let mut indices = value.char_indices();
            let head_end = indices.nth(16).map_or(value.len(), |(i, _)| i);
            let skip = tail_offset.saturating_sub(17);
            let tail_start = indices.nth(skip).map_or(0, |(i, _)| i);
            Cow::Owned(format!("{}...{}", &value[..head_end], &value[tail_start..]))
        }
    }
}

/// Check whether a string is a hex-encoded key at a known private key size.
fn check_string_for_hex_key(value: &str) -> bool {
    let len = value.len();
    if len < 64 || len % 2 != 0 {
        return false;
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    matches!(len, 64 | 96) || len >= 128
}

const fn base58_table() -> [bool; 256] {
    let mut table = [false; 256];
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut i = 0;
    while i < alphabet.len() {
        table[alphabet[i] as usize] = true;
        i += 1;
    }
    table
}

const BASE58_TABLE: [bool; 256] = base58_table();

fn is_base58(value: &str) -> bool {
    value.bytes().all(|b| BASE58_TABLE[b as usize])
}

/// Check whether a string is a base58-encoded private key.
fn check_string_for_base58_key(value: &str) -> bool {
    let len = value.len();
    match value.as_bytes().first() {
        Some(b'5' | b'K' | b'L') if (51..=52).contains(&len) => is_base58(value),
        _ if (64..=88).contains(&len) => is_base58(value),
        _ => false,
    }
}

/// Validator: receives (full value, suffix after prefix) and returns whether it matches.
type PrefixValidator = fn(&str, &str) -> bool;

/// Check whether a string starts with a known cryptographic key prefix.
fn check_string_for_key_prefix(value: &str) -> bool {
    const KEY_PREFIXES: &[(&str, PrefixValidator)] = &[
        ("AGE-SECRET-KEY-1", |v, _| v.len() > 16),
        ("xprv", |v, suffix| v.len() >= 111 && is_base58(suffix)),
        ("ed25519:", |v, _| v.len() > 8),
        ("0x", |v, suffix| {
            v.len() == 66 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        }),
    ];
    KEY_PREFIXES.iter().any(|(prefix, validate)| {
        value
            .strip_prefix(prefix)
            .is_some_and(|suffix| validate(value, suffix))
    })
}

fn validate_sk_suffix(_full: &str, suffix: &str) -> bool {
    suffix.len() >= 24 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Check whether a string starts with a known credential prefix.
fn check_string_for_credential_prefix(value: &str) -> bool {
    const CREDENTIAL_PREFIXES: &[(&str, PrefixValidator)] = &[
        ("AKIA", |v, suffix| {
            v.len() == 20
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        }),
        ("sk_live_", validate_sk_suffix),
        ("sk_test_", validate_sk_suffix),
        ("sk-", validate_sk_suffix),
    ];
    match starts_with_github_prefix(value) {
        true => value.len() == 40 && value[4..].bytes().all(|b| b.is_ascii_alphanumeric()),
        false => CREDENTIAL_PREFIXES.iter().any(|(prefix, validate)| {
            value
                .strip_prefix(prefix)
                .is_some_and(|suffix| validate(value, suffix))
        }),
    }
}

fn starts_with_github_prefix(value: &str) -> bool {
    matches!(value.get(..4), Some("ghp_" | "gho_" | "ghs_" | "ghr_"))
}

/// Key-material checks that are mutually exclusive (a string matches at most one).
pub(crate) const KEY_MATERIAL_CHECKS: &[fn(&str) -> bool] = &[
    check_string_for_hex_key,
    check_string_for_base58_key,
    check_string_for_key_prefix,
    check_string_for_credential_prefix,
];

type StringLiteralCheck = (fn(&str) -> bool, Capability);

pub(crate) const STRING_LITERAL_CHECKS: &[StringLiteralCheck] = &[
    (check_string_for_endpoint, Capability::Network),
    (check_string_for_pem, Capability::Crypto),
];

/// Extract string literals from source, yielding (value, line, column) tuples.
///
/// Handles single-quoted and double-quoted strings with backslash escapes.
/// Does not handle triple-quoted strings or raw strings in v1.
pub(crate) fn scan_string_literals(source: &str) -> Box<[(Box<str>, usize, usize)]> {
    let mut results = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut line = 1usize;
    let mut line_start = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                line += 1;
                line_start = i + 1;
                i += 1;
            }
            b'#' => {
                i = skip_to_eol(bytes, i);
            }
            b'\'' | b'"' => {
                let col = i - line_start + 1;
                let (literal_content, end) = extract_string_body(bytes, i);
                i = end;
                results.extend(literal_content.map(|v| (v, line, col)));
            }
            _ => {
                i += 1;
            }
        }
    }
    results.into_boxed_slice()
}

fn skip_to_eol(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

/// Check if a module name matches a pattern, allowing subpath imports.
///
/// `matches_module_prefix("fs/promises", "fs")` is true.
/// `matches_module_prefix("fstream", "fs")` is false.
pub(crate) fn matches_module_prefix(name: &str, pattern: &str) -> bool {
    name == pattern
        || (name.starts_with(pattern) && name.as_bytes().get(pattern.len()) == Some(&b'/'))
}

/// Shared call-site detection: scan lines for substring patterns and emit findings.
pub(crate) fn detect_call_sites(
    path: &Arc<str>,
    source: &str,
    patterns: &[(&str, Capability, &str)],
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    for (line_num, line) in source.lines().enumerate() {
        for &(pattern, capability, evidence) in patterns {
            if let Some(col) = line.find(pattern) {
                findings.push(CapabilityFinding {
                    capability,
                    location: SourceLocation {
                        file: Arc::clone(path),
                        line: line_num + 1,
                        column: col + 1,
                    },
                    evidence: Arc::from(evidence),
                    origin: Some(FindingOrigin::CodeSite),
                    language: Some(language),
                    execution_context: None,
                    reachable: None,
                });
            }
        }
    }
}

/// Shared string-literal finding builder: apply endpoint, PEM, and key-material
/// checks to extracted literals and emit findings.
pub(crate) fn detect_string_literal_findings(
    path: &Arc<str>,
    literals: &[(Box<str>, usize, usize)],
    language: Language,
    findings: &mut Vec<CapabilityFinding>,
) {
    for &(ref value, line, column) in literals {
        if let Some(&(_, capability)) = STRING_LITERAL_CHECKS
            .iter()
            .find(|&&(checker, _)| checker(value))
        {
            findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line,
                    column,
                },
                evidence: Arc::from(value.as_ref()),
                origin: Some(FindingOrigin::StringLiteral),
                language: Some(language),
                execution_context: None,
                reachable: None,
            });
        }

        if KEY_MATERIAL_CHECKS.iter().any(|check| check(value)) {
            let evidence = truncate_evidence(value);
            findings.push(CapabilityFinding {
                capability: Capability::Crypto,
                location: SourceLocation {
                    file: Arc::clone(path),
                    line,
                    column,
                },
                evidence: Arc::from(evidence.as_ref()),
                origin: Some(FindingOrigin::StringLiteral),
                language: Some(language),
                execution_context: None,
                reachable: None,
            });
        }
    }
}

/// Check whether `pattern` appears at a shell command boundary in `line`.
///
/// A command boundary requires whitespace or shell operators before the match
/// (or start of line), and whitespace, shell operators, or allowed trailing
/// characters after the match (or end of line).
pub(crate) fn is_shell_command_boundary(
    line: &str,
    pos: usize,
    pattern: &str,
    extra_after: &[u8],
) -> bool {
    let before_ok = match pos {
        0 => true,
        _ => {
            let prev = line.as_bytes()[pos - 1];
            matches!(prev, b' ' | b'\t' | b'|' | b';' | b'`' | b'(' | b'&')
        }
    };

    let after_pos = pos + pattern.len();
    let after_ok = match line.as_bytes().get(after_pos) {
        None => true,
        Some(b) => {
            matches!(b, b' ' | b'\t' | b';' | b'|' | b'&' | b'\n' | b')') || extra_after.contains(b)
        }
    };

    before_ok && after_ok
}

/// Parse a string literal starting at the opening quote. Returns the extracted
/// content (or `None` if unterminated/empty) and the position after the closing quote.
fn extract_string_body(bytes: &[u8], start: usize) -> (Option<Box<str>>, usize) {
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

// ── C-family string scanners (JS/TS, Go) ────────────────────────────────

fn skip_block_comment(
    bytes: &[u8],
    start: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> usize {
    let mut i = start;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'\n' => {
                *line += 1;
                *line_start = i + 1;
                i += 1;
            }
            b'*' if bytes[i + 1] == b'/' => return i + 2,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Skip a `${…}` interpolation block, tracking line positions.
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

/// Extract a JS template literal (backtick-delimited). Skips `${…}` interpolations.
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

/// Extract a Go raw string literal (backtick-delimited, no escapes).
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

/// Skip a Go rune literal (`'x'`, `'\n'`, etc.).
fn skip_rune_literal(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1; // skip opening '
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => return i + 1,
            b'\\' if i + 1 < bytes.len() => i += 2,
            b'\n' => return i,
            _ => i += 1,
        }
    }
    i
}

/// Handle `//` and `/* */` comment prefix. Returns `Some(new_position)` if a
/// comment was consumed, `None` if the `/` is not a comment start.
fn try_skip_comment(
    bytes: &[u8],
    i: usize,
    line: &mut usize,
    line_start: &mut usize,
) -> Option<usize> {
    match bytes.get(i + 1)? {
        b'/' => Some(skip_to_eol(bytes, i)),
        b'*' => Some(skip_block_comment(bytes, i + 2, line, line_start)),
        _ => None,
    }
}

/// Extract string literals from JavaScript/TypeScript source.
///
/// Handles `//` and `/* */` comments, single/double-quoted strings,
/// and template literals (backtick).
pub(crate) fn scan_js_string_literals(source: &str) -> Box<[(Box<str>, usize, usize)]> {
    let mut results = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut line = 1usize;
    let mut line_start = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                line += 1;
                line_start = i + 1;
                i += 1;
            }
            b'/' => {
                i = try_skip_comment(bytes, i, &mut line, &mut line_start).unwrap_or(i + 1);
            }
            b'\'' | b'"' => {
                let col = i - line_start + 1;
                let (content, end) = extract_string_body(bytes, i);
                i = end;
                results.extend(content.map(|v| (v, line, col)));
            }
            b'`' => {
                let col = i - line_start + 1;
                let (content, end) =
                    extract_template_literal(bytes, i + 1, &mut line, &mut line_start);
                i = end;
                results.extend(content.map(|v| (v, line, col)));
            }
            _ => i += 1,
        }
    }
    results.into_boxed_slice()
}

/// Extract string literals from Go source.
///
/// Handles `//` and `/* */` comments, double-quoted strings with escapes,
/// backtick raw strings, and skips rune literals.
pub(crate) fn scan_go_string_literals(source: &str) -> Box<[(Box<str>, usize, usize)]> {
    let mut results = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut line = 1usize;
    let mut line_start = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                line += 1;
                line_start = i + 1;
                i += 1;
            }
            b'/' => {
                i = try_skip_comment(bytes, i, &mut line, &mut line_start).unwrap_or(i + 1);
            }
            b'"' => {
                let col = i - line_start + 1;
                let (content, end) = extract_string_body(bytes, i);
                i = end;
                results.extend(content.map(|v| (v, line, col)));
            }
            b'`' => {
                let col = i - line_start + 1;
                let (content, end) = extract_raw_string(bytes, i + 1, &mut line, &mut line_start);
                i = end;
                results.extend(content.map(|v| (v, line, col)));
            }
            b'\'' => {
                i = skip_rune_literal(bytes, i);
            }
            _ => i += 1,
        }
    }
    results.into_boxed_slice()
}
