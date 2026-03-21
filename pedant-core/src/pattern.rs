use syn::{Attribute, ExprMethodCall, Macro, Type};

/// Matches text against a glob-style pattern.
/// Supports: `*` for any characters, literal matching, prefix/suffix matching.
pub fn matches_pattern(text: &str, pattern: &str) -> bool {
    let star_count = pattern.matches('*').count();
    match star_count {
        0 => text == pattern,
        1 => match_single_wildcard(text, pattern),
        _ => match_multiple_wildcards(text, pattern, star_count),
    }
}

pub(crate) fn match_single_wildcard(text: &str, pattern: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    text.starts_with(prefix) && text.ends_with(suffix)
}

fn match_multiple_wildcards(text: &str, pattern: &str, star_count: usize) -> bool {
    let total = star_count + 1;
    let mut pos = 0;

    for (index, part) in pattern.split('*').enumerate() {
        match try_match_part(text, &mut pos, part, index, total) {
            PartMatch::Continue => continue,
            PartMatch::Fail => return false,
            PartMatch::Ok => {}
        }
    }
    true
}

enum PartMatch {
    Continue,
    Fail,
    Ok,
}

fn try_match_part(
    text: &str,
    pos: &mut usize,
    part: &str,
    index: usize,
    total: usize,
) -> PartMatch {
    match (part.is_empty(), text[*pos..].find(part)) {
        (true, _) => PartMatch::Continue,
        (false, None) => PartMatch::Fail,
        (false, Some(found)) => check_position_constraints(text, pos, part, found, index, total),
    }
}

fn check_position_constraints(
    text: &str,
    pos: &mut usize,
    part: &str,
    found: usize,
    index: usize,
    total: usize,
) -> PartMatch {
    let is_first = index == 0;
    let is_last = index == total - 1;
    let first_mismatch = is_first && found != 0;
    let last_mismatch = is_last && *pos + found + part.len() != text.len();

    match (first_mismatch, last_mismatch) {
        (true, _) | (_, true) => PartMatch::Fail,
        _ => {
            *pos += found + part.len();
            PartMatch::Ok
        }
    }
}

/// Matches a file path against a glob pattern with `/`-separated segments.
/// Supports `*` (single segment wildcard) and `**` (multi-segment wildcard).
pub(crate) fn matches_glob(pattern: &str, path: &str) -> bool {
    let path = path.strip_prefix("./").unwrap_or(path);
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    matches_glob_parts(&pattern_parts, &path_parts)
}

fn matches_glob_parts(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) => matches_double_star(&pattern[1..], path),
        (Some(p), Some(s)) if matches_segment(p, s) => {
            matches_glob_parts(&pattern[1..], &path[1..])
        }
        _ => false,
    }
}

fn matches_double_star(rest_pattern: &[&str], path: &[&str]) -> bool {
    if rest_pattern.is_empty() {
        return true;
    }
    (0..=path.len()).any(|i| matches_glob_parts(rest_pattern, &path[i..]))
}

fn matches_segment(pattern: &str, segment: &str) -> bool {
    match pattern {
        "*" => true,
        p if p.contains('*') => match_single_wildcard(segment, p),
        _ => pattern == segment,
    }
}

/// Extracts the text representation of an attribute for pattern matching.
/// Returns the inner content of the attribute (e.g., "allow(dead_code)" from #[allow(dead_code)]).
pub fn extract_attribute_text(attr: &Attribute) -> Box<str> {
    let tokens = &attr.meta;
    quote::quote!(#tokens)
        .to_string()
        .replace(' ', "")
        .into_boxed_str()
}

/// Extracts the text representation of a type for pattern matching.
/// Normalizes whitespace for consistent matching.
pub fn extract_type_text(ty: &Type) -> Box<str> {
    quote::quote!(#ty)
        .to_string()
        .replace(' ', "")
        .into_boxed_str()
}

/// Extracts the text representation of a method call for pattern matching.
/// Returns format ".method_name()" for matching.
pub fn extract_method_call_text(call: &ExprMethodCall) -> Box<str> {
    format!(".{}()", call.method).into_boxed_str()
}

/// Extracts the text representation of a macro for pattern matching.
/// Returns the macro name with "!" suffix (e.g., "println!").
pub fn extract_macro_text(mac: &Macro) -> Box<str> {
    let path = &mac.path;
    format!("{}!", quote::quote!(#path).to_string().replace(' ', "")).into_boxed_str()
}
