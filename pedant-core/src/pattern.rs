use syn::{Attribute, ExprMethodCall, Macro, Type};

/// Test whether `text` matches a glob pattern (`*` matches any characters).
pub fn matches_pattern(text: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return text == pattern;
    }
    let star_count = pattern.matches('*').count();
    match star_count {
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

/// Path-aware glob: `*` matches one segment, `**` matches zero or more segments.
///
/// When the pattern is relative and the path is absolute, tries matching
/// against every suffix of the path (so `pedant/src/main.rs` matches
/// `/Users/jem/.../pedant/src/main.rs`).
pub(crate) fn matches_glob(pattern: &str, path: &str) -> bool {
    let path = path.strip_prefix("./").unwrap_or(path);
    let pat_segs: Box<[&str]> = pattern.split('/').collect::<Vec<_>>().into_boxed_slice();
    let path_segs: Box<[&str]> = path.split('/').collect::<Vec<_>>().into_boxed_slice();

    // Direct match (both relative, or both absolute).
    if matches_glob_at(&pat_segs, 0, &path_segs, 0) {
        return true;
    }

    // Suffix match: try aligning the pattern against each tail of the path.
    // Only when the pattern doesn't start with `/` or `**`.
    let pattern_is_relative = !pattern.starts_with('/') && pat_segs.first() != Some(&"**");
    match pattern_is_relative && path_segs.len() > pat_segs.len() {
        true => (1..=path_segs.len() - pat_segs.len())
            .any(|offset| matches_glob_at(&pat_segs, 0, &path_segs, offset)),
        false => false,
    }
}

fn matches_glob_at(pat_segs: &[&str], pi: usize, path_segs: &[&str], si: usize) -> bool {
    match (pat_segs.get(pi), path_segs.get(si)) {
        (None, None) => true,
        (Some(&"**"), _) => matches_double_star_at(pat_segs, pi + 1, path_segs, si),
        (Some(p), Some(s)) if matches_segment(p, s) => {
            matches_glob_at(pat_segs, pi + 1, path_segs, si + 1)
        }
        _ => false,
    }
}

fn matches_double_star_at(pat_segs: &[&str], pi: usize, path_segs: &[&str], si: usize) -> bool {
    match pat_segs.get(pi) {
        None => true,
        Some(_) => (si..=path_segs.len()).any(|i| matches_glob_at(pat_segs, pi, path_segs, i)),
    }
}

fn matches_segment(pattern: &str, segment: &str) -> bool {
    match pattern {
        "*" => true,
        p if p.contains('*') => match_single_wildcard(segment, p),
        _ => pattern == segment,
    }
}

/// Render the inner content of an attribute (e.g., `allow(dead_code)` from `#[allow(dead_code)]`).
pub fn extract_attribute_text(attr: &Attribute) -> Box<str> {
    let tokens = &attr.meta;
    quote::quote!(#tokens)
        .to_string()
        .replace(' ', "")
        .into_boxed_str()
}

/// Render a type with whitespace stripped for consistent pattern matching.
pub fn extract_type_text(ty: &Type) -> Box<str> {
    quote::quote!(#ty)
        .to_string()
        .replace(' ', "")
        .into_boxed_str()
}

/// Render a method call as `.method_name()` for pattern matching.
pub fn extract_method_call_text(call: &ExprMethodCall) -> Box<str> {
    format!(".{}()", call.method).into_boxed_str()
}

/// Render a macro invocation as `name!` (e.g., `println!`) for pattern matching.
pub fn extract_macro_text(mac: &Macro) -> Box<str> {
    let path = &mac.path;
    format!("{}!", quote::quote!(#path).to_string().replace(' ', "")).into_boxed_str()
}
