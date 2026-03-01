use syn::{Attribute, ExprMethodCall, Macro, Type};

/// Matches text against a glob-style pattern.
/// Supports: `*` for any characters, literal matching, prefix/suffix matching.
pub fn matches_pattern(text: &str, pattern: &str) -> bool {
    match pattern.matches('*').count() {
        0 => text == pattern,
        1 => match_single_wildcard(text, pattern),
        _ => match_multiple_wildcards(text, pattern),
    }
}

fn match_single_wildcard(text: &str, pattern: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    text.starts_with(prefix) && text.ends_with(suffix)
}

fn match_multiple_wildcards(text: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;
    let total = parts.len();

    for (index, part) in parts.iter().enumerate() {
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

fn try_match_part(text: &str, pos: &mut usize, part: &str, index: usize, total: usize) -> PartMatch {
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

/// Extracts the text representation of an attribute for pattern matching.
/// Returns the inner content of the attribute (e.g., "allow(dead_code)" from #[allow(dead_code)]).
pub fn extract_attribute_text(attr: &Attribute) -> String {
    let tokens = &attr.meta;
    quote::quote!(#tokens).to_string().replace(' ', "")
}

/// Extracts the text representation of a type for pattern matching.
/// Normalizes whitespace for consistent matching.
pub fn extract_type_text(ty: &Type) -> String {
    quote::quote!(#ty).to_string().replace(' ', "")
}

/// Extracts the text representation of a method call for pattern matching.
/// Returns format ".method_name()" for matching.
pub fn extract_method_call_text(call: &ExprMethodCall) -> String {
    format!(".{}()", call.method)
}

/// Extracts the text representation of a macro for pattern matching.
/// Returns the macro name with "!" suffix (e.g., "println!").
pub fn extract_macro_text(mac: &Macro) -> String {
    let path = &mac.path;
    format!("{}!", quote::quote!(#path).to_string().replace(' ', ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_pattern("allow(dead_code)", "allow(dead_code)"));
        assert!(!matches_pattern("allow(dead_code)", "allow(unused)"));
    }

    #[test]
    fn test_prefix_match() {
        assert!(matches_pattern("allow(unused_variables)", "allow(unused*"));
        assert!(matches_pattern(".unwrap()", ".unwrap()*"));
    }

    #[test]
    fn test_suffix_match() {
        assert!(matches_pattern(".unwrap()", "*.unwrap()"));
        assert!(matches_pattern("foo.unwrap()", "*.unwrap()"));
    }

    #[test]
    fn test_contains_match() {
        assert!(matches_pattern("allow(clippy::unwrap_used)", "*clippy*"));
        assert!(matches_pattern("Box<dyn Error>", "*Error*"));
    }

    #[test]
    fn test_complex_wildcard() {
        assert!(matches_pattern("Arc<Vec<String>>", "Arc<Vec<*>>"));
        assert!(matches_pattern("Box<dyn MyError>", "Box<dyn *Error*"));
    }

    #[test]
    fn test_no_match() {
        assert!(!matches_pattern("Option<String>", "Result<*>"));
        assert!(!matches_pattern("clone()", ".unwrap()"));
    }
}
