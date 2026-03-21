use pedant_core::pattern::matches_pattern;

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
