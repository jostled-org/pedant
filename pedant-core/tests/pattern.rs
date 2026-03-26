use pedant_core::pattern::{matches_glob, matches_pattern};

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

// --- matches_glob tests ---

#[test]
fn test_glob_exact_relative() {
    assert!(matches_glob("src/main.rs", "src/main.rs"));
    assert!(!matches_glob("src/main.rs", "src/lib.rs"));
}

#[test]
fn test_glob_single_star() {
    assert!(matches_glob("src/*.rs", "src/main.rs"));
    assert!(matches_glob("src/*.rs", "src/lib.rs"));
    assert!(!matches_glob("src/*.rs", "src/nested/lib.rs"));
}

#[test]
fn test_glob_double_star() {
    assert!(matches_glob("src/**/*.rs", "src/main.rs"));
    assert!(matches_glob("src/**/*.rs", "src/nested/lib.rs"));
    assert!(matches_glob("src/**/*.rs", "src/a/b/c.rs"));
    assert!(!matches_glob("src/**/*.rs", "tests/a.rs"));
}

#[test]
fn test_glob_suffix_match_absolute_path() {
    assert!(matches_glob(
        "pedant-core/src/main.rs",
        "/Users/jem/repos/pedant-core/src/main.rs"
    ));
    assert!(matches_glob(
        "src/*.rs",
        "/Users/jem/repos/project/src/main.rs"
    ));
}

#[test]
fn test_glob_no_suffix_match_for_absolute_pattern() {
    assert!(!matches_glob(
        "/absolute/pattern.rs",
        "/different/absolute/pattern.rs"
    ));
}

#[test]
fn test_glob_no_suffix_match_for_doublestar_start() {
    assert!(matches_glob("**/*.rs", "src/main.rs"));
    assert!(matches_glob("**/*.rs", "a/b/c/d.rs"));
}

#[test]
fn test_glob_dot_slash_stripped() {
    assert!(matches_glob("src/main.rs", "./src/main.rs"));
}

#[test]
fn test_glob_star_in_segment() {
    assert!(matches_glob("src/test_*.rs", "src/test_foo.rs"));
    assert!(!matches_glob("src/test_*.rs", "src/main.rs"));
}
