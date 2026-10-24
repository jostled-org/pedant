//! Calls written where the method-call expression never appears: inside macro
//! arguments, and as a `Type::method` path.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use std::sync::Arc;

use pedant_core::check_config::{CheckConfig, PatternCheck};
use pedant_core::lint::analyze;
use pedant_core::violation::ViolationType;

use super::permissive_config;

const FALLBACK_PATTERNS: &[&str] = &[
    ".unwrap()",
    ".unwrap_or(*)",
    ".unwrap_or_default()",
    ".ok()",
];

fn pattern_check(patterns: &[&str]) -> PatternCheck {
    PatternCheck {
        enabled: true,
        patterns: patterns.iter().copied().map(Arc::from).collect(),
    }
}

/// Lines of every violation `config` reports for `source` that `keep` selects.
fn lines_where(
    source: &str,
    config: &CheckConfig,
    keep: impl Fn(&ViolationType) -> bool,
) -> Vec<usize> {
    analyze("hidden_calls.rs", source, config, None)
        .expect("source should analyze")
        .violations
        .iter()
        .filter(|violation| keep(&violation.violation_type))
        .map(|violation| violation.line)
        .collect()
}

fn forbidden_call_lines(source: &str, patterns: &[&str]) -> Vec<usize> {
    let config = CheckConfig {
        forbid_calls: pattern_check(patterns),
        ..permissive_config()
    };
    lines_where(source, &config, |kind| {
        matches!(kind, ViolationType::ForbiddenCall { .. })
    })
}

fn forbidden_macro_lines(source: &str, patterns: &[&str]) -> Vec<usize> {
    let config = CheckConfig {
        forbid_macros: pattern_check(patterns),
        ..permissive_config()
    };
    lines_where(source, &config, |kind| {
        matches!(kind, ViolationType::ForbiddenMacro { .. })
    })
}

fn clone_in_loop_lines(source: &str) -> Vec<usize> {
    let config = CheckConfig {
        check_clone_in_loop: true,
        ..permissive_config()
    };
    lines_where(source, &config, |kind| {
        matches!(kind, ViolationType::CloneInLoop)
    })
}

#[test]
fn test_forbidden_calls_found_in_every_call_form() {
    let source = include_str!("../fixtures/hidden_calls.rs");
    assert_eq!(
        forbidden_call_lines(source, FALLBACK_PATTERNS),
        vec![2, 6, 10, 14, 18, 22]
    );
}

#[test]
fn test_forbidden_call_inside_nested_macro() {
    let source =
        "fn f(x: Option<u8>) -> String {\n    format!(\"{}\", format!(\"{}\", x.unwrap()))\n}\n";
    assert_eq!(forbidden_call_lines(source, FALLBACK_PATTERNS), vec![2]);
}

#[test]
fn test_forbidden_call_inside_repeat_vec() {
    let source = "fn f(x: Option<u8>) -> Vec<u8> {\n    vec![x.unwrap(); 3]\n}\n";
    assert_eq!(forbidden_call_lines(source, FALLBACK_PATTERNS), vec![2]);
}

#[test]
fn test_forbidden_call_inside_macro_that_is_not_expressions() {
    let source = "fn f(x: Option<u8>) -> bool {\n    matches!(x.unwrap(), n if n > 0)\n}\n";
    assert_eq!(forbidden_call_lines(source, FALLBACK_PATTERNS), vec![2]);
}

#[test]
fn test_turbofish_call_inside_macro_that_is_not_expressions() {
    let source = "fn f(x: &str) -> bool {\n    matches!(x.parse::<u8>(), Ok(n) if n > 0)\n}\n";
    assert_eq!(forbidden_call_lines(source, &[".parse()"]), vec![2]);
}

#[test]
fn test_range_inside_macro_that_is_not_expressions_is_no_call() {
    let source = "fn f(n: usize) -> bool {\n    matches!(n, k if k < (0..len(k)).end)\n}\nfn len(k: usize) -> usize { k }\n";
    assert_eq!(
        forbidden_call_lines(source, &[".len()"]),
        Vec::<usize>::new()
    );
}

#[test]
fn test_forbidden_macro_inside_macro_argument() {
    let source = "fn f(x: u8) -> String {\n    format!(\"{}\", dbg!(x))\n}\n";
    assert_eq!(forbidden_macro_lines(source, &["dbg!"]), vec![2]);
}

#[test]
fn test_forbidden_macro_inside_macro_that_is_not_expressions() {
    let source = "fn f(x: u8) -> bool {\n    matches!(x, n if dbg!(n) > 0)\n}\n";
    assert_eq!(forbidden_macro_lines(source, &["dbg!"]), vec![2]);
}

#[test]
fn test_qualified_call_matches_method_pattern() {
    let source = "fn f(x: Option<u8>) -> u8 {\n    Option::unwrap(x)\n}\n";
    assert_eq!(forbidden_call_lines(source, FALLBACK_PATTERNS), vec![2]);
}

#[test]
fn test_associated_function_path_matches_only_when_named() {
    let source = "fn f(x: Option<Vec<u8>>) -> Vec<u8> {\n    x.unwrap_or_else(Vec::new)\n}\n";
    assert_eq!(
        forbidden_call_lines(source, FALLBACK_PATTERNS),
        Vec::<usize>::new()
    );
    assert_eq!(forbidden_call_lines(source, &[".new()"]), vec![2]);
}

#[test]
fn test_module_function_path_is_no_method_call() {
    let source = "fn f(x: &mut Option<u8>) -> Option<u8> {\n    std::mem::take(x)\n}\n";
    assert_eq!(
        forbidden_call_lines(source, &[".take()"]),
        Vec::<usize>::new()
    );
}

#[test]
fn test_clone_inside_macro_argument_in_loop_is_reported() {
    let source =
        "fn f(v: &[String]) {\n    for s in v {\n        println!(\"{}\", s.clone());\n    }\n}\n";
    assert_eq!(clone_in_loop_lines(source), vec![3]);
}

#[test]
fn test_refcount_clone_path_in_loop_is_not_reported() {
    let source = "use std::sync::Arc;\nfn f(v: &[Arc<str>]) -> Vec<Arc<str>> {\n    let mut out = Vec::new();\n    for s in v {\n        out.push(Arc::clone(s));\n    }\n    out\n}\n";
    assert_eq!(clone_in_loop_lines(source), Vec::<usize>::new());
}
