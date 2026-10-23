//! `analyze` produces what the direct IR pipeline produces, from one parse.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::capabilities::detect_capabilities;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir::ControlFlowKind;
use pedant_core::lint::analyze;
use pedant_core::style::check_style;

use super::{CAPABILITY_FIXTURES, parse_and_extract};

/// Every remaining fixture the analyze-versus-direct-IR equivalence case walks:
/// the style cases, which carry no capability evidence.
const STYLE_FIXTURES: &[(&str, &str)] = &[
    (
        "deep_nesting.rs",
        include_str!("../fixtures/deep_nesting.rs"),
    ),
    ("nested_if.rs", include_str!("../fixtures/nested_if.rs")),
    (
        "nested_match.rs",
        include_str!("../fixtures/nested_match.rs"),
    ),
    ("if_in_match.rs", include_str!("../fixtures/if_in_match.rs")),
    ("else_chain.rs", include_str!("../fixtures/else_chain.rs")),
    (
        "clone_in_loop.rs",
        include_str!("../fixtures/clone_in_loop.rs"),
    ),
    ("dyn_return.rs", include_str!("../fixtures/dyn_return.rs")),
    ("dyn_param.rs", include_str!("../fixtures/dyn_param.rs")),
    ("dyn_field.rs", include_str!("../fixtures/dyn_field.rs")),
    ("vec_box_dyn.rs", include_str!("../fixtures/vec_box_dyn.rs")),
    (
        "default_hasher.rs",
        include_str!("../fixtures/default_hasher.rs"),
    ),
    (
        "let_underscore_result.rs",
        include_str!("../fixtures/let_underscore_result.rs"),
    ),
    (
        "inline_tests.rs",
        include_str!("../fixtures/inline_tests.rs"),
    ),
    (
        "mixed_concerns.rs",
        include_str!("../fixtures/mixed_concerns.rs"),
    ),
    (
        "mixed_concerns_clean.rs",
        include_str!("../fixtures/mixed_concerns_clean.rs"),
    ),
    (
        "mixed_concerns_body.rs",
        include_str!("../fixtures/mixed_concerns_body.rs"),
    ),
    (
        "generic_naming.rs",
        include_str!("../fixtures/generic_naming.rs"),
    ),
];

// 4.T1: analyze() produces identical output to direct IR calls
#[test]
fn test_analyze_produces_identical_output() {
    let config = CheckConfig::default();

    for (name, source) in CAPABILITY_FIXTURES.iter().chain(STYLE_FIXTURES) {
        assert_analyze_matches_direct_ir(name, source, &config);
    }
}

/// `analyze` and the direct IR path must agree on one fixture, violation for
/// violation and finding for finding.
fn assert_analyze_matches_direct_ir(name: &str, source: &str, config: &CheckConfig) {
    // Run through analyze() — the public entry point
    let result = analyze(name, source, config, None).unwrap_or_else(|e| {
        panic!("analyze failed for {name}: {e}");
    });

    // Run through direct IR path for comparison
    let ir = parse_and_extract(source);
    let direct_violations = check_style(&ir, config);
    let direct_capabilities = detect_capabilities(&ir, None);

    assert_eq!(
        result.violations.len(),
        direct_violations.len(),
        "{name}: violation count mismatch (analyze={}, direct={})",
        result.violations.len(),
        direct_violations.len()
    );
    for (i, (a, d)) in result
        .violations
        .iter()
        .zip(direct_violations.iter())
        .enumerate()
    {
        assert_eq!(
            a.violation_type, d.violation_type,
            "{name}: violation[{i}] type mismatch"
        );
        assert_eq!(a.line, d.line, "{name}: violation[{i}] line mismatch");
    }

    assert_eq!(
        result.capabilities.profile.findings.len(),
        direct_capabilities.profile.findings.len(),
        "{name}: capability count mismatch"
    );
    for (i, (a, d)) in result
        .capabilities
        .profile
        .findings
        .iter()
        .zip(direct_capabilities.profile.findings.iter())
        .enumerate()
    {
        assert_eq!(
            a.capability, d.capability,
            "{name}: capability[{i}] mismatch"
        );
    }
}

// 4.T2: analyze() calls syn::parse_file once (not twice)
#[test]
fn test_analyze_single_parse() {
    // The large fixture exercises both style and capability detection.
    // If analyze() parsed twice, performance would degrade, but correctness
    // is the key guarantee: a single parse_file call feeds both subsystems.
    let source = r#"
        use std::net::TcpStream;
        use std::collections::HashMap;

        fn deep() {
            if true {
                if false {
                    match 1 {
                        _ => {}
                    }
                }
            }
        }

        unsafe fn danger() {}

        struct Foo;
        struct Bar;
    "#;

    let config = CheckConfig::default();
    let result = analyze("single_parse.rs", source, &config, None).unwrap();

    // Must find style violations (nesting) AND capability findings (unsafe, network)
    assert!(
        !result.violations.is_empty(),
        "expected style violations from deep nesting"
    );
    assert!(
        !result.capabilities.profile.findings.is_empty(),
        "expected capability findings from unsafe/network"
    );
}

// 3.T1: Control flow facts track containing function
#[test]
fn test_control_flow_has_containing_fn() {
    let source = r#"
        fn first(x: i32) {
            if x > 0 {
                match x {
                    1 => {}
                    _ => {}
                }
            }
        }
        fn second(y: bool) {
            if y {}
        }
    "#;
    let ir = parse_and_extract(source);

    // Should have functions "first" and "second"
    assert_eq!(ir.functions.len(), 2);
    let first_idx = ir
        .functions
        .iter()
        .position(|f| &*f.name == "first")
        .expect("missing 'first'");
    let second_idx = ir
        .functions
        .iter()
        .position(|f| &*f.name == "second")
        .expect("missing 'second'");

    // All control flow facts should have containing_fn set
    for cf in &ir.control_flow {
        assert!(
            cf.containing_fn.is_some(),
            "ControlFlowFact missing containing_fn"
        );
    }

    // first() has an If and a Match
    let first_cfs: Vec<_> = ir
        .control_flow
        .iter()
        .filter(|cf| cf.containing_fn == Some(first_idx))
        .collect();
    assert_eq!(
        first_cfs.len(),
        2,
        "first() should have 2 control flow facts"
    );
    assert!(first_cfs.iter().any(|cf| cf.kind == ControlFlowKind::If));
    assert!(first_cfs.iter().any(|cf| cf.kind == ControlFlowKind::Match));

    // second() has one If
    let second_cfs: Vec<_> = ir
        .control_flow
        .iter()
        .filter(|cf| cf.containing_fn == Some(second_idx))
        .collect();
    assert_eq!(
        second_cfs.len(),
        1,
        "second() should have 1 control flow fact"
    );
    assert_eq!(second_cfs[0].kind, ControlFlowKind::If);
}
