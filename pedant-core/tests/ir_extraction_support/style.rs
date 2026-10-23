//! Style checks consume the IR one parse extracted.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::check_config::{CheckConfig, NamingCheck, PatternCheck};
use pedant_core::lint::analyze;
use pedant_core::style::check_style;
use pedant_core::violation::ViolationType;
use std::sync::Arc;

use super::{parse_and_extract, permissive_config};

// ── Step 3: Style checks consume IR ──────────────────────────────────

// 3.T1: Nesting violations via IR
#[test]
fn test_ir_style_nesting_violations() {
    let source = include_str!("../fixtures/nested_if.rs");
    let ir = parse_and_extract(source);
    let config = permissive_config();
    let violations = check_style(&ir, &config);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::NestedIf);

    let source = include_str!("../fixtures/if_in_match.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::IfInMatch);

    let source = include_str!("../fixtures/nested_match.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::NestedMatch);

    // Deep nesting
    let source = include_str!("../fixtures/deep_nesting.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 3,
        forbid_unsafe: false,
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let depth_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::MaxDepth)
        .collect();
    assert!(!depth_violations.is_empty());
}

// 3.T2: Forbidden patterns via IR
#[test]
fn test_ir_style_forbidden_patterns() {
    let source = include_str!("../fixtures/forbidden_attr.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        forbid_attributes: PatternCheck {
            enabled: true,
            patterns: Arc::from(vec![Arc::from("allow(*)")]),
        },
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let attr_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::ForbiddenAttribute { .. }))
        .collect();
    assert!(!attr_violations.is_empty());

    // Forbidden types
    let source = include_str!("../fixtures/forbidden_types.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        forbid_types: PatternCheck {
            enabled: true,
            patterns: Arc::from(vec![Arc::from("Arc<String>")]),
        },
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let type_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::ForbiddenType { .. }))
        .collect();
    assert!(!type_violations.is_empty());

    // Forbidden calls
    let source = include_str!("../fixtures/forbidden_calls.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        forbid_calls: PatternCheck {
            enabled: true,
            patterns: Arc::from(vec![Arc::from(".unwrap()"), Arc::from(".expect(*)")]),
        },
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let call_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::ForbiddenCall { .. }))
        .collect();
    assert!(!call_violations.is_empty());

    // Forbidden macros
    let source = include_str!("../fixtures/forbidden_macros.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        forbid_macros: PatternCheck {
            enabled: true,
            patterns: Arc::from(vec![Arc::from("println!"), Arc::from("todo!")]),
        },
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let macro_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(&v.violation_type, ViolationType::ForbiddenMacro { .. }))
        .collect();
    assert!(!macro_violations.is_empty());
}

// 3.T3: Clone-in-loop via IR
#[test]
fn test_ir_style_clone_in_loop() {
    let source = include_str!("../fixtures/clone_in_loop.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        check_clone_in_loop: true,
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let clone_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::CloneInLoop)
        .collect();
    // Should flag non-refcounted clones in loops but not Arc/Rc clones
    assert!(!clone_violations.is_empty());

    // Compare with baseline
    let baseline = analyze("clone_in_loop.rs", source, &config, None).unwrap();
    let baseline_clones: Vec<_> = baseline
        .violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::CloneInLoop)
        .collect();
    assert_eq!(clone_violations.len(), baseline_clones.len());
}

// 3.T4: Let-underscore-result via IR
#[test]
fn test_ir_style_let_underscore_result() {
    let source = include_str!("../fixtures/let_underscore_result.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        check_let_underscore_result: true,
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let lur_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::LetUnderscoreResult)
        .collect();
    assert!(!lur_violations.is_empty());

    // Suppressed write-to-String cases should not fire
    let source = include_str!("../fixtures/let_underscore_result_suppressed.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let lur_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::LetUnderscoreResult)
        .collect();
    assert!(lur_violations.is_empty());
}

// 3.T5: Mixed-concerns via IR
#[test]
fn test_ir_style_mixed_concerns() {
    let source = include_str!("../fixtures/mixed_concerns.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        check_mixed_concerns: true,
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let mc_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::MixedConcerns)
        .collect();
    assert_eq!(mc_violations.len(), 1);
    assert!(mc_violations[0].message.contains("disconnected"));

    // Clean file should have no mixed-concerns
    let source = include_str!("../fixtures/mixed_concerns_clean.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let mc_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::MixedConcerns)
        .collect();
    assert!(mc_violations.is_empty());
}

// 3.T6: Dyn dispatch checks via IR
#[test]
fn test_ir_style_dyn_dispatch() {
    let source = include_str!("../fixtures/dyn_return.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        check_dyn_return: true,
        check_dyn_param: true,
        check_vec_box_dyn: true,
        check_dyn_field: true,
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let dyn_return: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::DynReturn)
        .collect();
    assert!(!dyn_return.is_empty());

    let source = include_str!("../fixtures/dyn_param.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let dyn_param: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::DynParam)
        .collect();
    assert!(!dyn_param.is_empty());

    let source = include_str!("../fixtures/vec_box_dyn.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let vbd: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::VecBoxDyn)
        .collect();
    assert!(!vbd.is_empty());

    let source = include_str!("../fixtures/dyn_field.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let dyn_field: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::DynField)
        .collect();
    assert!(!dyn_field.is_empty());
}

// 3.T7: Naming check via IR
#[test]
fn test_ir_style_naming() {
    let source = include_str!("../fixtures/generic_naming.rs");
    let ir = parse_and_extract(source);
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        check_naming: NamingCheck {
            enabled: true,
            ..NamingCheck::default()
        },
        ..CheckConfig::default()
    };
    let violations = check_style(&ir, &config);
    let naming: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::GenericNaming)
        .collect();
    assert!(!naming.is_empty());
}
