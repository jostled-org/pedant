use std::sync::Arc;

use pedant::config::{NamingCheck, PatternCheck};
use pedant::violation::ViolationType;
use pedant::visitor::{CheckConfig, analyze};
use pedant::{Config, lint_file, lint_str};

fn default_config() -> CheckConfig {
    CheckConfig::default()
}

fn permissive_config() -> CheckConfig {
    CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..default_config()
    }
}

#[test]
fn test_nested_if_detection() {
    let source = include_str!("fixtures/nested_if.rs");
    let violations = analyze("nested_if.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::NestedIf);
    assert_eq!(violations[0].line, 3);
}

#[test]
fn test_if_in_match_detection() {
    let source = include_str!("fixtures/if_in_match.rs");
    let violations = analyze("if_in_match.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::IfInMatch);
    assert_eq!(violations[0].line, 4);
}

#[test]
fn test_nested_match_detection() {
    let source = include_str!("fixtures/nested_match.rs");
    let violations = analyze("nested_match.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::NestedMatch);
    assert_eq!(violations[0].line, 4);
}

#[test]
fn test_deep_nesting_detection() {
    let source = include_str!("fixtures/deep_nesting.rs");
    let violations = analyze("deep_nesting.rs", source, &default_config())
        .unwrap()
        .violations;

    let max_depth_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::MaxDepth)
        .collect();

    assert!(!max_depth_violations.is_empty());
}

#[test]
fn test_else_chain_detection() {
    let source = include_str!("fixtures/else_chain.rs");
    let violations = analyze("else_chain.rs", source, &permissive_config())
        .unwrap()
        .violations;

    let else_chain_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::ElseChain)
        .collect();

    assert_eq!(else_chain_violations.len(), 1);
}

#[test]
fn test_clean_code_no_violations() {
    let source = include_str!("fixtures/clean.rs");
    let violations = analyze("clean.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(violations.is_empty());
}

#[test]
fn test_disabled_checks() {
    let source = include_str!("fixtures/nested_if.rs");
    let config = CheckConfig {
        check_nested_if: false,
        ..permissive_config()
    };
    let violations = analyze("nested_if.rs", source, &config).unwrap().violations;

    assert!(
        violations
            .iter()
            .all(|v| v.violation_type != ViolationType::NestedIf)
    );
}

#[test]
fn test_custom_max_depth() {
    let source = include_str!("fixtures/deep_nesting.rs");
    let violations = analyze("deep_nesting.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| v.violation_type != ViolationType::MaxDepth)
    );
}

#[test]
fn test_forbidden_attribute_detection() {
    let source = include_str!("fixtures/forbidden_attr.rs");
    let config = CheckConfig {
        forbid_attributes: PatternCheck {
            enabled: true,
            patterns: vec![
                Arc::from("allow(dead_code)"),
                Arc::from("allow(unused*)"),
                Arc::from("allow(clippy::*)"),
            ],
        },
        ..permissive_config()
    };
    let violations = analyze("forbidden_attr.rs", source, &config)
        .unwrap()
        .violations;

    assert_eq!(violations.len(), 3);
    assert!(
        violations
            .iter()
            .all(|v| matches!(v.violation_type, ViolationType::ForbiddenAttribute { .. }))
    );
}

#[test]
fn test_forbidden_attribute_disabled() {
    let source = include_str!("fixtures/forbidden_attr.rs");
    let config = CheckConfig {
        forbid_attributes: PatternCheck {
            enabled: false,
            patterns: vec![Arc::from("allow(dead_code)")],
        },
        ..permissive_config()
    };
    let violations = analyze("forbidden_attr.rs", source, &config)
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::ForbiddenAttribute { .. }))
    );
}

#[test]
fn test_forbidden_type_detection() {
    let source = include_str!("fixtures/forbidden_types.rs");
    let config = CheckConfig {
        forbid_types: PatternCheck {
            enabled: true,
            patterns: vec![
                Arc::from("Arc<String>"),
                Arc::from("Arc<Vec<*>>"),
                Arc::from("Box<dyn*Error*>"),
            ],
        },
        ..permissive_config()
    };
    let violations = analyze("forbidden_types.rs", source, &config)
        .unwrap()
        .violations;

    let type_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ForbiddenType { .. }))
        .collect();
    assert_eq!(type_violations.len(), 4);
}

#[test]
fn test_forbidden_type_disabled() {
    let source = include_str!("fixtures/forbidden_types.rs");
    let config = CheckConfig {
        forbid_types: PatternCheck {
            enabled: false,
            patterns: vec![Arc::from("Arc<String>")],
        },
        ..permissive_config()
    };
    let violations = analyze("forbidden_types.rs", source, &config)
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::ForbiddenType { .. }))
    );
}

#[test]
fn test_forbidden_call_detection() {
    let source = include_str!("fixtures/forbidden_calls.rs");
    let config = CheckConfig {
        forbid_calls: PatternCheck {
            enabled: true,
            patterns: vec![
                Arc::from(".unwrap()"),
                Arc::from(".expect(*)"),
                Arc::from(".clone()"),
            ],
        },
        ..permissive_config()
    };
    let violations = analyze("forbidden_calls.rs", source, &config)
        .unwrap()
        .violations;

    let call_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ForbiddenCall { .. }))
        .collect();
    assert_eq!(call_violations.len(), 3);
}

#[test]
fn test_forbidden_macro_detection() {
    let source = include_str!("fixtures/forbidden_macros.rs");
    let config = CheckConfig {
        forbid_macros: PatternCheck {
            enabled: true,
            patterns: vec![
                Arc::from("panic!"),
                Arc::from("todo!"),
                Arc::from("unimplemented!"),
                Arc::from("dbg!"),
                Arc::from("println!"),
            ],
        },
        ..permissive_config()
    };
    let violations = analyze("forbidden_macros.rs", source, &config)
        .unwrap()
        .violations;

    let macro_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ForbiddenMacro { .. }))
        .collect();
    assert_eq!(macro_violations.len(), 5);
}

#[test]
fn test_lint_str_api() {
    let source = r#"
fn nested() {
    if true {
        if false {
            println!("nested");
        }
    }
}
"#;
    let config = Config::default();
    let violations = lint_str(source, &config).unwrap().violations;

    assert!(!violations.is_empty());
    assert!(
        violations
            .iter()
            .any(|v| v.violation_type == ViolationType::NestedIf)
    );
}

#[test]
fn test_lint_file_api() {
    use std::path::Path;

    let path = Path::new("tests/fixtures/nested_if.rs");
    let config = Config {
        max_depth: 10,
        ..Config::default()
    };
    let violations = lint_file(path, &config).unwrap().violations;

    assert!(!violations.is_empty());
    assert!(
        violations
            .iter()
            .any(|v| v.violation_type == ViolationType::NestedIf)
    );
}

#[test]
fn test_forbidden_else() {
    let source = include_str!("fixtures/forbidden_keywords.rs");
    let config = CheckConfig {
        forbid_else: true,
        ..permissive_config()
    };
    let violations = analyze("forbidden_keywords.rs", source, &config)
        .unwrap()
        .violations;

    let else_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ForbiddenElse))
        .collect();
    assert_eq!(else_violations.len(), 1);
}

#[test]
fn test_forbidden_unsafe() {
    let source = include_str!("fixtures/forbidden_keywords.rs");
    let config = CheckConfig {
        forbid_unsafe: true,
        ..permissive_config()
    };
    let violations = analyze("forbidden_keywords.rs", source, &config)
        .unwrap()
        .violations;

    let unsafe_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ForbiddenUnsafe))
        .collect();
    assert_eq!(unsafe_violations.len(), 1);
}

#[test]
fn test_dyn_return_detection() {
    let source = include_str!("fixtures/dyn_return.rs");
    let config = CheckConfig {
        check_dyn_return: true,
        ..permissive_config()
    };
    let violations = analyze("dyn_return.rs", source, &config)
        .unwrap()
        .violations;

    let dyn_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::DynReturn))
        .collect();
    assert_eq!(dyn_violations.len(), 2);
}

#[test]
fn test_dyn_return_disabled() {
    let source = include_str!("fixtures/dyn_return.rs");
    let violations = analyze("dyn_return.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::DynReturn))
    );
}

#[test]
fn test_dyn_param_detection() {
    let source = include_str!("fixtures/dyn_param.rs");
    let config = CheckConfig {
        check_dyn_param: true,
        ..permissive_config()
    };
    let violations = analyze("dyn_param.rs", source, &config).unwrap().violations;

    let dyn_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::DynParam))
        .collect();
    assert_eq!(dyn_violations.len(), 2);
}

#[test]
fn test_dyn_param_disabled() {
    let source = include_str!("fixtures/dyn_param.rs");
    let violations = analyze("dyn_param.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::DynParam))
    );
}

#[test]
fn test_vec_box_dyn_detection() {
    let source = include_str!("fixtures/vec_box_dyn.rs");
    let config = CheckConfig {
        check_vec_box_dyn: true,
        ..permissive_config()
    };
    let violations = analyze("vec_box_dyn.rs", source, &config)
        .unwrap()
        .violations;

    let vbd_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::VecBoxDyn))
        .collect();
    assert_eq!(vbd_violations.len(), 2);
}

#[test]
fn test_dyn_field_detection() {
    let source = include_str!("fixtures/dyn_field.rs");
    let config = CheckConfig {
        check_dyn_field: true,
        ..permissive_config()
    };
    let violations = analyze("dyn_field.rs", source, &config).unwrap().violations;

    let field_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::DynField))
        .collect();
    assert_eq!(field_violations.len(), 3);
}

#[test]
fn test_dyn_field_disabled() {
    let source = include_str!("fixtures/dyn_field.rs");
    let violations = analyze("dyn_field.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::DynField))
    );
}

#[test]
fn test_clone_in_loop_detection() {
    let source = include_str!("fixtures/clone_in_loop.rs");
    let config = CheckConfig {
        check_clone_in_loop: true,
        ..permissive_config()
    };
    let violations = analyze("clone_in_loop.rs", source, &config)
        .unwrap()
        .violations;

    let clone_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::CloneInLoop))
        .collect();
    assert_eq!(clone_violations.len(), 4);
}

#[test]
fn test_clone_in_loop_disabled() {
    let source = include_str!("fixtures/clone_in_loop.rs");
    let violations = analyze("clone_in_loop.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::CloneInLoop))
    );
}

#[test]
fn test_default_hasher_detection() {
    let source = include_str!("fixtures/default_hasher.rs");
    let config = CheckConfig {
        check_default_hasher: true,
        ..permissive_config()
    };
    let violations = analyze("default_hasher.rs", source, &config)
        .unwrap()
        .violations;

    let hasher_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::DefaultHasher))
        .collect();
    assert_eq!(hasher_violations.len(), 4);
}

#[test]
fn test_default_hasher_disabled() {
    let source = include_str!("fixtures/default_hasher.rs");
    let violations = analyze("default_hasher.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::DefaultHasher))
    );
}

#[test]
fn test_mixed_concerns_detection() {
    let source = include_str!("fixtures/mixed_concerns.rs");
    let config = CheckConfig {
        check_mixed_concerns: true,
        ..permissive_config()
    };
    let violations = analyze("mixed_concerns.rs", source, &config)
        .unwrap()
        .violations;

    let mc_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::MixedConcerns))
        .collect();
    assert_eq!(mc_violations.len(), 1);
    assert!(
        mc_violations[0]
            .message
            .contains("disconnected type groups")
    );
}

#[test]
fn test_mixed_concerns_clean() {
    let source = include_str!("fixtures/mixed_concerns_clean.rs");
    let config = CheckConfig {
        check_mixed_concerns: true,
        ..permissive_config()
    };
    let violations = analyze("mixed_concerns_clean.rs", source, &config)
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::MixedConcerns))
    );
}

#[test]
fn test_mixed_concerns_body_coupling() {
    let source = include_str!("fixtures/mixed_concerns_body.rs");
    let config = CheckConfig {
        check_mixed_concerns: true,
        ..permissive_config()
    };
    let violations = analyze("mixed_concerns_body.rs", source, &config)
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::MixedConcerns))
    );
}

#[test]
fn test_mixed_concerns_disabled() {
    let source = include_str!("fixtures/mixed_concerns.rs");
    let violations = analyze("mixed_concerns.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::MixedConcerns))
    );
}

#[test]
fn test_inline_tests_detection() {
    let source = include_str!("fixtures/inline_tests.rs");
    let config = CheckConfig {
        check_inline_tests: true,
        ..permissive_config()
    };
    let violations = analyze("inline_tests.rs", source, &config)
        .unwrap()
        .violations;

    let it_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::InlineTests))
        .collect();
    assert_eq!(it_violations.len(), 1);
    assert!(it_violations[0].message.contains("tests"));
}

#[test]
fn test_inline_tests_disabled() {
    let source = include_str!("fixtures/inline_tests.rs");
    let violations = analyze("inline_tests.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::InlineTests))
    );
}

fn naming_config() -> CheckConfig {
    CheckConfig {
        check_naming: NamingCheck {
            enabled: true,
            ..NamingCheck::default()
        },
        ..permissive_config()
    }
}

#[test]
fn test_generic_naming_detection() {
    let source = include_str!("fixtures/generic_naming.rs");
    let violations = analyze("generic_naming.rs", source, &naming_config())
        .unwrap()
        .violations;

    let naming_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::GenericNaming))
        .collect();
    // bad() and non_math() should be flagged
    assert_eq!(naming_violations.len(), 2);
}

#[test]
fn test_generic_naming_disabled() {
    let source = include_str!("fixtures/generic_naming.rs");
    let violations = analyze("generic_naming.rs", source, &permissive_config())
        .unwrap()
        .violations;

    assert!(
        violations
            .iter()
            .all(|v| !matches!(v.violation_type, ViolationType::GenericNaming))
    );
}

#[test]
fn test_generic_naming_custom_config() {
    let source = include_str!("fixtures/generic_naming.rs");
    let config = CheckConfig {
        check_naming: NamingCheck {
            enabled: true,
            generic_names: vec![Arc::from("config")],
            min_generic_count: 1,
            ..NamingCheck::default()
        },
        ..permissive_config()
    };
    let violations = analyze("generic_naming.rs", source, &config)
        .unwrap()
        .violations;

    let naming_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::GenericNaming))
        .collect();
    // mostly_clean() has "config" param + "tmp" won't match custom list, so only 1 generic / 2 total = 50%
    assert!(
        naming_violations
            .iter()
            .any(|v| v.message.contains("config"))
    );
}
