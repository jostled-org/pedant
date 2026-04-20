use pedant_core::capabilities::detect_capabilities;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::lint::analyze;
use pedant_core::style::check_style;
use pedant_core::violation::ViolationType;
use pedant_core::{Config, lint_str};
use pedant_types::Capability;

fn permissive_config() -> CheckConfig {
    CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

// 1.T1: pedant-core analyze produces violations
#[test]
fn test_pedant_core_analyze_produces_violations() {
    let source = r#"
fn nested() {
    if true {
        if false {
            println!("nested");
        }
    }
}
"#;
    let result = analyze("test.rs", source, &permissive_config(), None).unwrap();

    assert!(!result.violations.is_empty());
}

// 1.T2: pedant-core lint_str works
#[test]
fn test_pedant_core_lint_str() {
    let source = r#"
fn nested() {
    if true {
        if false {}
    }
}
"#;
    let config = Config::default();
    let result = lint_str(source, &config).unwrap();

    assert!(
        result
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::NestedIf)
    );
}

// 1.T3: pedant-core IR extraction
#[test]
fn test_pedant_core_ir_extract() {
    let source = r#"
use std::net::TcpStream;

fn greet(name: &str) -> String {
    format!("hello {name}")
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let file_ir = ir::extract("test.rs", &syntax, None);

    assert!(!file_ir.functions.is_empty());
    assert!(!file_ir.use_paths.is_empty());
}

// 1.T4: pedant-core capability detection
#[test]
fn test_pedant_core_detect_capabilities() {
    let source = r#"
use std::net::TcpStream;

fn connect() {
    let _ = TcpStream::connect("127.0.0.1:80");
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let file_ir = ir::extract("test.rs", &syntax, None);
    let profile = detect_capabilities(&file_ir, None);
    let caps = profile.capabilities();

    assert!(caps.contains(&Capability::Network));
}

// 1.T5: pedant-core style checks
#[test]
fn test_pedant_core_check_style() {
    let source = r#"
fn dyn_ret() -> Box<dyn std::error::Error> {
    todo!()
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let file_ir = ir::extract("test.rs", &syntax, None);
    let config = CheckConfig {
        check_dyn_return: true,
        ..permissive_config()
    };
    let violations = check_style(&file_ir, &config);

    assert!(
        violations
            .iter()
            .any(|v| v.violation_type == ViolationType::DynReturn)
    );
}
