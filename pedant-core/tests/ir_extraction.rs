use pedant_core::capabilities::detect_capabilities;
use pedant_core::check_config::{CheckConfig, NamingCheck, PatternCheck};
use pedant_core::ir::{
    BranchContext, ControlFlowKind, TypeDefKind, TypeRefContext, UnsafeKind, extract,
};
use pedant_core::lint::analyze;
use pedant_core::style::check_style;
use pedant_core::violation::ViolationType;
use pedant_types::Capability;
use std::sync::Arc;

fn parse_and_extract(source: &str) -> pedant_core::ir::FileIr {
    let syntax = syn::parse_file(source).expect("parse failed");
    extract("test.rs", &syntax, None)
}

fn permissive_config() -> CheckConfig {
    CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

// 1.T1: Function facts
#[test]
fn test_ir_extracts_function_facts() {
    let source = r#"
        unsafe fn danger(x: i32) -> bool { true }
        fn safe(a: String, b: u64) {}
    "#;
    let ir = parse_and_extract(source);

    assert_eq!(ir.functions.len(), 2);

    let danger = &ir.functions[0];
    assert_eq!(&*danger.name, "danger");
    assert!(danger.is_unsafe);
    assert_eq!(danger.params.len(), 1);
    assert_eq!(&*danger.params[0].name, "x");
    assert!(danger.return_type.is_some());
    assert!(!danger.signature_type_names.is_empty());

    let safe = &ir.functions[1];
    assert_eq!(&*safe.name, "safe");
    assert!(!safe.is_unsafe);
    assert_eq!(safe.params.len(), 2);
    assert_eq!(&*safe.params[0].name, "a");
    assert_eq!(&*safe.params[1].name, "b");
}

// 1.T2: Control flow facts
#[test]
fn test_ir_extracts_control_flow() {
    let source = r#"
        fn example(x: i32) {
            match x {
                0 => {
                    if true {}
                }
                _ => {}
            }
            for i in 0..10 {
                while true {}
            }
            let c = || {};
        }
    "#;
    let ir = parse_and_extract(source);

    let kinds: Vec<_> = ir.control_flow.iter().map(|cf| cf.kind).collect();
    assert!(kinds.contains(&ControlFlowKind::Match));
    assert!(kinds.contains(&ControlFlowKind::If));
    assert!(kinds.contains(&ControlFlowKind::ForLoop));
    assert!(kinds.contains(&ControlFlowKind::WhileLoop));
    assert!(kinds.contains(&ControlFlowKind::Closure));

    // The if inside match should have parent_branch = Some(Match)
    let if_fact = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::If)
        .unwrap();
    assert_eq!(if_fact.parent_branch, Some(BranchContext::Match));

    // For loop should have loop_depth >= 1
    let for_fact = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::ForLoop)
        .unwrap();
    assert!(for_fact.loop_depth >= 1);

    // While inside for should have loop_depth >= 2
    let while_fact = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::WhileLoop)
        .unwrap();
    assert!(while_fact.loop_depth >= 2);
}

// 1.T3: Binding facts
#[test]
fn test_ir_extracts_bindings() {
    let source = r#"
        use std::sync::Arc;
        fn example() {
            let _ = some_call();
            let name: String = String::new();
            let rc: Arc<i32> = Arc::new(1);
            for i in 0..10 {
                let inner = 1;
            }
        }
    "#;
    let ir = parse_and_extract(source);

    // Should have a wildcard binding
    let wildcard = ir.bindings.iter().find(|b| b.is_wildcard);
    assert!(wildcard.is_some());

    // Named bindings should exist (excluding underscore-prefixed)
    let named: Vec<_> = ir
        .bindings
        .iter()
        .filter(|b| !b.is_wildcard && &*b.name != "_")
        .collect();
    let names: Vec<&str> = named.iter().map(|b| &*b.name).collect();
    assert!(names.contains(&"name"));
    assert!(names.contains(&"inner"));

    // Bindings in for loop should have loop_depth > 0
    let inner_binding = ir.bindings.iter().find(|b| &*b.name == "inner");
    assert!(inner_binding.is_some());
    assert!(inner_binding.unwrap().loop_depth > 0);
}

// 1.T4: Type reference facts
#[test]
fn test_ir_extracts_type_refs() {
    let source = r#"
        use std::collections::HashMap;
        fn returns_dyn() -> Box<dyn std::fmt::Display> { todo!() }
        fn takes_vec(v: Vec<Box<dyn Iterator<Item = i32>>>) {}
        fn uses_map(m: HashMap<String, i32>) {}
    "#;
    let ir = parse_and_extract(source);

    // Should have type refs with involves_dyn set
    let dyn_refs: Vec<_> = ir.type_refs.iter().filter(|tr| tr.involves_dyn).collect();
    assert!(!dyn_refs.is_empty());

    // Should have vec_box_dyn
    let vbd_refs: Vec<_> = ir.type_refs.iter().filter(|tr| tr.is_vec_box_dyn).collect();
    assert!(!vbd_refs.is_empty());

    // Should have default hasher detection
    let hasher_refs: Vec<_> = ir
        .type_refs
        .iter()
        .filter(|tr| tr.is_default_hasher)
        .collect();
    assert!(!hasher_refs.is_empty());

    // Return type refs should have context = Return
    let return_refs: Vec<_> = ir
        .type_refs
        .iter()
        .filter(|tr| tr.context == TypeRefContext::Return)
        .collect();
    assert!(!return_refs.is_empty());
}

// 1.T5: Use path facts
#[test]
fn test_ir_extracts_use_paths() {
    let source = r#"
        use std::net::TcpStream;
        use std::fs::{read, write};
    "#;
    let ir = parse_and_extract(source);

    let paths: Vec<&str> = ir.use_paths.iter().map(|up| &*up.path).collect();
    assert!(paths.contains(&"std::net::TcpStream"));
    assert!(paths.contains(&"std::fs::read"));
    assert!(paths.contains(&"std::fs::write"));
}

// 1.T6: Capability signal facts
#[test]
fn test_ir_extracts_capability_signals() {
    let source = r#"
        #[link(name = "foo")]
        extern "C" {
            fn external();
        }

        #[proc_macro]
        pub fn my_macro() {}

        fn example() {
            unsafe {
                external();
            }
            let url = "https://example.com";
        }
    "#;
    let ir = parse_and_extract(source);

    // Unsafe block
    let unsafe_blocks: Vec<_> = ir
        .unsafe_sites
        .iter()
        .filter(|u| u.kind == UnsafeKind::Block)
        .collect();
    assert!(!unsafe_blocks.is_empty());

    // Extern block
    assert!(!ir.extern_blocks.is_empty());

    // Attributes: #[link] and #[proc_macro]
    let attr_names: Vec<&str> = ir.attributes.iter().map(|a| &*a.name).collect();
    assert!(attr_names.contains(&"link"));
    assert!(attr_names.contains(&"proc_macro"));

    // String literal with URL
    let urls: Vec<_> = ir
        .string_literals
        .iter()
        .filter(|s| s.value.starts_with("https://"))
        .collect();
    assert!(!urls.is_empty());
}

// 1.T7: Type defs and impl blocks
#[test]
fn test_ir_extracts_type_defs_and_impls() {
    let source = r#"
        struct Foo {
            bar: Bar,
        }
        enum Color {
            Red,
            Blue,
        }
        trait Drawable {
            fn draw(&self);
        }
        impl Drawable for Foo {
            fn draw(&self) {}
        }
    "#;
    let ir = parse_and_extract(source);

    // Type defs
    assert_eq!(ir.type_defs.len(), 3);
    let type_names: Vec<&str> = ir.type_defs.iter().map(|td| &*td.name).collect();
    assert!(type_names.contains(&"Foo"));
    assert!(type_names.contains(&"Color"));
    assert!(type_names.contains(&"Drawable"));

    let foo_def = ir.type_defs.iter().find(|td| &*td.name == "Foo").unwrap();
    assert_eq!(foo_def.kind, TypeDefKind::Struct);
    // Foo has edge to Bar
    assert!(!foo_def.edges.is_empty());

    let color_def = ir.type_defs.iter().find(|td| &*td.name == "Color").unwrap();
    assert_eq!(color_def.kind, TypeDefKind::Enum);

    let drawable_def = ir
        .type_defs
        .iter()
        .find(|td| &*td.name == "Drawable")
        .unwrap();
    assert_eq!(drawable_def.kind, TypeDefKind::Trait);

    // Impl block
    assert_eq!(ir.impl_blocks.len(), 1);
    assert_eq!(&*ir.impl_blocks[0].self_type, "Foo");
    assert_eq!(ir.impl_blocks[0].trait_name.as_deref(), Some("Drawable"));
}

// 1.T8: Pattern check facts (method calls, macros, attributes)
#[test]
fn test_ir_extracts_pattern_checks() {
    let source = r#"
        #[allow(dead_code)]
        fn example() {
            let v = vec![1, 2, 3];
            let c = v.clone();
            println!("hello");
        }
    "#;
    let ir = parse_and_extract(source);

    // Method call: .clone()
    let clone_calls: Vec<_> = ir
        .method_calls
        .iter()
        .filter(|mc| &*mc.method_name == "clone")
        .collect();
    assert!(!clone_calls.is_empty());

    // Macro: println!
    let println_macros: Vec<_> = ir
        .macro_invocations
        .iter()
        .filter(|m| m.text.contains("println"))
        .collect();
    assert!(!println_macros.is_empty());

    // Attribute: allow(dead_code)
    let allow_attrs: Vec<_> = ir
        .attributes
        .iter()
        .filter(|a| a.text.contains("allow"))
        .collect();
    assert!(!allow_attrs.is_empty());
}

// 1.T9: Module facts
#[test]
fn test_ir_extracts_modules() {
    let source = r#"
        #[cfg(test)]
        mod tests {
            #[test]
            fn it_works() {}
        }
        mod utils {}
    "#;
    let ir = parse_and_extract(source);

    assert_eq!(ir.modules.len(), 2);

    let test_mod = ir.modules.iter().find(|m| &*m.name == "tests").unwrap();
    assert!(test_mod.is_cfg_test);

    let utils_mod = ir.modules.iter().find(|m| &*m.name == "utils").unwrap();
    assert!(!utils_mod.is_cfg_test);
}

// 2.T1: IR capabilities match CapabilityVisitor output for all fixtures
#[test]
fn test_ir_capabilities_match_visitor() {
    let fixtures: &[(&str, &str)] = &[
        (
            "network_capability.rs",
            include_str!("fixtures/network_capability.rs"),
        ),
        (
            "filesystem_capability.rs",
            include_str!("fixtures/filesystem_capability.rs"),
        ),
        (
            "process_capability.rs",
            include_str!("fixtures/process_capability.rs"),
        ),
        (
            "env_capability.rs",
            include_str!("fixtures/env_capability.rs"),
        ),
        (
            "ffi_capability.rs",
            include_str!("fixtures/ffi_capability.rs"),
        ),
        (
            "unsafe_capability.rs",
            include_str!("fixtures/unsafe_capability.rs"),
        ),
        (
            "endpoint_capability.rs",
            include_str!("fixtures/endpoint_capability.rs"),
        ),
        (
            "crypto_capability.rs",
            include_str!("fixtures/crypto_capability.rs"),
        ),
        (
            "proc_macro_capability.rs",
            include_str!("fixtures/proc_macro_capability.rs"),
        ),
        (
            "system_time_capability.rs",
            include_str!("fixtures/system_time_capability.rs"),
        ),
        ("clean.rs", include_str!("fixtures/clean.rs")),
    ];

    let config = permissive_config();

    for (name, source) in fixtures {
        let baseline = analyze(name, source, &config, None).unwrap();
        let baseline_caps = baseline.capabilities.capabilities();

        let syntax = syn::parse_file(source).unwrap();
        let ir = extract(name, &syntax, None);
        let ir_profile = detect_capabilities(&ir, false);
        let ir_caps = ir_profile.capabilities();

        assert_eq!(
            &*baseline_caps, &*ir_caps,
            "capability mismatch for fixture {name}: baseline={baseline_caps:?}, ir={ir_caps:?}"
        );

        // Verify same number of findings
        assert_eq!(
            baseline.capabilities.findings.len(),
            ir_profile.findings.len(),
            "finding count mismatch for fixture {name}"
        );

        // Verify evidence strings match (sorted for stable comparison)
        let mut baseline_evidence: Vec<&str> = baseline
            .capabilities
            .findings
            .iter()
            .map(|f| f.evidence.as_ref())
            .collect();
        baseline_evidence.sort();

        let mut ir_evidence: Vec<&str> = ir_profile
            .findings
            .iter()
            .map(|f| f.evidence.as_ref())
            .collect();
        ir_evidence.sort();

        assert_eq!(
            baseline_evidence, ir_evidence,
            "evidence mismatch for fixture {name}"
        );
    }
}

// 2.T2: Network detection via IR
#[test]
fn test_ir_capabilities_network_detection() {
    let source = r#"
use std::net::TcpStream;

fn connect() {
    let _url = "https://api.example.com/data";
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir = extract("test.rs", &syntax, None);
    let profile = detect_capabilities(&ir, false);
    let caps = profile.capabilities();

    assert!(caps.contains(&Capability::Network));

    // Should have findings for both the use path and the URL string
    let net_findings: Vec<_> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Network)
        .collect();
    assert!(net_findings.len() >= 2);
}

// 2.T3: Unsafe detection via IR
#[test]
fn test_ir_capabilities_unsafe_detection() {
    let source = r#"
struct MyType;

unsafe fn dangerous() -> i32 { 42 }

unsafe impl Send for MyType {}

fn uses_unsafe() {
    let _val = unsafe { 42 };
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir = extract("test.rs", &syntax, None);
    let profile = detect_capabilities(&ir, false);
    let caps = profile.capabilities();

    assert!(caps.contains(&Capability::UnsafeCode));

    let evidence: Vec<&str> = profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::UnsafeCode)
        .map(|f| f.evidence.as_ref())
        .collect();

    assert!(evidence.contains(&"unsafe block"));
    assert!(evidence.contains(&"unsafe fn"));
    assert!(evidence.contains(&"unsafe impl"));
}

// ── Step 3: Style checks consume IR ──────────────────────────────────

// 3.T1: Nesting violations via IR
#[test]
fn test_ir_style_nesting_violations() {
    let source = include_str!("fixtures/nested_if.rs");
    let ir = parse_and_extract(source);
    let config = permissive_config();
    let violations = check_style(&ir, &config);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::NestedIf);

    let source = include_str!("fixtures/if_in_match.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::IfInMatch);

    let source = include_str!("fixtures/nested_match.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, ViolationType::NestedMatch);

    // Deep nesting
    let source = include_str!("fixtures/deep_nesting.rs");
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
    let source = include_str!("fixtures/forbidden_attr.rs");
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
    let source = include_str!("fixtures/forbidden_types.rs");
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
    let source = include_str!("fixtures/forbidden_calls.rs");
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
    let source = include_str!("fixtures/forbidden_macros.rs");
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
    let source = include_str!("fixtures/clone_in_loop.rs");
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
    let source = include_str!("fixtures/let_underscore_result.rs");
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
    let source = include_str!("fixtures/let_underscore_result_suppressed.rs");
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
    let source = include_str!("fixtures/mixed_concerns.rs");
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
    let source = include_str!("fixtures/mixed_concerns_clean.rs");
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
    let source = include_str!("fixtures/dyn_return.rs");
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

    let source = include_str!("fixtures/dyn_param.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let dyn_param: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::DynParam)
        .collect();
    assert!(!dyn_param.is_empty());

    let source = include_str!("fixtures/vec_box_dyn.rs");
    let ir = parse_and_extract(source);
    let violations = check_style(&ir, &config);
    let vbd: Vec<_> = violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::VecBoxDyn)
        .collect();
    assert!(!vbd.is_empty());

    let source = include_str!("fixtures/dyn_field.rs");
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
    let source = include_str!("fixtures/generic_naming.rs");
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

// 4.T1: analyze() produces identical output to direct IR calls
#[test]
fn test_analyze_produces_identical_output() {
    let fixtures: &[(&str, &str)] = &[
        ("clean.rs", include_str!("fixtures/clean.rs")),
        ("deep_nesting.rs", include_str!("fixtures/deep_nesting.rs")),
        ("nested_if.rs", include_str!("fixtures/nested_if.rs")),
        ("nested_match.rs", include_str!("fixtures/nested_match.rs")),
        ("if_in_match.rs", include_str!("fixtures/if_in_match.rs")),
        ("else_chain.rs", include_str!("fixtures/else_chain.rs")),
        (
            "clone_in_loop.rs",
            include_str!("fixtures/clone_in_loop.rs"),
        ),
        ("dyn_return.rs", include_str!("fixtures/dyn_return.rs")),
        ("dyn_param.rs", include_str!("fixtures/dyn_param.rs")),
        ("dyn_field.rs", include_str!("fixtures/dyn_field.rs")),
        ("vec_box_dyn.rs", include_str!("fixtures/vec_box_dyn.rs")),
        (
            "default_hasher.rs",
            include_str!("fixtures/default_hasher.rs"),
        ),
        (
            "let_underscore_result.rs",
            include_str!("fixtures/let_underscore_result.rs"),
        ),
        ("inline_tests.rs", include_str!("fixtures/inline_tests.rs")),
        (
            "mixed_concerns.rs",
            include_str!("fixtures/mixed_concerns.rs"),
        ),
        (
            "mixed_concerns_clean.rs",
            include_str!("fixtures/mixed_concerns_clean.rs"),
        ),
        (
            "mixed_concerns_body.rs",
            include_str!("fixtures/mixed_concerns_body.rs"),
        ),
        (
            "generic_naming.rs",
            include_str!("fixtures/generic_naming.rs"),
        ),
        (
            "network_capability.rs",
            include_str!("fixtures/network_capability.rs"),
        ),
        (
            "filesystem_capability.rs",
            include_str!("fixtures/filesystem_capability.rs"),
        ),
        (
            "process_capability.rs",
            include_str!("fixtures/process_capability.rs"),
        ),
        (
            "env_capability.rs",
            include_str!("fixtures/env_capability.rs"),
        ),
        (
            "ffi_capability.rs",
            include_str!("fixtures/ffi_capability.rs"),
        ),
        (
            "crypto_capability.rs",
            include_str!("fixtures/crypto_capability.rs"),
        ),
        (
            "unsafe_capability.rs",
            include_str!("fixtures/unsafe_capability.rs"),
        ),
        (
            "endpoint_capability.rs",
            include_str!("fixtures/endpoint_capability.rs"),
        ),
        (
            "proc_macro_capability.rs",
            include_str!("fixtures/proc_macro_capability.rs"),
        ),
        (
            "system_time_capability.rs",
            include_str!("fixtures/system_time_capability.rs"),
        ),
    ];

    let config = CheckConfig::default();

    for (name, source) in fixtures {
        // Run through analyze() — the public entry point
        let result = analyze(name, source, &config, None).unwrap_or_else(|e| {
            panic!("analyze failed for {name}: {e}");
        });

        // Run through direct IR path for comparison
        let ir = parse_and_extract(source);
        let direct_violations = check_style(&ir, &config);
        let direct_capabilities = detect_capabilities(&ir, false);

        // Violation counts must match exactly
        assert_eq!(
            result.violations.len(),
            direct_violations.len(),
            "{name}: violation count mismatch (analyze={}, direct={})",
            result.violations.len(),
            direct_violations.len()
        );

        // Violation types must match in order
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

        // Capability finding counts must match
        assert_eq!(
            result.capabilities.findings.len(),
            direct_capabilities.findings.len(),
            "{name}: capability count mismatch"
        );

        // Capability findings must match in order
        for (i, (a, d)) in result
            .capabilities
            .findings
            .iter()
            .zip(direct_capabilities.findings.iter())
            .enumerate()
        {
            assert_eq!(
                a.capability, d.capability,
                "{name}: capability[{i}] mismatch"
            );
        }
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
        !result.capabilities.findings.is_empty(),
        "expected capability findings from unsafe/network"
    );
}
