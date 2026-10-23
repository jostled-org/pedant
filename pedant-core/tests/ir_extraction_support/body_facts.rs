//! Facts one parse extracts from function bodies: control flow, bindings,
//! type references, capability signals and pattern checks.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::ir::{BranchContext, ControlFlowKind, TypeRefContext, UnsafeKind};

use super::parse_and_extract;

// A match guard is part of the arm's pattern, not a field beside it. Code the
// guard states is still extracted, at the depth of the match it guards.
#[test]
fn test_ir_extracts_control_flow_inside_match_guard() {
    let source = r#"
        fn example(x: Option<Vec<i32>>) {
            match x {
                Some(v) if v.iter().any(|n| *n > 0) => {}
                _ => {}
            }
        }
    "#;
    let ir = parse_and_extract(source);

    let match_depth = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::Match)
        .expect("the match is extracted")
        .depth;
    let closure = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::Closure)
        .expect("the closure the guard states is extracted");
    assert_eq!(closure.depth, match_depth);
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
