//! What semantic enrichment adds to extraction, and what it leaves alone.

use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::lint::analyze;

use crate::fixtures::{fixture_lib_path, fixture_workspace_root, parse_fixture};

// --- Step 2: IR extraction enrichment tests ---

#[test]
fn test_extract_with_semantic_resolves_binding_type() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Find the binding `h` from `binding_through_alias()`
    let binding = enriched
        .bindings
        .iter()
        .find(|b| &*b.name == "h")
        .expect("should find h binding");

    assert!(
        binding.resolved_type.is_some(),
        "resolved_type should be populated for a typed binding"
    );
    let resolved = binding.resolved_type.as_deref().unwrap();
    assert!(
        resolved.contains("Arc"),
        "resolved type should contain 'Arc', got: {resolved}"
    );
    assert!(
        binding.is_refcounted,
        "is_refcounted should be true for a Handle = Arc<String> binding"
    );
}

#[test]
fn test_extract_without_semantic_leaves_none() {
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let plain = ir::extract(&file_path, &syntax, None);

    let binding = plain
        .bindings
        .iter()
        .find(|b| &*b.name == "h")
        .expect("should find _h binding");

    assert!(
        binding.resolved_type.is_none(),
        "resolved_type should be None without semantic context"
    );
    // Syntactic check misses alias — `Handle` doesn't look like Arc/Rc
    assert!(
        !binding.is_refcounted,
        "is_refcounted should be false without semantic (alias not resolved)"
    );
}

#[test]
fn test_extract_resolves_type_ref() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // bar() returns MyHashMap — find its return TypeRefFact
    let bar_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "bar")
        .expect("should find bar function");

    let type_ref = enriched
        .type_refs
        .iter()
        .find(|tr| tr.containing_fn == Some(bar_fn_idx) && tr.context == ir::TypeRefContext::Return)
        .expect("should find return type ref for bar()");

    assert!(
        type_ref.is_default_hasher,
        "is_default_hasher should be true (resolved through alias)"
    );
}

#[test]
fn test_extract_resolves_method_receiver() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Find clone() call in clone_string_in_loop — receiver is String
    let clone_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "clone_string_in_loop")
        .expect("should find clone_string_in_loop function");

    let clone_call = enriched
        .method_calls
        .iter()
        .find(|mc| &*mc.method_name == "clone" && mc.containing_fn == Some(clone_fn_idx))
        .expect("should find clone method call in clone_string_in_loop");

    assert!(
        clone_call.receiver_type.is_some(),
        "receiver_type should be populated"
    );
    assert!(
        !clone_call.is_copy_receiver,
        "String should not be a Copy receiver"
    );
}

#[test]
fn test_extract_copy_receiver_detected() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Find clone() call in clone_copy_in_loop — receiver is i32
    let copy_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "clone_copy_in_loop")
        .expect("should find clone_copy_in_loop function");

    let clone_call = enriched
        .method_calls
        .iter()
        .find(|mc| &*mc.method_name == "clone" && mc.containing_fn == Some(copy_fn_idx))
        .expect("should find clone method call in clone_copy_in_loop");

    assert!(
        clone_call.is_copy_receiver,
        "i32 should be detected as a Copy receiver"
    );
}

// --- Step 5: Receiver type enrichment reuses binding types ---

/// 5.T2: Multiple method calls on the same binding all get receiver_type populated.
#[test]
fn test_receiver_type_enrichment_reuses_binding_types() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    let fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "repeated_method_calls_same_binding")
        .expect("should find repeated_method_calls_same_binding function");

    let calls_in_fn: Vec<_> = enriched
        .method_calls
        .iter()
        .filter(|mc| mc.containing_fn == Some(fn_idx) && mc.receiver_type.is_some())
        .collect();

    assert!(
        calls_in_fn.len() >= 3,
        "expected at least 3 method calls with resolved receiver_type, got {}",
        calls_in_fn.len()
    );

    for mc in &calls_in_fn {
        let rt = mc.receiver_type.as_deref().unwrap();
        assert!(
            rt.contains("String"),
            "receiver_type should resolve to String, got: {rt}"
        );
    }
}

// --- Step 1 (DataFlow): DataFlowFact and reachable annotation ---

/// 1.T1: data_flows is empty without semantic context.
#[test]
fn test_data_flow_fact_default_empty() {
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    // Without semantic context, no data flow analysis runs.
    let extracted = ir::extract(&file_path, &syntax, None);

    assert!(
        extracted.data_flows.is_empty(),
        "data_flows should be empty without semantic context"
    );
}

/// 1.T2: reachable is None by default on capability findings.
#[test]
fn test_capability_finding_reachable_none_by_default() {
    // Use a source with a known capability (std::net import)
    let source = r#"use std::net::TcpStream;"#;
    let config = CheckConfig::default();
    let result = analyze("<test>", source, &config, None).unwrap();

    assert!(
        !result.capabilities.findings.is_empty(),
        "should detect Network capability from std::net import"
    );
    for finding in result.capabilities.findings.iter() {
        assert!(
            finding.reachable.is_none(),
            "reachable should be None by default, got: {:?}",
            finding.reachable
        );
    }
}

// --- Step 2: Call graph construction ---
