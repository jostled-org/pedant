#![cfg(feature = "semantic")]

use std::path::PathBuf;
use std::sync::Arc;

use pedant_core::SemanticContext;
use pedant_core::SemanticFileAnalysis;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::ir::DataFlowKind;
use pedant_core::ir::{DataFlowFact, IrSpan};
use pedant_core::lint::{analyze, analyze_with_build_script, determine_analysis_tier};
use pedant_core::violation::ViolationType;
use pedant_types::{AnalysisTier, Capability};

fn fixture_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("semantic_workspace")
}

#[test]
fn test_semantic_context_loads_simple_workspace() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root);
    assert!(
        ctx.is_some(),
        "SemanticContext::load should succeed for a valid workspace"
    );
}

#[test]
fn test_resolve_type_through_alias() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let lib_path = root.join("src").join("lib.rs");
    let file = lib_path.to_str().expect("path should be valid UTF-8");

    // Line 11 (1-based): `pub fn foo() -> MyArc {`
    // MyArc starts at column 16 (0-based).
    // resolve_type should resolve through the alias to Arc<String>.
    let resolved = ctx.resolve_type(file, 11, 16);
    assert!(
        resolved.is_some(),
        "resolve_type should return Some for a type alias in return position"
    );
    let resolved_str = resolved.unwrap();
    assert!(
        resolved_str.contains("Arc"),
        "resolved type should contain 'Arc', got: {resolved_str}"
    );
}

#[test]
fn test_resolve_type_unknown_position_returns_none() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let lib_path = root.join("src").join("lib.rs");
    let file = lib_path.to_str().expect("path should be valid UTF-8");

    // Line 21 (1-based): `/// A comment line for testing unknown position.`
    // No type at a comment position.
    let resolved = ctx.resolve_type(file, 21, 0);
    assert!(
        resolved.is_none(),
        "resolve_type should return None for a comment position"
    );
}

#[test]
fn test_is_copy_for_primitive() {
    let root = fixture_workspace_root();
    SemanticContext::load(&root).expect("workspace should load");
    assert!(SemanticContext::is_copy("i32"), "i32 should implement Copy");
}

#[test]
fn test_is_copy_for_string() {
    let root = fixture_workspace_root();
    SemanticContext::load(&root).expect("workspace should load");
    assert!(
        !SemanticContext::is_copy("String"),
        "String should not implement Copy"
    );
}

#[test]
fn test_load_missing_workspace_returns_none() {
    let nonexistent = PathBuf::from("/tmp/pedant_test_nonexistent_workspace_dir");
    let ctx = SemanticContext::load(&nonexistent);
    assert!(
        ctx.is_none(),
        "SemanticContext::load should return None for a missing workspace"
    );
}

#[test]
fn test_load_invalid_workspace_returns_none() {
    let workspace_dir = std::env::temp_dir().join("pedant_test_invalid_workspace");
    std::fs::create_dir_all(&workspace_dir).unwrap();
    std::fs::write(workspace_dir.join("Cargo.toml"), "[invalid\nbroken toml").unwrap();

    let loaded = SemanticContext::load(&workspace_dir);
    assert!(
        loaded.is_none(),
        "SemanticContext::load should return None for a malformed workspace"
    );

    std::fs::remove_dir_all(&workspace_dir).unwrap();
}

// --- Step 2: IR extraction enrichment tests ---

fn fixture_lib_path() -> String {
    fixture_workspace_root()
        .join("src")
        .join("lib.rs")
        .to_string_lossy()
        .into_owned()
}

fn parse_fixture() -> syn::File {
    let lib_path = fixture_workspace_root().join("src").join("lib.rs");
    let source = std::fs::read_to_string(&lib_path).expect("fixture lib.rs should exist");
    syn::parse_file(&source).expect("fixture should parse")
}

#[test]
fn test_extract_with_semantic_resolves_binding_type() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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

fn dataflow_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("dataflow_workspace")
}

fn dataflow_lib_path() -> String {
    dataflow_workspace_root()
        .join("src")
        .join("lib.rs")
        .to_string_lossy()
        .into_owned()
}

/// 2.T1: call_graph returns edges for direct function calls.
#[test]
fn test_call_graph_direct_call() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let edges = analysis.call_graph();

    let has_run_fetch = edges
        .iter()
        .any(|(caller, callee)| &**caller == "run" && &**callee == "fetch");
    assert!(
        has_run_fetch,
        "call graph should contain (\"run\", \"fetch\") edge, got: {edges:?}"
    );
}

/// 2.T2: call_graph returns no edges for a function with no calls.
#[test]
fn test_call_graph_no_calls() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let edges = analysis.call_graph();

    let no_calls_edges: Vec<_> = edges
        .iter()
        .filter(|(caller, _)| &**caller == "no_calls")
        .collect();
    assert!(
        no_calls_edges.is_empty(),
        "no_calls function should have no outgoing edges, got: {no_calls_edges:?}"
    );
}

// --- Step 3 (DataFlow): Taint propagation ---

/// 3.T1: trace_taints detects env var flowing to network sink.
#[test]
fn test_trace_taints_env_to_network() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let summary = analysis.function("leak_env").expect("should find leak_env");
    let taints = summary.taint_flows();

    assert_eq!(
        taints.len(),
        1,
        "should find one taint flow in leak_env, got: {taints:?}"
    );
    assert_eq!(
        taints[0].source_capability,
        Some(pedant_types::Capability::EnvAccess)
    );
    assert_eq!(
        taints[0].sink_capability,
        Some(pedant_types::Capability::Network)
    );
}

/// 3.T2: trace_taints returns empty for safe env usage (no flow to sink).
#[test]
fn test_trace_taints_no_flow() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let summary = analysis.function("safe_env").expect("should find safe_env");
    let taints = summary.taint_flows();

    assert!(
        taints.is_empty(),
        "safe_env should have no taint flows, got: {taints:?}"
    );
}

// --- Step 4: Reachability from public entry points ---

/// 4.T1: Public function is reachable.
#[test]
fn test_is_reachable_public_fn() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // reachable_network() is pub and uses TcpStream at line 20
    assert!(
        analysis.is_line_reachable(20),
        "pub fn reachable_network should be reachable"
    );
}

/// 4.T2: Private function never called is unreachable.
#[test]
fn test_is_reachable_dead_code() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // unreachable_private() is private and never called — line 25
    assert!(
        !analysis.is_line_reachable(25),
        "private fn unreachable_private should not be reachable"
    );
}

// --- Existing Step 3: analyze() with SemanticContext ---

fn fixture_source() -> String {
    let lib_path = fixture_workspace_root().join("src").join("lib.rs");
    std::fs::read_to_string(&lib_path).expect("fixture lib.rs should exist")
}

fn clone_in_loop_config() -> CheckConfig {
    CheckConfig {
        check_clone_in_loop: true,
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

fn default_hasher_config() -> CheckConfig {
    CheckConfig {
        check_default_hasher: true,
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

/// 3.T1: With semantic analysis, clone on aliased Arc in a loop is NOT flagged
/// (recognized as refcounted through alias). Without semantic, it IS flagged.
#[test]
fn test_analyze_with_semantic_detects_aliased_refcount() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let source = fixture_source();
    let config = clone_in_loop_config();

    // clone_aliased_arc_in_loop: h.clone() is at line 37 in the fixture
    let aliased_clone_line = 37;

    // With semantic: alias resolved, clone on Arc is cheap — no violation
    let with_semantic = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let has_aliased_clone = with_semantic.violations.iter().any(|v| {
        matches!(v.violation_type, ViolationType::CloneInLoop) && v.line == aliased_clone_line
    });
    assert!(
        !has_aliased_clone,
        "semantic analysis should suppress clone-in-loop for aliased Arc"
    );

    // Without semantic: alias not resolved, flagged as expensive clone
    let without_semantic = analyze(&file_path, &source, &config, None).unwrap();
    let has_aliased_clone = without_semantic.violations.iter().any(|v| {
        matches!(v.violation_type, ViolationType::CloneInLoop) && v.line == aliased_clone_line
    });
    assert!(
        has_aliased_clone,
        "without semantic, clone-in-loop on aliased Arc should be flagged"
    );
}

/// 3.T2: With semantic analysis, default-hasher violation is raised for aliased HashMap.
#[test]
fn test_analyze_with_semantic_detects_aliased_hasher() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let source = fixture_source();
    let config = default_hasher_config();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let hasher_violations: Vec<_> = result
        .violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::DefaultHasher))
        .collect();
    assert!(
        !hasher_violations.is_empty(),
        "semantic analysis should detect default hasher through MyHashMap alias"
    );
}

/// 3.T3: With semantic analysis, capability detection still works for aliased imports.
#[test]
fn test_analyze_with_semantic_resolves_capability_alias() {
    let root = fixture_workspace_root();
    let semantic_ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let source = fixture_source();
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    };

    // Verify analyze with semantic context does not break capability detection.
    // The fixture uses std::sync::Arc and std::collections::HashMap —
    // these are stdlib imports, not external capabilities.
    let analysis = analyze(&file_path, &source, &config, Some(&semantic_ctx)).unwrap();
    // No network/filesystem capabilities in the fixture
    assert!(
        analysis.capabilities.findings.is_empty(),
        "fixture should not trigger capability findings, got: {:?}",
        analysis.capabilities.findings
    );
}

// --- Step 5: Extractor populates DataFlow facts and reachability ---

fn dataflow_source() -> String {
    let lib_path = dataflow_workspace_root().join("src").join("lib.rs");
    std::fs::read_to_string(&lib_path).expect("dataflow lib.rs should exist")
}

/// 5.T1: analyze() with SemanticContext populates data_flows.
#[test]
fn test_analyze_with_semantic_populates_data_flows() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();

    let env_to_net = result.data_flows.iter().any(|f| {
        f.source_capability == Some(pedant_types::Capability::EnvAccess)
            && f.sink_capability == Some(pedant_types::Capability::Network)
    });
    assert!(
        env_to_net,
        "should contain EnvAccess→Network data flow from leak_env, got: {:?}",
        result.data_flows
    );
}

/// 5.T2: analyze() with SemanticContext annotates reachability on findings.
#[test]
fn test_analyze_with_semantic_annotates_reachability() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();

    // All findings should have reachable set (not None) when semantic is active.
    for finding in result.capabilities.findings.iter() {
        assert!(
            finding.reachable.is_some(),
            "finding at line {} should have reachable annotated, got None",
            finding.location.line,
        );
    }

    // reachable_network() is pub — its findings should be reachable.
    // Line 21: TcpStream::connect string literal "127.0.0.1:8080"
    let reachable_finding = result
        .capabilities
        .findings
        .iter()
        .find(|f| f.location.line == 21);
    assert!(
        reachable_finding.is_some_and(|f| f.reachable == Some(true)),
        "finding in pub fn reachable_network (line 21) should be reachable"
    );

    // unreachable_private() is private, never called — unreachable.
    // Line 26: TcpStream::connect string literal "127.0.0.1:8080"
    let unreachable_finding = result
        .capabilities
        .findings
        .iter()
        .find(|f| f.location.line == 26);
    assert!(
        unreachable_finding.is_some_and(|f| f.reachable == Some(false)),
        "finding in private fn unreachable_private (line 26) should be unreachable"
    );
}

/// 5.T3: analyze() without SemanticContext leaves data_flows empty and reachable None.
#[test]
fn test_analyze_without_semantic_no_data_flows() {
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, None).unwrap();

    assert!(
        result.data_flows.is_empty(),
        "data_flows should be empty without semantic context"
    );
    for finding in result.capabilities.findings.iter() {
        assert!(
            finding.reachable.is_none(),
            "reachable should be None without semantic, got {:?} at line {}",
            finding.reachable,
            finding.location.line,
        );
    }
}

#[test]
fn test_analyze_with_build_script_preserves_semantic_reachability() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze_with_build_script(
        &file_path,
        &source,
        &config,
        Some(&ctx),
        Some((&file_path, &source)),
    )
    .unwrap();

    let build_findings: Vec<_> = result
        .capabilities
        .findings
        .iter()
        .filter(|finding| finding.is_build_hook())
        .collect();

    assert!(!build_findings.is_empty(), "expected build-script findings");
    assert!(
        build_findings
            .iter()
            .all(|finding| finding.reachable.is_some()),
        "build findings should keep semantic reachability"
    );
}

// --- Helpers for dataflow per-function issue assertions ---

enum IssueCategory {
    Quality,
    Performance,
    Concurrency,
}

/// Load the dataflow fixture's file analysis (shared across tests).
fn dataflow_file_analysis() -> Arc<SemanticFileAnalysis> {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();
    ctx.analyze_file(&file)
        .expect("should produce file analysis")
}

/// Assert that `fn_name` produces exactly `expected` findings of `kind`
/// in the given issue category. Panics with a descriptive message on mismatch.
fn assert_function_issue_count(
    analysis: &SemanticFileAnalysis,
    fn_name: &str,
    category: IssueCategory,
    kind: DataFlowKind,
    expected: usize,
) {
    let summary = analysis
        .function(fn_name)
        .unwrap_or_else(|| panic!("should find {fn_name}"));
    let facts = match category {
        IssueCategory::Quality => summary.quality_issues(),
        IssueCategory::Performance => summary.performance_issues(),
        IssueCategory::Concurrency => summary.concurrency_issues(),
    };
    let matched: Vec<_> = facts.iter().filter(|f| f.kind == kind).collect();
    assert_eq!(
        matched.len(),
        expected,
        "expected {expected} {kind:?} in {fn_name}(), got: {matched:?}"
    );
}

// --- Quality: dead store detection ---

/// Dead store: value overwritten before read.
#[test]
fn test_dead_store_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "dead_store",
        IssueCategory::Quality,
        DataFlowKind::DeadStore,
        1,
    );
}

/// No dead store when value is read before reassignment.
#[test]
fn test_dead_store_not_flagged_when_read() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "no_dead_store",
        IssueCategory::Quality,
        DataFlowKind::DeadStore,
        0,
    );
}

// --- Quality: discarded result detection ---

/// Result-returning function called without binding.
#[test]
fn test_discarded_result_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "discarded_result",
        IssueCategory::Quality,
        DataFlowKind::DiscardedResult,
        1,
    );
}

/// Result bound with `let _ =` is intentional discard — not flagged.
#[test]
fn test_discarded_result_not_flagged_when_bound() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "discarded_result_bound",
        IssueCategory::Quality,
        DataFlowKind::DiscardedResult,
        0,
    );
}

// --- Quality: partial error handling detection ---

/// Result handled on some paths, dropped on others.
#[test]
fn test_partial_error_handling_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "partial_error_handling",
        IssueCategory::Quality,
        DataFlowKind::PartialErrorHandling,
        1,
    );
}

// --- Performance: repeated call detection ---

/// Repeated call: same function, same args within a scope.
#[test]
fn test_repeated_call_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "repeated_call_same_args",
        IssueCategory::Performance,
        DataFlowKind::RepeatedCall,
        1,
    );
}

/// Different arguments — no repeated call.
#[test]
fn test_repeated_call_different_args_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "repeated_call_different_args",
        IssueCategory::Performance,
        DataFlowKind::RepeatedCall,
        0,
    );
}

// --- Performance: unnecessary clone detection ---

/// Clone where original is never used after.
#[test]
fn test_unnecessary_clone_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "unnecessary_clone",
        IssueCategory::Performance,
        DataFlowKind::UnnecessaryClone,
        1,
    );
}

/// Clone where original is used after — necessary.
#[test]
fn test_clone_needed_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "clone_needed",
        IssueCategory::Performance,
        DataFlowKind::UnnecessaryClone,
        0,
    );
}

// --- Performance: allocation in loop detection ---

/// Vec allocated inside loop body.
#[test]
fn test_allocation_in_loop_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "allocation_in_loop",
        IssueCategory::Performance,
        DataFlowKind::AllocationInLoop,
        1,
    );
}

// --- Performance: redundant collect detection ---

/// Collect then immediately re-iterate.
#[test]
fn test_redundant_collect_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "redundant_collect",
        IssueCategory::Performance,
        DataFlowKind::RedundantCollect,
        1,
    );
}

// --- Concurrency: lock across await detection ---

/// Lock guard held across await point — direct.
#[test]
fn test_lock_across_await_direct() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "lock_across_await_direct",
        IssueCategory::Concurrency,
        DataFlowKind::LockAcrossAwait,
        1,
    );
}

/// Lock guard held across async function call — cross-function.
#[test]
fn test_lock_across_await_cross_function() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "lock_across_await_cross_fn",
        IssueCategory::Concurrency,
        DataFlowKind::LockAcrossAwait,
        1,
    );
}

/// Lock guard dropped before await — safe pattern, not flagged.
#[test]
fn test_lock_dropped_before_await_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "lock_dropped_before_await",
        IssueCategory::Concurrency,
        DataFlowKind::LockAcrossAwait,
        0,
    );
}

// --- Concurrency: inconsistent lock ordering ---

/// Inconsistent lock ordering across lock_order_a and lock_order_b.
#[test]
fn test_inconsistent_lock_order_detected() {
    let analysis = dataflow_file_analysis();
    let findings: Vec<_> = analysis
        .data_flows()
        .iter()
        .filter(|f| f.kind == DataFlowKind::InconsistentLockOrder)
        .collect();
    assert!(
        !findings.is_empty(),
        "should find inconsistent lock ordering across lock_order_a/lock_order_b, got: {findings:?}"
    );
}

/// Consistent lock ordering — not flagged.
#[test]
fn test_consistent_lock_order_not_flagged() {
    let analysis = dataflow_file_analysis();
    // The finding should reference lock_order_a and lock_order_b (inconsistent pair).
    // lock_order_consistent and lock_order_a have the same ordering — no finding between them.
    let findings: Vec<_> = analysis
        .data_flows()
        .iter()
        .filter(|f| {
            f.kind == DataFlowKind::InconsistentLockOrder
                && f.message.contains("lock_order_consistent")
        })
        .collect();
    assert!(
        findings.is_empty(),
        "should find no inconsistent ordering involving lock_order_consistent, got: {findings:?}"
    );
}

// --- Quality: immutable growable detection ---

/// Immutable Vec detected.
#[test]
fn test_immutable_vec_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "immutable_vec",
        IssueCategory::Quality,
        DataFlowKind::ImmutableGrowable,
        1,
    );
    let summary = analysis.function("immutable_vec").unwrap();
    let finding = summary
        .quality_issues()
        .iter()
        .find(|f| f.kind == DataFlowKind::ImmutableGrowable)
        .unwrap();
    assert!(
        finding.message.contains("Vec"),
        "message should mention Vec, got: {}",
        finding.message
    );
}

/// Immutable String detected.
#[test]
fn test_immutable_string_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "immutable_string",
        IssueCategory::Quality,
        DataFlowKind::ImmutableGrowable,
        1,
    );
    let summary = analysis.function("immutable_string").unwrap();
    let finding = summary
        .quality_issues()
        .iter()
        .find(|f| f.kind == DataFlowKind::ImmutableGrowable)
        .unwrap();
    assert!(
        finding.message.contains("String"),
        "message should mention String, got: {}",
        finding.message
    );
}

/// Mutated Vec not flagged.
#[test]
fn test_mutated_vec_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "mutated_vec",
        IssueCategory::Quality,
        DataFlowKind::ImmutableGrowable,
        0,
    );
}

/// Returned Vec not flagged (caller may mutate).
#[test]
fn test_returned_vec_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "returned_vec",
        IssueCategory::Quality,
        DataFlowKind::ImmutableGrowable,
        0,
    );
}

/// Vec passed as &mut ref not flagged.
#[test]
fn test_vec_passed_as_mut_ref_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "caller_passes_mut",
        IssueCategory::Quality,
        DataFlowKind::ImmutableGrowable,
        0,
    );
}

// --- Quality: swallowed .ok() detection ---

/// SwallowedOk: .ok() as statement on Result — detected.
#[test]
fn test_swallowed_ok_statement_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "swallowed_ok_statement",
        IssueCategory::Quality,
        DataFlowKind::SwallowedOk,
        1,
    );
}

/// SwallowedOk: let _ = expr.ok() — detected.
#[test]
fn test_swallowed_ok_let_underscore_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "swallowed_ok_let_underscore",
        IssueCategory::Quality,
        DataFlowKind::SwallowedOk,
        1,
    );
}

/// .ok() result is used — not flagged.
#[test]
fn test_ok_used_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "ok_used",
        IssueCategory::Quality,
        DataFlowKind::SwallowedOk,
        0,
    );
}

/// write!().ok() is exempt per audit ledger.
#[test]
fn test_write_ok_exempt() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "write_ok_exempt",
        IssueCategory::Quality,
        DataFlowKind::SwallowedOk,
        0,
    );
}

// --- Concurrency: unobserved spawn detection ---

/// UnobservedSpawn: std::thread::spawn as statement — detected.
#[test]
fn test_unobserved_thread_spawn_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "unobserved_thread_spawn",
        IssueCategory::Concurrency,
        DataFlowKind::UnobservedSpawn,
        1,
    );
}

/// UnobservedSpawn: let _ = std::thread::spawn — detected.
#[test]
fn test_unobserved_thread_spawn_let_underscore_detected() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "unobserved_thread_spawn_let_underscore",
        IssueCategory::Concurrency,
        DataFlowKind::UnobservedSpawn,
        1,
    );
}

/// Observed spawn: JoinHandle bound and used — not flagged.
#[test]
fn test_observed_thread_spawn_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "observed_thread_spawn",
        IssueCategory::Concurrency,
        DataFlowKind::UnobservedSpawn,
        0,
    );
}

/// Custom spawn function — not std::thread, not flagged.
#[test]
fn test_custom_spawn_not_flagged() {
    let analysis = dataflow_file_analysis();
    assert_function_issue_count(
        &analysis,
        "custom_spawn",
        IssueCategory::Concurrency,
        DataFlowKind::UnobservedSpawn,
        0,
    );
}

/// 5.T4: analysis tier is DataFlow when semantic context produces data flows.
#[test]
fn test_attestation_tier_dataflow() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let tier = determine_analysis_tier(Some(&ctx), &result.data_flows);

    assert_eq!(
        tier,
        AnalysisTier::DataFlow,
        "tier should be DataFlow when semantic context is active and flows are detected"
    );

    // Without semantic: Syntactic tier
    let plain = analyze(&file_path, &source, &config, None).unwrap();
    let plain_tier = determine_analysis_tier(None, &plain.data_flows);
    assert_eq!(plain_tier, AnalysisTier::Syntactic);

    // Semantic but no flows: Semantic tier
    let semantic_no_flow_tier = determine_analysis_tier(Some(&ctx), &[]);
    assert_eq!(semantic_no_flow_tier, AnalysisTier::Semantic);
}

#[test]
fn test_analysis_tier_requires_semantic_context_for_dataflow() {
    let data_flows = [DataFlowFact {
        kind: DataFlowKind::DiscardedResult,
        source_capability: Some(Capability::FileRead),
        source_span: IrSpan { line: 1, column: 1 },
        sink_capability: Some(Capability::Network),
        sink_span: IrSpan { line: 2, column: 1 },
        call_chain: Box::new([]),
        message: Box::from("synthetic flow"),
    }];

    let tier = determine_analysis_tier(None, &data_flows);
    assert_eq!(tier, AnalysisTier::Syntactic);
}

// --- Cache: public queries match pre-cache behavior (T1) ---

/// T1: Run all public semantic queries on the dataflow fixture and verify
/// outputs match expected behavior. Guards against regressions when
/// introducing file-level analysis caching.
#[test]
fn test_semantic_public_queries_match_pre_cache_behavior() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // call_graph: run→fetch edge exists
    let edges = analysis.call_graph();
    assert!(
        edges.iter().any(|(c, e)| &**c == "run" && &**e == "fetch"),
        "call_graph should contain (run, fetch) edge"
    );

    // trace_taints: leak_env has env→network flow
    let summary = analysis.function("leak_env").expect("should find leak_env");
    let taints = summary.taint_flows();
    assert_eq!(taints.len(), 1, "leak_env should have one taint flow");

    // detect_quality_issues: dead_store detects DeadStore
    let summary = analysis
        .function("dead_store")
        .expect("should find dead_store");
    let quality = summary.quality_issues();
    assert!(
        quality.iter().any(|f| f.kind == DataFlowKind::DeadStore),
        "dead_store should produce DeadStore finding"
    );

    // detect_performance_issues: repeated_call_same_args detects RepeatedCall
    let summary = analysis
        .function("repeated_call_same_args")
        .expect("should find repeated_call_same_args");
    let perf = summary.performance_issues();
    assert!(
        perf.iter().any(|f| f.kind == DataFlowKind::RepeatedCall),
        "repeated_call_same_args should produce RepeatedCall finding"
    );

    // detect_concurrency_issues: unobserved_thread_spawn detects UnobservedSpawn
    let summary = analysis
        .function("unobserved_thread_spawn")
        .expect("should find unobserved_thread_spawn");
    let conc = summary.concurrency_issues();
    assert!(
        conc.iter().any(|f| f.kind == DataFlowKind::UnobservedSpawn),
        "unobserved_thread_spawn should produce UnobservedSpawn finding"
    );

    // is_reachable: pub fn is reachable, private uncalled is not
    assert!(
        analysis.is_line_reachable(20),
        "pub fn reachable_network should be reachable"
    );
    assert!(
        !analysis.is_line_reachable(25),
        "private fn unreachable_private should not be reachable"
    );

    // detect_inconsistent_lock_ordering: file has ordering violation
    assert!(
        analysis
            .data_flows()
            .iter()
            .any(|f| f.kind == DataFlowKind::InconsistentLockOrder),
        "should detect inconsistent lock ordering"
    );
}

// --- Cache: multiple queries reuse cached file state (T2) ---

/// T2: Multiple semantic queries on the same file should reuse cached
/// file-level analysis (call graph, function entries, reachable set)
/// instead of rebuilding from scratch.
#[test]
fn test_semantic_multiple_queries_reuse_cached_file_state() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    // First query: analyze_file triggers file-level analysis
    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let count_after_first = ctx.file_setup_count();

    // Second query: is_line_reachable should reuse cached state
    let _reachable = analysis.is_line_reachable(20);
    let count_after_second = ctx.file_setup_count();

    // Third query: check_reachability_batch should reuse cached state
    let _batch = analysis.check_reachability_batch(&[20, 25]);
    let count_after_third = ctx.file_setup_count();

    assert!(
        count_after_first >= 1,
        "first query should trigger file setup"
    );
    assert_eq!(
        count_after_first, count_after_second,
        "is_line_reachable should reuse cached state, not re-setup file"
    );
    assert_eq!(
        count_after_second, count_after_third,
        "check_reachability_batch should reuse cached state"
    );
}

// --- Cache: batched and individual queries agree (T3) ---

/// T3: The batched data-flow enrichment (via analyze()) should produce
/// the same findings as the union of individual per-function queries.
#[test]
fn test_enrich_all_data_flows_and_individual_queries_agree() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    // Batched results via analyze()
    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let batched = &result.data_flows;

    // Individual results: query each function's analysis summary
    let file = dataflow_lib_path();
    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let all_fn_names: &[&str] = &[
        "fetch",
        "run",
        "no_calls",
        "reachable_network",
        "unreachable_private",
        "leak_env",
        "safe_env",
        "compute_something",
        "compute_other",
        "use_value",
        "dead_store",
        "no_dead_store",
        "discarded_result",
        "discarded_result_bound",
        "partial_error_handling",
        "expensive_compute",
        "use_both",
        "repeated_call_same_args",
        "repeated_call_different_args",
        "consume",
        "unnecessary_clone",
        "clone_needed",
        "fill",
        "process",
        "allocation_in_loop",
        "redundant_collect",
        "do_async_work",
        "lock_across_await_direct",
        "helper_async",
        "lock_across_await_cross_fn",
        "lock_dropped_before_await",
        "lock_order_a",
        "lock_order_b",
        "lock_order_consistent",
        "immutable_vec",
        "immutable_string",
        "mutated_vec",
        "returned_vec",
        "passed_mut",
        "caller_passes_mut",
        "fallible_io",
        "swallowed_ok_statement",
        "swallowed_ok_let_underscore",
        "ok_used",
        "write_ok_exempt",
        "unobserved_thread_spawn",
        "unobserved_thread_spawn_let_underscore",
        "observed_thread_spawn",
        "custom_spawn_impl",
        "custom_spawn",
    ];

    let mut individual: Vec<ir::DataFlowFact> = Vec::new();
    for fn_name in all_fn_names {
        if let Some(summary) = analysis.function(fn_name) {
            individual.extend_from_slice(summary.taint_flows());
            individual.extend_from_slice(summary.quality_issues());
            individual.extend_from_slice(summary.performance_issues());
            individual.extend_from_slice(summary.concurrency_issues());
        }
    }
    // File-level inconsistent lock ordering facts
    individual.extend(
        analysis
            .data_flows()
            .iter()
            .filter(|f| f.kind == DataFlowKind::InconsistentLockOrder)
            .cloned(),
    );

    // Compare by DataFlowKind counts
    let batched_counts = count_by_kind(batched);
    let individual_counts = count_by_kind(&individual);

    for (kind_label, count) in &batched_counts {
        let ind_count = individual_counts.get(kind_label).copied().unwrap_or(0);
        assert_eq!(
            *count, ind_count,
            "kind {kind_label}: batched={count}, individual={ind_count}"
        );
    }
    for (kind_label, count) in &individual_counts {
        let bat_count = batched_counts.get(kind_label).copied().unwrap_or(0);
        assert_eq!(
            *count, bat_count,
            "kind {kind_label}: individual={count}, batched={bat_count}"
        );
    }
}

// --- Semantic file analysis cache (Step 1) ---

/// T1: Multiple queries on the same file through analyze_file reuse the cached analysis.
#[test]
fn test_semantic_multiple_queries_reuse_cached_file_analysis() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis1 = ctx.analyze_file(&file);
    assert!(analysis1.is_some(), "analyze_file should return Some");

    let analysis2 = ctx.analyze_file(&file);
    assert!(analysis2.is_some(), "second call should also return Some");

    assert_eq!(
        ctx.file_setup_count(),
        1,
        "file should be parsed exactly once across multiple analyze_file calls"
    );
}

/// T2: Queries through the SemanticFileAnalysis object match existing behavior.
#[test]
fn test_semantic_file_analysis_public_queries_match_existing_behavior() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // Call graph: (run, fetch) edge should be present
    let has_run_fetch = analysis
        .call_graph()
        .iter()
        .any(|(caller, callee)| &**caller == "run" && &**callee == "fetch");
    assert!(
        has_run_fetch,
        "call graph should contain (run, fetch) edge, got: {:?}",
        analysis.call_graph()
    );

    // Reachability: pub fn at line 20 reachable, private fn at line 25 not
    assert!(
        analysis.is_line_reachable(20),
        "pub fn reachable_network should be reachable"
    );
    assert!(
        !analysis.is_line_reachable(25),
        "private fn unreachable_private should not be reachable"
    );

    // Data flows: EnvAccess→Network taint flow should be present
    let has_taint = analysis.data_flows().iter().any(|f| {
        f.source_capability == Some(pedant_types::Capability::EnvAccess)
            && f.sink_capability == Some(pedant_types::Capability::Network)
    });
    assert!(
        has_taint,
        "should contain EnvAccess→Network taint flow, got: {:?}",
        analysis.data_flows()
    );
}

fn count_by_kind(facts: &[ir::DataFlowFact]) -> std::collections::BTreeMap<Box<str>, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for fact in facts {
        *counts
            .entry(format!("{:?}", fact.kind).into_boxed_str())
            .or_insert(0) += 1;
    }
    counts
}

// --- Semantic file analysis cache (Step 3): FunctionAnalysisSummary ---

/// 3.T1: Quality, perf, and concurrency queries through the file-analysis
/// path preserve the same findings as the flat data_flows() output.
#[test]
fn test_quality_perf_concurrency_queries_preserve_existing_findings() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // Per-function queries through FunctionAnalysisSummary
    let dead_store_summary = analysis
        .function("dead_store")
        .expect("should find dead_store function");
    assert!(
        dead_store_summary
            .quality_issues()
            .iter()
            .any(|f| f.kind == DataFlowKind::DeadStore),
        "dead_store function should produce DeadStore finding via summary"
    );

    let repeated_summary = analysis
        .function("repeated_call_same_args")
        .expect("should find repeated_call_same_args function");
    assert!(
        repeated_summary
            .performance_issues()
            .iter()
            .any(|f| f.kind == DataFlowKind::RepeatedCall),
        "repeated_call_same_args should produce RepeatedCall finding via summary"
    );

    let spawn_summary = analysis
        .function("unobserved_thread_spawn")
        .expect("should find unobserved_thread_spawn function");
    assert!(
        spawn_summary
            .concurrency_issues()
            .iter()
            .any(|f| f.kind == DataFlowKind::UnobservedSpawn),
        "unobserved_thread_spawn should produce UnobservedSpawn finding via summary"
    );
}

/// 3.T2: Call graph and batch reachability queries reuse cached state —
/// file setup counter does not grow after the initial analysis.
#[test]
fn test_call_graph_and_reachability_reuse_cached_state() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let count_after_first = ctx.file_setup_count();

    // Repeated queries on the cached analysis should not trigger file setup
    let _edges = analysis.call_graph();
    let _reachable = analysis.is_line_reachable(20);
    let _batch = analysis.check_reachability_batch(&[20, 25]);

    // Second analyze_file call should hit cache
    let _analysis2 = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let count_after_all = ctx.file_setup_count();

    assert_eq!(
        count_after_first, count_after_all,
        "repeated queries and analyze_file calls should not trigger additional file setup"
    );
}

/// 3.T3: Batch reachability answers match the existing per-line behavior.
#[test]
fn test_batch_reachability_answers_match_existing_public_behavior() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    let lines = [20, 25, 1, 999];
    let batch = analysis.check_reachability_batch(&lines);

    for (i, &line) in lines.iter().enumerate() {
        assert_eq!(
            batch[i],
            analysis.is_line_reachable(line),
            "batch reachability at line {line} should match individual check"
        );
    }

    // Line 20 (pub fn reachable_network) should be reachable
    assert!(batch[0], "line 20 should be reachable");
    // Line 25 (private unreachable_private) should not
    assert!(!batch[1], "line 25 should not be reachable");
}

/// 3.T4: data_flows() includes taint, quality, perf, and concurrency findings
/// from a single cached file-analysis path.
#[test]
fn test_taint_quality_perf_and_concurrency_flows_share_one_file_analysis() {
    let root = dataflow_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    let flows = analysis.data_flows();

    let has_taint = flows.iter().any(|f| f.kind == DataFlowKind::TaintFlow);
    let has_quality = flows.iter().any(|f| {
        matches!(
            f.kind,
            DataFlowKind::DeadStore | DataFlowKind::DiscardedResult
        )
    });
    let has_perf = flows.iter().any(|f| {
        matches!(
            f.kind,
            DataFlowKind::RepeatedCall | DataFlowKind::UnnecessaryClone
        )
    });
    let has_concurrency = flows.iter().any(|f| {
        matches!(
            f.kind,
            DataFlowKind::UnobservedSpawn | DataFlowKind::LockAcrossAwait
        )
    });

    assert!(has_taint, "data_flows should include taint findings");
    assert!(has_quality, "data_flows should include quality findings");
    assert!(has_perf, "data_flows should include performance findings");
    assert!(
        has_concurrency,
        "data_flows should include concurrency findings"
    );

    // All flows should be reachable through the same file analysis
    assert_eq!(
        ctx.file_setup_count(),
        1,
        "all domain findings should come from a single file analysis"
    );
}
