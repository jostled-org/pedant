#![cfg(feature = "semantic")]
#![cfg(feature = "checks")]

//! Semantic analysis: the workspace loader, the enrichment it feeds, the
//! detectors that read it, and the cache underneath all of them.
//!
//! This root carries the cases named by the resolution plan's owner-registration
//! inventory. Every other case is a `#[path]` support module beside it.
//!
//! The `#[path]` is required. Default resolution would place these files in
//! `tests/semantic/`, which pedant's `conflicting-module-root` rule rejects
//! beside `semantic.rs`, and its advice — fold the root into
//! `semantic/mod.rs` — does not apply to a cargo test root, since cargo builds
//! a test executable per `tests/*.rs` and would stop building this one. A
//! sibling directory satisfies both: cargo declares no target for it, because
//! it holds no `main.rs`.
use pedant_core::ir::DataFlowKind;

use crate::fixtures::{dataflow_lib_path, dataflow_workspace_root};

/// Serialization of rust-analyzer workspace construction.
#[path = "semantic_support/workspace_load.rs"]
mod workspace_load;

/// Shared and fresh semantic contexts used by the cases.
#[path = "semantic_support/semantic_context_fixture.rs"]
mod semantic_context_fixture;

/// Every workspace, source text, configuration, and shared assertion the
#[path = "semantic_support/fixtures.rs"]
mod fixtures;

/// Loading a workspace and answering type questions about it.
#[path = "semantic_support/context_cases.rs"]
mod context_cases;

/// What semantic enrichment adds to extraction, and what it leaves alone.
#[path = "semantic_support/extraction_cases.rs"]
mod extraction_cases;

/// Taint propagation and reachability from public entry points.
#[path = "semantic_support/flow_cases.rs"]
mod flow_cases;

/// `analyze` with a semantic context: aliases it resolves, data flows it
#[path = "semantic_support/analyze_cases.rs"]
mod analyze_cases;

/// Quality detectors over one file analysis: dead stores, discarded results,
#[path = "semantic_support/detector_quality_cases.rs"]
mod detector_quality_cases;

/// Performance detectors: repeated calls, unnecessary clones, allocation in a
#[path = "semantic_support/detector_performance_cases.rs"]
mod detector_performance_cases;

/// Concurrency detectors: locks held across an await, inconsistent lock
#[path = "semantic_support/detector_concurrency_cases.rs"]
mod detector_concurrency_cases;

/// The analysis tier a run reports, and what it requires to report it.
#[path = "semantic_support/tier_cases.rs"]
mod tier_cases;

/// The per-file semantic cache: reuse across queries, and batched answers that
#[path = "semantic_support/cache_cases.rs"]
mod cache_cases;

#[test]
fn test_dataflow_file_analysis_is_shared() {
    let first = crate::fixtures::dataflow_file_analysis();
    let second = crate::fixtures::dataflow_file_analysis();

    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "the shared fixture analysis should be constructed once"
    );
}

/// 2.T1: a direct call still reaches the callee, proved through the retained
/// public query.
///
/// `fetch` is private, so nothing but the `run` → `fetch` call pair can make its
/// line reachable. The name-only edge list is detector input, not a surface, so
/// reachability is where that pair is observable.
#[test]
fn test_call_graph_direct_call() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    assert!(
        analysis.is_line_reachable(5),
        "private fn fetch is reachable only through the run → fetch call"
    );
}

/// 2.T2: a function that calls nothing adds no reachability of its own.
#[test]
fn test_call_graph_no_calls() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    assert!(
        analysis.is_line_reachable(15),
        "pub fn no_calls is an entry point"
    );
    assert!(
        !analysis.is_line_reachable(25),
        "no_calls reaches nothing, so the private unreachable fn stays unreachable"
    );
}

// --- Cache: public queries match pre-cache behavior (T1) ---

/// T1: Run all public semantic queries on the dataflow fixture and verify
/// outputs match expected behavior. Guards against regressions when
/// introducing file-level analysis caching.
#[test]
fn test_semantic_public_queries_match_pre_cache_behavior() {
    let root = dataflow_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // reachability: the run→fetch call keeps the private callee reachable
    assert!(
        analysis.is_line_reachable(5),
        "the run → fetch call should keep private fn fetch reachable"
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

/// T2: Queries through the SemanticFileAnalysis object match existing behavior.
#[test]
fn test_semantic_file_analysis_public_queries_match_existing_behavior() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");

    // Reachability through the call pair: private fn fetch is reachable
    assert!(
        analysis.is_line_reachable(5),
        "the run → fetch call should keep private fn fetch reachable"
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

/// 3.T2: Call graph and batch reachability queries reuse cached state —
/// file setup counter does not grow after the initial analysis.
#[test]
fn test_call_graph_and_reachability_reuse_cached_state() {
    let root = dataflow_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file = dataflow_lib_path();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let count_after_first = ctx.file_setup_count();

    // Repeated queries on the cached analysis should not trigger file setup
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
