//! The per-file semantic cache: reuse across queries, and batched answers that
//! agree with individual ones.
use pedant_core::SemanticFileAnalysis;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::ir::DataFlowKind;
use pedant_core::lint::analyze;

use crate::fixtures::{
    count_by_kind, dataflow_lib_path, dataflow_source, dataflow_workspace_root, fixture_lib_path,
    fixture_workspace_root,
};

// --- Cache: multiple queries reuse cached file state (T2) ---

/// T2: Multiple semantic queries on the same file should reuse cached
/// file-level analysis (call graph, function entries, reachable set)
/// instead of rebuilding from scratch.
#[test]
fn test_semantic_multiple_queries_reuse_cached_file_state() {
    let root = dataflow_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
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

#[test]
fn test_semantic_cache_uses_canonical_file_identity() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let canonical = fixture_lib_path();
    let lexical_alias = root
        .join("src")
        .join("..")
        .join("src")
        .join("lib.rs")
        .to_str()
        .expect("fixture path should be UTF-8")
        .to_owned();

    let first = ctx
        .analyze_file(&canonical)
        .expect("canonical file should analyze");
    let count_after_first = ctx.file_setup_count();
    let second = ctx
        .analyze_file(&lexical_alias)
        .expect("a lexical alias of the same file should analyze");

    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "one physical file should have one cached semantic analysis"
    );
    assert_eq!(
        count_after_first,
        ctx.file_setup_count(),
        "the lexical alias should not perform another file setup"
    );
}

// --- Cache: batched and individual queries agree (T3) ---

/// T3: The batched data-flow enrichment (via analyze()) should produce
/// the same findings as the union of individual per-function queries.
#[test]
fn test_enrich_all_data_flows_and_individual_queries_agree() {
    let root = dataflow_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let batched = analyze(&file_path, &source, &config, Some(&ctx))
        .expect("the dataflow fixture should analyze")
        .data_flows;
    let analysis = ctx
        .analyze_file(&dataflow_lib_path())
        .expect("should produce file analysis");
    let individual = per_function_facts(&analysis);

    assert_same_kind_counts(&batched, &individual);
}

/// Every fact the per-function queries report, in the order they report it.
///
/// Inconsistent lock ordering is a file-level fact rather than a function's, so
/// it comes from the analysis itself; leaving it out would make the batched
/// result look larger than the individual one for a reason that is not a defect.
fn per_function_facts(analysis: &SemanticFileAnalysis) -> Vec<ir::DataFlowFact> {
    let mut facts: Vec<ir::DataFlowFact> = Vec::new();
    for summary in DATAFLOW_FUNCTIONS
        .iter()
        .filter_map(|it| analysis.function(it))
    {
        facts.extend_from_slice(summary.taint_flows());
        facts.extend_from_slice(summary.quality_issues());
        facts.extend_from_slice(summary.performance_issues());
        facts.extend_from_slice(summary.concurrency_issues());
    }
    facts.extend(
        analysis
            .data_flows()
            .iter()
            .filter(|fact| fact.kind == DataFlowKind::InconsistentLockOrder)
            .cloned(),
    );
    facts
}

/// The two routes agree kind for kind, in both directions.
///
/// One direction alone would pass a route that reported a strict subset.
fn assert_same_kind_counts(batched: &[ir::DataFlowFact], individual: &[ir::DataFlowFact]) {
    let batched_counts = count_by_kind(batched);
    let individual_counts = count_by_kind(individual);
    assert_eq!(
        batched_counts, individual_counts,
        "the batched and per-function routes report different fact kinds"
    );
}

/// Every function the dataflow fixture declares.
///
/// Written down rather than taken from the analysis: a list derived from the
/// run would shrink with it, and the comparison would still pass.
const DATAFLOW_FUNCTIONS: &[&str] = &[
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

/// T1: Multiple queries on the same file through analyze_file reuse the cached analysis.
#[test]
fn test_semantic_multiple_queries_reuse_cached_file_analysis() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file = dataflow_lib_path();
    let count_before = ctx.file_setup_count();

    let analysis1 = ctx.analyze_file(&file);
    assert!(analysis1.is_some(), "analyze_file should return Some");
    let count_after_first = ctx.file_setup_count();

    let analysis2 = ctx.analyze_file(&file);
    assert!(analysis2.is_some(), "second call should also return Some");
    let count_after_second = ctx.file_setup_count();

    assert!(
        count_after_first <= count_before + 1,
        "first call should perform at most one file setup"
    );
    assert_eq!(
        count_after_first, count_after_second,
        "second call should reuse the first call's cached analysis"
    );
}

// --- Semantic file analysis cache (Step 3): FunctionAnalysisSummary ---

/// 3.T1: Quality, perf, and concurrency queries through the file-analysis
/// path preserve the same findings as the flat data_flows() output.
#[test]
fn test_quality_perf_concurrency_queries_preserve_existing_findings() {
    let root = dataflow_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
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

/// 3.T3: Batch reachability answers match the existing per-line behavior.
#[test]
fn test_batch_reachability_answers_match_existing_public_behavior() {
    let root = dataflow_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
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
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file = dataflow_lib_path();
    let count_before = ctx.file_setup_count();

    let analysis = ctx
        .analyze_file(&file)
        .expect("should produce file analysis");
    let count_after = ctx.file_setup_count();

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

    assert!(
        count_after <= count_before + 1,
        "all domain findings should require at most one file setup"
    );
}
