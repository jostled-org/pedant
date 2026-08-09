//! Taint propagation and reachability from public entry points.

use crate::fixtures::{dataflow_lib_path, dataflow_workspace_root};

// --- Step 3 (DataFlow): Taint propagation ---

/// 3.T1: trace_taints detects env var flowing to network sink.
#[test]
fn test_trace_taints_env_to_network() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
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
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
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
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
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
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
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
