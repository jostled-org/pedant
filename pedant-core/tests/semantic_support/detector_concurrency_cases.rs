//! Concurrency detectors: locks held across an await, inconsistent lock
//! ordering, and unobserved spawns.
use pedant_core::ir::DataFlowKind;

use crate::fixtures::{IssueCategory, assert_function_issue_count, dataflow_file_analysis};

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
