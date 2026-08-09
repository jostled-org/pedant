//! Performance detectors: repeated calls, unnecessary clones, allocation in a
//! loop, and redundant collects.
use pedant_core::ir::DataFlowKind;

use crate::fixtures::{IssueCategory, assert_function_issue_count, dataflow_file_analysis};

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
