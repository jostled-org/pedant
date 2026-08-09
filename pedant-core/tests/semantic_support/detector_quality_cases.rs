//! Quality detectors over one file analysis: dead stores, discarded results,
//! partial error handling, immutable growables, and swallowed `.ok()`.
use pedant_core::ir::DataFlowKind;

use crate::fixtures::{IssueCategory, assert_function_issue_count, dataflow_file_analysis};

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
