//! What `audit_crate` reports, including the flow arrays it carries.

#[cfg(feature = "semantic")]
use std::path::Path;

#[cfg(feature = "semantic")]
use pedant_mcp::index::WorkspaceIndex;
use pedant_mcp::tools::{AuditCrateParams, audit_crate};

use crate::tool_fixture::{fixture_index, is_error, result_text};

// ---------------------------------------------------------------------------
// 2.T8: audit_crate
// ---------------------------------------------------------------------------

#[test]
fn test_audit_crate() {
    let index = fixture_index();
    let result = audit_crate(
        AuditCrateParams {
            scope: "lib-a".into(),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let audit: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        audit.get("capabilities").is_some(),
        "expected capabilities in audit: {text}"
    );
    assert!(
        audit.get("gate_verdicts").is_some(),
        "expected gate_verdicts in audit: {text}"
    );
    assert!(
        audit.get("tier").is_some(),
        "expected tier in audit: {text}"
    );
    assert_eq!(audit["tier"], "syntactic");
}

// ---------------------------------------------------------------------------
// 7.T3: audit_crate response includes data_flows array
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_audit_crate_includes_data_flows() {
    let index = fixture_index();
    let result = audit_crate(
        AuditCrateParams {
            scope: "lib-a".into(),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let audit: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        audit.get("data_flows").is_some(),
        "expected data_flows field in audit output: {text}"
    );
    // Without semantic analysis, data_flows should be an empty array.
    let flows = audit["data_flows"].as_array().unwrap();
    assert!(
        flows.is_empty(),
        "expected empty data_flows without semantic analysis: {text}"
    );
}

// ---------------------------------------------------------------------------
// 5.T2: audit_crate includes quality DataFlowFacts when semantic analysis is active
// ---------------------------------------------------------------------------

#[cfg(feature = "semantic")]
#[test]
fn test_mcp_audit_includes_quality_flows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("pedant-core/tests/fixtures/dataflow_workspace");
    let semantic = pedant_core::SemanticContext::load(&root);
    let index = WorkspaceIndex::build(&root, semantic).unwrap();

    let result = audit_crate(
        AuditCrateParams {
            scope: "dataflow-fixture".into(),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let audit: serde_json::Value = serde_json::from_str(&text).unwrap();
    let flows = audit["data_flows"]
        .as_array()
        .expect("expected data_flows array");

    // With semantic analysis, quality data flow facts should be present.
    let quality_kinds = ["dead-store", "discarded-result", "partial-error-handling"];
    let has_quality = flows.iter().any(|f| {
        f["kind"]
            .as_str()
            .is_some_and(|k| quality_kinds.contains(&k))
    });
    assert!(
        has_quality,
        "expected quality data flow facts in audit output, got flows: {flows:?}"
    );
}
