//! What the four query tools answer over the fixture workspace.

use pedant_mcp::tools::{
    QueryCapabilitiesParams, QueryGateVerdictsParams, QueryViolationsParams,
    SearchByCapabilityParams, query_capabilities, query_gate_verdicts, query_violations,
    search_by_capability,
};

use crate::tool_fixture::{fixture_index, is_error, result_text};

// ---------------------------------------------------------------------------
// 2.T1: query_capabilities returns findings
// ---------------------------------------------------------------------------

#[test]
fn test_query_capabilities_returns_findings() {
    let index = fixture_index();
    let result = query_capabilities(
        QueryCapabilitiesParams {
            scope: "lib-a".into(),
            capability: None,
            execution_context: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("network"),
        "expected network capability in response: {text}"
    );

    // The MCP index takes the flat projection from each analysis, so the
    // payload keeps its exact current shape and carries no symbol evidence.
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(&text).expect("the payload is a flat finding array");
    assert!(!findings.is_empty(), "expected findings: {text}");
    for finding in &findings {
        let fields: Vec<&str> = finding
            .as_object()
            .expect("each finding is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            !fields.contains(&"symbols") && !fields.contains(&"symbol_attribution"),
            "a capability finding must carry no symbol field: {fields:?}"
        );
    }
    for field in ["\"symbols\"", "\"symbol_attribution\""] {
        assert!(
            !text.contains(field),
            "the MCP capability payload must not carry {field}: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2.T2: query_capabilities filtered
// ---------------------------------------------------------------------------

#[test]
fn test_query_capabilities_filtered() {
    let index = fixture_index();
    let result = query_capabilities(
        QueryCapabilitiesParams {
            scope: "lib-a".into(),
            capability: Some("crypto".into()),
            execution_context: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let findings: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
    assert!(
        findings.is_empty(),
        "expected no crypto findings in lib-a: {text}"
    );
}

#[test]
fn test_query_capabilities_build_hook_filter() {
    let index = fixture_index();
    let result = query_capabilities(
        QueryCapabilitiesParams {
            scope: "lib-a".into(),
            capability: None,
            execution_context: Some("build_hook".into()),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("build_hook"),
        "expected build-hook findings: {text}"
    );
}

// ---------------------------------------------------------------------------
// 2.T3: query_gate_verdicts
// ---------------------------------------------------------------------------

#[test]
fn test_query_gate_verdicts() {
    let index = fixture_index();
    let result = query_gate_verdicts(
        QueryGateVerdictsParams {
            scope: "lib-a".into(),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("build-script-network"),
        "expected build-script-network verdict: {text}"
    );
}

// ---------------------------------------------------------------------------
// 2.T4: query_violations
// ---------------------------------------------------------------------------

#[test]
fn test_query_violations() {
    let index = fixture_index();
    let result = query_violations(
        QueryViolationsParams {
            scope: "lib-b".into(),
            check: None,
            category: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("max-depth") || text.contains("nesting"),
        "expected nesting violation in lib-b: {text}"
    );
}

// ---------------------------------------------------------------------------
// 2.T5: search_by_capability
// ---------------------------------------------------------------------------

#[test]
fn test_search_by_capability() {
    let index = fixture_index();
    let result = search_by_capability(
        SearchByCapabilityParams {
            pattern: "network".into(),
            language: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("lib-a"),
        "expected lib-a in network search results: {text}"
    );
    assert!(
        !text.contains("\"lib-b\""),
        "lib-b should not appear in network search results: {text}"
    );
}

// ---------------------------------------------------------------------------
// 2.T6: search_by_capability combination
// ---------------------------------------------------------------------------

#[test]
fn test_search_by_capability_combination() {
    let index = fixture_index();
    let result = search_by_capability(
        SearchByCapabilityParams {
            pattern: "network + crypto".into(),
            language: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("lib-c"),
        "expected lib-c in network+crypto search: {text}"
    );
}
