use std::path::Path;

use pedant_core::Config;
use pedant_mcp::index::WorkspaceIndex;
use pedant_mcp::schema::all_tools;
use pedant_mcp::tools::{
    AuditCrateParams, ExplainFindingParams, QueryCapabilitiesParams, QueryGateVerdictsParams,
    QueryViolationsParams, SearchByCapabilityParams, audit_crate, explain_finding,
    query_capabilities, query_gate_verdicts, query_violations, search_by_capability,
};

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn fixture_index() -> WorkspaceIndex {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    WorkspaceIndex::build(&root, &config, None).unwrap()
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| match &c.raw {
            rmcp::model::RawContent::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn is_error(result: &rmcp::model::CallToolResult) -> bool {
    result.is_error == Some(true)
}

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
            build_script_only: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("network"),
        "expected network capability in response: {text}"
    );
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
            build_script_only: None,
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

// ---------------------------------------------------------------------------
// 2.T7: explain_finding
// ---------------------------------------------------------------------------

#[test]
fn test_explain_finding_check() {
    let result = explain_finding(ExplainFindingParams {
        check_name: "max-depth".into(),
    });

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("problem"),
        "expected rationale with problem field: {text}"
    );
    assert!(
        text.contains("fix"),
        "expected rationale with fix field: {text}"
    );
}

// ---------------------------------------------------------------------------
// 2.T8: audit_crate
// ---------------------------------------------------------------------------

#[test]
fn test_audit_crate() {
    let index = fixture_index();
    let result = audit_crate(
        AuditCrateParams {
            crate_name: "lib-a".into(),
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
}

// ---------------------------------------------------------------------------
// 7.T3: audit_crate response includes data_flows array
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_audit_crate_includes_data_flows() {
    let index = fixture_index();
    let result = audit_crate(
        AuditCrateParams {
            crate_name: "lib-a".into(),
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
// 2.T9: tools list contains all security tools
// ---------------------------------------------------------------------------

#[test]
fn test_tools_list_contains_all_security_tools() {
    let tools = all_tools();
    assert!(
        tools.len() >= 6,
        "expected at least 6 tools, found {}",
        tools.len()
    );

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for expected in [
        "query_capabilities",
        "query_gate_verdicts",
        "query_violations",
        "search_by_capability",
        "explain_finding",
        "audit_crate",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool: {expected}, found: {names:?}"
        );
    }

    for tool in tools.iter() {
        assert!(
            tool.description.is_some(),
            "tool {} missing description",
            tool.name
        );
        assert!(
            !tool.input_schema.is_empty(),
            "tool {} missing input schema",
            tool.name
        );
    }
}
