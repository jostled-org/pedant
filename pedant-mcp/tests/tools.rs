use std::path::Path;

use pedant_core::Config;
use pedant_mcp::index::WorkspaceIndex;
use pedant_mcp::registry;
use pedant_mcp::tools::{
    AuditCrateParams, ExplainFindingParams, FindStructuralDuplicatesParams,
    QueryCapabilitiesParams, QueryGateVerdictsParams, QueryViolationsParams,
    SearchByCapabilityParams, audit_crate, explain_finding, find_structural_duplicates,
    query_capabilities, query_gate_verdicts, query_violations, search_by_capability,
};
use serde_json::Value;

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

// ---------------------------------------------------------------------------
// 2.T7: explain_finding
// ---------------------------------------------------------------------------

#[test]
fn test_explain_finding_check() {
    let result = explain_finding(ExplainFindingParams {
        code: "max-depth".into(),
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

#[test]
fn test_explain_finding_schema_uses_code() {
    let tool = registry::all_tools()
        .iter()
        .find(|tool| tool.name == "explain_finding")
        .expect("missing explain_finding tool");

    let required = tool.input_schema["required"]
        .as_array()
        .expect("required must be an array");
    assert!(required.iter().any(|value| value == "code"));
    assert!(tool.input_schema["properties"]["code"].is_object());
    assert!(tool.input_schema["properties"]["check_name"].is_null());
}

#[test]
fn test_explain_finding_dispatch_accepts_code() {
    let index = fixture_index();
    let arguments = serde_json::from_value::<serde_json::Map<String, Value>>(serde_json::json!({
        "code": "max-depth"
    }))
    .expect("arguments should deserialize");

    let result = registry::dispatch("explain_finding", Some(&arguments), &index);

    assert!(!is_error(&result));
    let text = result_text(&result);
    assert!(
        text.contains("problem"),
        "expected rationale output: {text}"
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
    let config = Config::default();
    let semantic = pedant_core::SemanticContext::load(&root);
    let index = WorkspaceIndex::build(&root, &config, semantic).unwrap();

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

// ---------------------------------------------------------------------------
// 2.T9: tools list contains all security tools
// ---------------------------------------------------------------------------

#[test]
fn test_tools_list_contains_all_security_tools() {
    let tools = registry::all_tools();
    assert!(
        tools.len() >= 6,
        "expected at least 6 tools, found {}",
        tools.len()
    );

    let names: Box<[&str]> = tools
        .iter()
        .map(|t| t.name.as_ref())
        .collect::<Vec<_>>()
        .into_boxed_slice();
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

// ---------------------------------------------------------------------------
// Duplicate detection helpers
// ---------------------------------------------------------------------------

fn group_fn_names<'a>(group: &'a serde_json::Value) -> Box<[&'a str]> {
    group["functions"]
        .as_array()
        .map(|fns| {
            fns.iter()
                .filter_map(|f| f["name"].as_str())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 5.T1: find_structural_duplicates exact match
// ---------------------------------------------------------------------------

#[test]
fn test_find_structural_duplicates_exact_match() {
    let index = fixture_index();
    let result = find_structural_duplicates(
        FindStructuralDuplicatesParams {
            scope: "lib-a".into(),
            min_fact_count: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let groups: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

    // Should find a group containing process_items and process_widgets
    let has_exact_pair = groups.iter().any(|g| {
        let names = group_fn_names(g);
        names.iter().any(|n| *n == "process_items") && names.iter().any(|n| *n == "process_widgets")
    });
    assert!(
        has_exact_pair,
        "expected exact duplicate group with process_items and process_widgets: {text}"
    );
}

// ---------------------------------------------------------------------------
// 5.T2: find_structural_duplicates parametric match
// ---------------------------------------------------------------------------

#[test]
fn test_find_structural_duplicates_parametric_match() {
    let index = fixture_index();
    let result = find_structural_duplicates(
        FindStructuralDuplicatesParams {
            scope: "workspace".into(),
            min_fact_count: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let groups: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

    // Should find a skeleton group containing all three: process_items, process_widgets, handle_items
    let has_skeleton_group = groups.iter().any(|g| {
        let names = group_fn_names(g);
        names.iter().any(|n| *n == "process_items")
            && names.iter().any(|n| *n == "process_widgets")
            && names.iter().any(|n| *n == "handle_items")
    });
    assert!(
        has_skeleton_group,
        "expected skeleton group with all three duplicate functions: {text}"
    );

    // handle_items should have a different exact_hash than process_items
    let skeleton_group = groups
        .iter()
        .find(|g| group_fn_names(g).iter().any(|n| *n == "handle_items"))
        .expect("expected group containing handle_items");

    let exact_subgroups = skeleton_group["exact_subgroups"]
        .as_array()
        .expect("expected exact_subgroups array");
    assert!(
        exact_subgroups.len() >= 2,
        "expected at least 2 exact subgroups (parametric match): {text}"
    );
}

// ---------------------------------------------------------------------------
// 5.T3: find_structural_duplicates filters trivial
// ---------------------------------------------------------------------------

#[test]
fn test_find_structural_duplicates_filters_trivial() {
    let index = fixture_index();
    let result = find_structural_duplicates(
        FindStructuralDuplicatesParams {
            scope: "lib-a".into(),
            min_fact_count: None,
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let groups: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

    // get_name is a trivial getter — should not appear in any group
    let has_trivial = groups
        .iter()
        .any(|g| group_fn_names(g).iter().any(|n| *n == "get_name"));
    assert!(
        !has_trivial,
        "trivial getter get_name should be filtered out: {text}"
    );
}

// ---------------------------------------------------------------------------
// 5.T4: find_structural_duplicates unknown scope
// ---------------------------------------------------------------------------

#[test]
fn test_find_structural_duplicates_unknown_scope() {
    let index = fixture_index();
    let result = find_structural_duplicates(
        FindStructuralDuplicatesParams {
            scope: "nonexistent".into(),
            min_fact_count: None,
        },
        &index,
    );

    assert!(
        is_error(&result),
        "expected error for unknown scope, got: {}",
        result_text(&result)
    );
}

// ---------------------------------------------------------------------------
// 3.T1: all registered tools are dispatchable
// ---------------------------------------------------------------------------

#[test]
fn test_all_registered_tools_are_dispatchable() {
    use pedant_mcp::registry;

    let index = fixture_index();
    let tool_names: Box<[&str]> = registry::all_tools()
        .iter()
        .map(|t| t.name.as_ref())
        .collect::<Vec<_>>()
        .into_boxed_slice();

    for name in &tool_names {
        // Every tool in the schema must route through dispatch without
        // returning "unknown tool".
        let result = registry::dispatch(name, None, &index);
        let text = result_text(&result);
        assert!(
            !text.contains("unknown tool"),
            "tool '{name}' listed in schema but not dispatchable"
        );
    }
}

// ---------------------------------------------------------------------------
// 3.T2: duplicate tool name rejected
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_tool_name_rejected() {
    use pedant_mcp::registry;
    use std::collections::HashSet;

    let tools = registry::all_tools();
    let mut seen = HashSet::new();
    for tool in tools.iter() {
        assert!(
            seen.insert(tool.name.as_ref()),
            "duplicate tool name: {}",
            tool.name
        );
    }
}

// ---------------------------------------------------------------------------
// 3.T3: schema and dispatch share same registry
// ---------------------------------------------------------------------------

#[test]
fn test_schema_and_dispatch_share_same_registry() {
    use pedant_mcp::registry;

    let schema_names: Box<[&str]> = registry::all_tools()
        .iter()
        .map(|t| t.name.as_ref())
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let dispatch_names = registry::dispatchable_names();

    assert_eq!(
        schema_names.len(),
        dispatch_names.len(),
        "schema tool count ({}) != dispatch tool count ({})",
        schema_names.len(),
        dispatch_names.len()
    );

    for name in &schema_names {
        assert!(
            dispatch_names.contains(name),
            "tool '{name}' in schema but not in dispatch"
        );
    }

    for name in &dispatch_names {
        assert!(
            schema_names.contains(name),
            "tool '{name}' in dispatch but not in schema"
        );
    }
}

// ---------------------------------------------------------------------------
// 6.T1: query_capabilities includes language field for non-Rust findings
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_query_capabilities_includes_language() {
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
    let findings: Vec<Value> = serde_json::from_str(&text).unwrap();

    // lib-a has scripts/fetch_data.py with `import requests` → network finding
    let python_findings: Box<[_]> = findings
        .iter()
        .filter(|f| f["language"].as_str() == Some("python"))
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        !python_findings.is_empty(),
        "expected Python-language findings in lib-a: {text}"
    );
}

// ---------------------------------------------------------------------------
// 6.T2: audit_crate includes findings from both Rust and non-Rust sources
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_audit_crate_multi_language() {
    let index = fixture_index();
    let result = audit_crate(
        AuditCrateParams {
            scope: "lib-a".into(),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let audit: Value = serde_json::from_str(&text).unwrap();
    let capabilities = audit["capabilities"]
        .as_array()
        .expect("expected capabilities array");

    // Should have both Rust findings (no language field) and Python findings
    let has_rust = capabilities
        .iter()
        .any(|f| f.get("language").is_none() || f["language"].is_null());
    let has_python = capabilities
        .iter()
        .any(|f| f["language"].as_str() == Some("python"));
    assert!(has_rust, "expected Rust findings in audit: {text}");
    assert!(has_python, "expected Python findings in audit: {text}");
}

// ---------------------------------------------------------------------------
// 6.T3: search_by_capability with language filter
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_search_by_capability_language_filter() {
    let index = fixture_index();

    // Search for network with language filter "python"
    let result = search_by_capability(
        SearchByCapabilityParams {
            pattern: "network".into(),
            language: Some("python".into()),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let results: Vec<Value> = serde_json::from_str(&text).unwrap();

    // lib-a has Python network findings (fetch_data.py)
    let lib_a = results.iter().find(|r| r["crate_name"] == "lib-a");
    assert!(
        lib_a.is_some(),
        "expected lib-a in Python network search: {text}"
    );

    // All returned findings should be Python
    for result_obj in &results {
        let findings = result_obj["findings"].as_array().unwrap();
        for f in findings {
            assert_eq!(
                f["language"].as_str(),
                Some("python"),
                "expected only Python findings with language filter: {text}"
            );
        }
    }

    // lib-c has Rust network findings but no Python → should not appear
    let lib_c = results.iter().find(|r| r["crate_name"] == "lib-c");
    assert!(
        lib_c.is_none(),
        "lib-c has no Python network findings, should not appear: {text}"
    );
}

// ---------------------------------------------------------------------------
// 6.T4: manifest/hook findings are indexed with execution context
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_manifest_hook_findings_indexed() {
    let index = fixture_index();
    let result = query_capabilities(
        QueryCapabilitiesParams {
            scope: "lib-a".into(),
            capability: None,
            execution_context: Some("install_hook".into()),
        },
        &index,
    );

    assert!(!is_error(&result));
    let text = result_text(&result);
    let findings: Vec<Value> = serde_json::from_str(&text).unwrap();

    // lib-a/package.json has a postinstall hook → install_hook context
    assert!(
        !findings.is_empty(),
        "expected install_hook findings from package.json: {text}"
    );

    let has_postinstall = findings
        .iter()
        .any(|f| f["evidence"].as_str() == Some("postinstall"));
    assert!(
        has_postinstall,
        "expected postinstall evidence in hook findings: {text}"
    );
}
