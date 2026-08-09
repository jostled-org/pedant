//! What the tools report for non-Rust sources: the language tag, the mixed
//! audit, the language filter, and manifest hooks with their execution context.

use pedant_mcp::tools::{
    AuditCrateParams, QueryCapabilitiesParams, SearchByCapabilityParams, audit_crate,
    query_capabilities, search_by_capability,
};
use serde_json::Value;

use crate::tool_fixture::{fixture_index, is_error, result_text};

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

    // All returned findings should be Python. A result object carrying an empty
    // findings array would judge nothing, so the count is asserted too: the
    // filter must return findings, not just crates.
    let mut judged = 0_usize;
    for result_obj in &results {
        let findings = result_obj["findings"].as_array().unwrap();
        for f in findings {
            assert_eq!(
                f["language"].as_str(),
                Some("python"),
                "expected only Python findings with language filter: {text}"
            );
            judged += 1;
        }
    }
    assert!(
        judged > 0,
        "expected at least one Python finding to judge: {text}"
    );

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
