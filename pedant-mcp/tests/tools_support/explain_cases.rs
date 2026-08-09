//! What `explain_finding` answers, and the parameter name its schema states.

use pedant_mcp::registry;
use pedant_mcp::tools::{ExplainFindingParams, explain_finding};
use serde_json::Value;

use crate::tool_fixture::{fixture_index, is_error, result_text};

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
