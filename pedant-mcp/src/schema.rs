use std::borrow::Cow;
use std::sync::{Arc, LazyLock};

use rmcp::model::Tool;
use serde_json::{Map, Value, json};

/// Cached tool definitions, built once on first access.
static TOOLS: LazyLock<Box<[Tool]>> = LazyLock::new(|| {
    vec![
        query_capabilities_tool(),
        query_gate_verdicts_tool(),
        query_violations_tool(),
        search_by_capability_tool(),
        explain_finding_tool(),
        audit_crate_tool(),
        find_structural_duplicates_tool(),
    ]
    .into()
});

/// Return the static list of MCP tool definitions.
pub fn all_tools() -> &'static [Tool] {
    &TOOLS
}

fn query_capabilities_tool() -> Tool {
    tool(
        "query_capabilities",
        "List capability findings for a crate or file",
        json!({
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Crate name, file path, or 'workspace'"
                },
                "capability": {
                    "type": "string",
                    "description": "Filter by capability type (e.g., 'network', 'crypto')"
                },
                "build_script_only": {
                    "type": "boolean",
                    "default": false,
                    "description": "Only return build script findings"
                }
            },
            "required": ["scope"]
        }),
    )
}

fn query_gate_verdicts_tool() -> Tool {
    tool(
        "query_gate_verdicts",
        "Evaluate gate rule verdicts for a crate or workspace",
        json!({
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Crate name or 'workspace'"
                }
            },
            "required": ["scope"]
        }),
    )
}

fn query_violations_tool() -> Tool {
    tool(
        "query_violations",
        "List style violations for a crate or file",
        json!({
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Crate name, file path, or 'workspace'"
                },
                "check": {
                    "type": "string",
                    "description": "Filter by check code (e.g., 'max-depth') or check name (e.g., 'nesting')"
                }
            },
            "required": ["scope"]
        }),
    )
}

fn search_by_capability_tool() -> Tool {
    tool(
        "search_by_capability",
        "Find crates matching a capability pattern (e.g., 'network + crypto')",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Capability pattern: single capability or 'cap1 + cap2' for intersection"
                }
            },
            "required": ["pattern"]
        }),
    )
}

fn explain_finding_tool() -> Tool {
    tool(
        "explain_finding",
        "Get detailed rationale for a violation check",
        json!({
            "type": "object",
            "properties": {
                "check_name": {
                    "type": "string",
                    "description": "Check code (e.g., 'max-depth', 'clone-in-loop')"
                }
            },
            "required": ["check_name"]
        }),
    )
}

fn audit_crate_tool() -> Tool {
    tool(
        "audit_crate",
        "Full security audit: capabilities, gate verdicts, violations, and analysis tier",
        json!({
            "type": "object",
            "properties": {
                "crate_name": {
                    "type": "string",
                    "description": "Name of the crate to audit"
                }
            },
            "required": ["crate_name"]
        }),
    )
}

fn find_structural_duplicates_tool() -> Tool {
    tool(
        "find_structural_duplicates",
        "Find structurally duplicated functions across files in a crate or workspace",
        json!({
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Crate name or 'workspace'"
                },
                "min_fact_count": {
                    "type": "integer",
                    "default": 3,
                    "description": "Minimum fact count to include a function (filters trivial getters)"
                }
            },
            "required": ["scope"]
        }),
    )
}

fn tool(name: &'static str, description: &'static str, schema: Value) -> Tool {
    let input_schema = match schema {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    let mut t = Tool::default();
    t.name = Cow::Borrowed(name);
    t.description = Some(Cow::Borrowed(description));
    t.input_schema = Arc::new(input_schema);
    t
}
