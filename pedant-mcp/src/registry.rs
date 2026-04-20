//! Single source of truth for MCP tool definitions and dispatch.
//!
//! Each tool is registered once via `ToolEntry`. The registry drives both
//! `all_tools` (schema generation) and `dispatch` (call routing), so tool
//! names, descriptions, schemas, and handlers cannot drift.

use std::borrow::Cow;
use std::sync::{Arc, LazyLock};

use rmcp::model::{CallToolResult, Tool};
use serde_json::{Map, Value, json};

use crate::index::WorkspaceIndex;
use crate::tools::{
    self, AuditCrateParams, ExplainFindingParams, FindStructuralDuplicatesParams,
    QueryCapabilitiesParams, QueryGateVerdictsParams, QueryViolationsParams,
    SearchByCapabilityParams, audit_crate, explain_finding, find_structural_duplicates,
    query_capabilities, query_gate_verdicts, query_violations, search_by_capability,
};

/// A single tool registration binding name, schema, and handler.
struct ToolEntry {
    name: &'static str,
    description: &'static str,
    schema: fn() -> Value,
    handler: fn(&Map<String, Value>, &WorkspaceIndex) -> CallToolResult,
}

/// Empty map used as default when no arguments are provided.
static EMPTY_ARGS: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

/// The authoritative tool registry. Every entry here appears in both
/// `list_tools` and `call_tool` dispatch.
static ENTRIES: &[ToolEntry] = &[
    ToolEntry {
        name: "query_capabilities",
        description: "List capability findings (Rust, Python, JS/TS, Go, Bash) for a crate or file",
        schema: query_capabilities_schema,
        handler: |args, idx| {
            call_with(args, |p: QueryCapabilitiesParams| {
                query_capabilities(p, idx)
            })
        },
    },
    ToolEntry {
        name: "query_gate_verdicts",
        description: "Evaluate gate rule verdicts for a crate or workspace",
        schema: query_gate_verdicts_schema,
        handler: |args, idx| {
            call_with(args, |p: QueryGateVerdictsParams| {
                query_gate_verdicts(p, idx)
            })
        },
    },
    ToolEntry {
        name: "query_violations",
        description: "List style violations for a crate or file",
        schema: query_violations_schema,
        handler: |args, idx| call_with(args, |p: QueryViolationsParams| query_violations(p, idx)),
    },
    ToolEntry {
        name: "search_by_capability",
        description: "Find crates matching a capability pattern, optionally filtered by language",
        schema: search_by_capability_schema,
        handler: |args, idx| {
            call_with(args, |p: SearchByCapabilityParams| {
                search_by_capability(p, idx)
            })
        },
    },
    ToolEntry {
        name: "explain_finding",
        description: "Get detailed rationale for a violation check",
        schema: explain_finding_schema,
        handler: |args, _idx| call_with(args, |p: ExplainFindingParams| explain_finding(p)),
    },
    ToolEntry {
        name: "audit_crate",
        description: "Full security audit across all languages: capabilities, gate verdicts, violations, and analysis tier",
        schema: audit_crate_schema,
        handler: |args, idx| call_with(args, |p: AuditCrateParams| audit_crate(p, idx)),
    },
    ToolEntry {
        name: "find_structural_duplicates",
        description: "Find structurally duplicated functions across files in a crate or workspace",
        schema: find_structural_duplicates_schema,
        handler: |args, idx| {
            call_with(args, |p: FindStructuralDuplicatesParams| {
                find_structural_duplicates(p, idx)
            })
        },
    },
];

/// Cached `Tool` objects derived from [`ENTRIES`], built once on first access.
static TOOLS: LazyLock<Box<[Tool]>> = LazyLock::new(|| {
    ENTRIES
        .iter()
        .map(|e| {
            let input_schema = match (e.schema)() {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            let mut t = Tool::default();
            t.name = Cow::Borrowed(e.name);
            t.description = Some(Cow::Borrowed(e.description));
            t.input_schema = Arc::new(input_schema);
            t
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
});

/// Return the static list of MCP tool definitions.
pub fn all_tools() -> &'static [Tool] {
    &TOOLS
}

/// Return the set of tool names that are dispatchable.
pub fn dispatchable_names() -> Box<[&'static str]> {
    ENTRIES
        .iter()
        .map(|e| e.name)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Route a tool call by name to the appropriate handler.
pub fn dispatch(
    name: &str,
    arguments: Option<&Map<String, Value>>,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let args = arguments.unwrap_or(&EMPTY_ARGS);
    match ENTRIES.iter().find(|e| e.name == name) {
        Some(entry) => (entry.handler)(args, index),
        None => tools::error_result(format!("unknown tool: {name}")),
    }
}

// ---------------------------------------------------------------------------
// Schema builders (one per tool)
// ---------------------------------------------------------------------------

fn query_capabilities_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "description": "Crate name, file path, or 'workspace'. Includes findings from all languages (Rust, Python, JS/TS, Go, Bash)"
            },
            "capability": {
                "type": "string",
                "description": "Filter by capability type (e.g., 'network', 'crypto')"
            },
            "execution_context": {
                "type": "string",
                "enum": ["runtime", "build_hook", "install_hook", "generator"],
                "description": "Filter by execution context"
            }
        },
        "required": ["scope"]
    })
}

fn query_gate_verdicts_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "description": "Crate name or 'workspace'"
            }
        },
        "required": ["scope"]
    })
}

fn query_violations_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "description": "Crate name, file path, or 'workspace'"
            },
            "check": {
                "type": "string",
                "description": "Filter by check code (e.g., 'max-depth')"
            },
            "category": {
                "type": "string",
                "description": "Filter by check category (e.g., 'nesting')"
            }
        },
        "required": ["scope"]
    })
}

fn search_by_capability_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "pattern": {
                "type": "string",
                "description": "Capability pattern: single capability or 'cap1 + cap2' for intersection"
            },
            "language": {
                "type": "string",
                "enum": ["python", "javascript", "typescript", "go", "bash"],
                "description": "Restrict results to findings from a specific language"
            }
        },
        "required": ["pattern"]
    })
}

fn explain_finding_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "Check code (e.g., 'max-depth', 'clone-in-loop')"
            }
        },
        "required": ["code"]
    })
}

fn audit_crate_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "scope": {
                "type": "string",
                "description": "Name of the crate to audit"
            }
        },
        "required": ["scope"]
    })
}

fn find_structural_duplicates_schema() -> Value {
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
    })
}

/// Deserialize arguments then invoke the handler. Returns an error result on bad params.
fn call_with<P, F>(tool_args: &Map<String, Value>, handler: F) -> CallToolResult
where
    P: serde::de::DeserializeOwned,
    F: FnOnce(P) -> CallToolResult,
{
    let wrapped = Value::Object(tool_args.clone());
    match serde_json::from_value::<P>(wrapped) {
        Ok(params) => handler(params),
        Err(e) => tools::error_result(format!("invalid parameters: {e}")),
    }
}
