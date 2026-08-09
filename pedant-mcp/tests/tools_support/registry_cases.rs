//! The registered tool set: its members, their uniqueness, and the one registry
//! both the schema list and the dispatcher read.

use pedant_mcp::registry;

use crate::tool_fixture::{fixture_index, result_text};

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
