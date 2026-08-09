//! What `find_structural_duplicates` groups, and what it declines to group.

use pedant_mcp::tools::{FindStructuralDuplicatesParams, find_structural_duplicates};

use crate::tool_fixture::{fixture_index, is_error, result_text};

// ---------------------------------------------------------------------------
// Duplicate detection helpers
// ---------------------------------------------------------------------------

fn group_fn_names(group: &serde_json::Value) -> Box<[&str]> {
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
        names.contains(&"process_items") && names.contains(&"process_widgets")
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
        names.contains(&"process_items")
            && names.contains(&"process_widgets")
            && names.contains(&"handle_items")
    });
    assert!(
        has_skeleton_group,
        "expected skeleton group with all three duplicate functions: {text}"
    );

    // handle_items should have a different exact_hash than process_items
    let skeleton_group = groups
        .iter()
        .find(|g| group_fn_names(g).contains(&"handle_items"))
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
        .any(|g| group_fn_names(g).contains(&"get_name"));
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
