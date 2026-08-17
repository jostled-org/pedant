//! The one indexed fixture workspace every tool case queries, and the two
//! readers that turn a `CallToolResult` back into text and status.
//!
//! Every case asks a tool a question about the same multi-crate fixture, so the
//! index is built one way here rather than per case. A tool answers in content
//! blocks; the cases assert about the text and the error flag, so those two
//! projections are stated once.

use pedant_mcp::index::WorkspaceIndex;

use crate::committed_fixture::fixture_path;

/// The multi-crate fixture workspace, indexed.
pub fn fixture_index() -> WorkspaceIndex {
    let root = fixture_path("multi_crate");
    WorkspaceIndex::build(&root, None).unwrap()
}

/// Every text block a tool answered with, joined.
pub fn result_text(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| match c {
            rmcp::model::ContentBlock::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Whether the tool refused.
pub fn is_error(result: &rmcp::model::CallToolResult) -> bool {
    result.is_error == Some(true)
}

/// Assert a capability payload carries no symbol evidence.
///
/// 4.T14 (Invariant 14): the MCP index takes the flat projection from each
/// analysis, so a finding keeps its exact current fields and neither symbol name
/// reaches the protocol. Two properties say that: no finding object holds a
/// `symbols` or `symbol_attribution` key, and neither name appears anywhere in
/// the serialized text, which also catches a nested carrier no key check reads.
///
/// Every capability case asks the same question of the same tool, so the two
/// properties are stated once. `subject` names the payload under test, because
/// the cases differ in which findings they drove the tool to answer with.
pub fn assert_no_symbol_evidence(text: &str, subject: &str) {
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(text).expect("the payload is a flat finding array");
    for finding in &findings {
        let fields: Vec<&str> = finding
            .as_object()
            .expect("each finding is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            !fields.contains(&"symbols") && !fields.contains(&"symbol_attribution"),
            "a {subject} finding must carry no symbol field: {fields:?}"
        );
    }
    for field in ["\"symbols\"", "\"symbol_attribution\""] {
        assert!(
            !text.contains(field),
            "the {subject} payload must not carry {field}: {text}"
        );
    }
}
