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
