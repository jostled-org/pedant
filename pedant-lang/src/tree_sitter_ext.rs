//! Shared tree-sitter helpers for structured AST extraction.
//!
//! Feature-gated: only compiled when at least one `ts-*` language feature is
//! enabled. Each language module uses these helpers together with its own
//! grammar-specific traversal logic.

use tree_sitter::{Node, Parser, Tree};

/// Parse source code with the given tree-sitter language.
///
/// Returns `None` if parsing fails (should not happen with valid grammars).
pub(crate) fn parse(source: &[u8], language: tree_sitter::Language) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

/// Extract UTF-8 text from a tree-sitter node.
///
/// Returns an empty string if the byte range is not valid UTF-8.
pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    let range = node.byte_range();
    std::str::from_utf8(&source[range]).unwrap_or("")
}

/// Walk all descendants of `root` using a tree cursor, calling `visitor`
/// for each node. Uses depth-first traversal with zero intermediate allocations.
pub(crate) fn walk_descendants(root: Node<'_>, mut visitor: impl FnMut(Node<'_>)) {
    let mut cursor = root.walk();
    let mut at_root = true;

    loop {
        let node = cursor.node();
        match at_root {
            true => at_root = false,
            false => visitor(node),
        }

        if cursor.goto_first_child() {
            continue;
        }

        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}
