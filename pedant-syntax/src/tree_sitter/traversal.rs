//! Depth-first traversal of a parsed tree, and node text reads.

use ::tree_sitter::TreeCursor;

use crate::tree_sitter::Node;

/// Extract UTF-8 text from a tree-sitter node.
///
/// `source` should be the same buffer [`parse`](super::parse) consumed to build
/// `node`'s tree. A node's byte range indexes that buffer, so a different one
/// answers with the wrong text.
///
/// Returns an empty string when the range falls outside `source` and when it is
/// not valid UTF-8. A caller that passes the parsed buffer and parsed a `&str`
/// reaches neither, and reads an unnamed node rather than an error either way.
pub fn node_text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    source
        .get(node.byte_range())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or("")
}

/// Walk all descendants of `root` using a tree cursor, calling `visitor`
/// for each node. Uses depth-first traversal with zero intermediate allocations.
pub fn walk_descendants(root: Node<'_>, mut visitor: impl FnMut(Node<'_>)) {
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

        if !advance_to_next_sibling(&mut cursor) {
            return;
        }
    }
}

/// Move the cursor to the next node in depth-first order after a leaf.
///
/// Ascends through parents until a next sibling is available. Returns `false`
/// when the traversal has exhausted every node and returned to the root.
fn advance_to_next_sibling(cursor: &mut TreeCursor<'_>) -> bool {
    while !cursor.goto_next_sibling() {
        if !cursor.goto_parent() {
            return false;
        }
    }
    true
}
