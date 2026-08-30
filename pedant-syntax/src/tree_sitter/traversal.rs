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

/// Walk all descendants of `root` depth-first and call `visitor` for each node.
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

        // This walk states no depth and holds no context open, so the shared
        // step is handed a counter it discards and a leaving step that does
        // nothing.
        if !advance(&mut cursor, &mut 0, |_| {}) {
            return;
        }
    }
}

/// Move the cursor to the next node in depth-first order after a leaf.
///
/// The crate's one cursor ascent. Ascends through parents until a next sibling
/// is available, decrementing `depth` once per level climbed. Returns `false`
/// when the traversal has exhausted every node and returned to the root.
///
/// The depth counts levels rather than states a ceiling, so it is as wide as
/// the tree a cursor can hold. A ceiling is a `u32`, and the walks that check
/// one refuse a level that width cannot name — which is a comparison against
/// the ceiling, not a saturation of the counter feeding it.
///
/// Every node the ascent leaves is handed to `leaving`, opening with the one the
/// cursor rests on: a leaf is left before its parent, and the ancestor the next
/// sibling is found from is left too. A caller holding contexts open closes them
/// there rather than in a second copy of this loop beside it.
pub(crate) fn advance(
    cursor: &mut TreeCursor<'_>,
    depth: &mut usize,
    mut leaving: impl FnMut(Node<'_>),
) -> bool {
    loop {
        leaving(cursor.node());
        if cursor.goto_next_sibling() {
            return true;
        }
        if !cursor.goto_parent() {
            return false;
        }
        *depth = depth.saturating_sub(1);
    }
}
