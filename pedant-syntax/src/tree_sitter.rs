//! Shared tree-sitter helpers for structured AST extraction.
//!
//! Feature-gated: only compiled when at least one `ts-*` language feature is
//! enabled. Grammar selection lives here, so a consumer names a
//! [`SyntaxLanguage`] and never a grammar crate. The node and tree types the
//! public signatures below name are re-exported, because this module is a
//! cross-crate API.

pub use ::tree_sitter::{Node, Tree};

use ::tree_sitter::{Parser, TreeCursor};

use crate::language::SyntaxLanguage;

/// Parse source code with the grammar for `language`.
///
/// Returns `None` when the language has no enabled grammar in this build and
/// when the parser itself fails. Never falls back to another grammar. A
/// recovered tree carrying error nodes is still a tree: this helper returns it.
pub fn parse(source: &[u8], language: SyntaxLanguage) -> Option<Tree> {
    let mut parser = Parser::new();
    let selected = parser.set_language(&grammar(language)?);
    // The two `?` above and below mean different things. `grammar` reports the
    // absence this build chose; a grammar it did link failing to load is an ABI
    // mismatch between that grammar and the tree-sitter core, which is a build
    // misconfiguration rather than a language this build omits.
    debug_assert!(
        selected.is_ok(),
        "a linked grammar matches the tree-sitter ABI"
    );
    selected.ok()?;
    parser.parse(source, None)
}

/// The enabled tree-sitter grammar for `language`, if this build has one.
///
/// Every variant names both arms — the grammar its feature enables and the
/// absence its feature leaves — so the match is exhaustive in every
/// configuration and a new [`SyntaxLanguage`] fails to compile here rather than
/// parsing as nothing.
fn grammar(language: SyntaxLanguage) -> Option<::tree_sitter::Language> {
    match language {
        // Rust parses through `syn`; it selects no grammar in any build.
        SyntaxLanguage::Rust => None,
        #[cfg(feature = "ts-python")]
        SyntaxLanguage::Python => Some(tree_sitter_python::LANGUAGE.into()),
        #[cfg(not(feature = "ts-python"))]
        SyntaxLanguage::Python => None,
        #[cfg(feature = "ts-javascript")]
        SyntaxLanguage::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        #[cfg(not(feature = "ts-javascript"))]
        SyntaxLanguage::JavaScript => None,
        #[cfg(feature = "ts-typescript")]
        SyntaxLanguage::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        #[cfg(feature = "ts-typescript")]
        SyntaxLanguage::Tsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        #[cfg(not(feature = "ts-typescript"))]
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => None,
        #[cfg(feature = "ts-go")]
        SyntaxLanguage::Go => Some(tree_sitter_go::LANGUAGE.into()),
        #[cfg(not(feature = "ts-go"))]
        SyntaxLanguage::Go => None,
        #[cfg(feature = "ts-bash")]
        SyntaxLanguage::Bash => Some(tree_sitter_bash::LANGUAGE.into()),
        #[cfg(not(feature = "ts-bash"))]
        SyntaxLanguage::Bash => None,
    }
}

/// Extract UTF-8 text from a tree-sitter node.
///
/// `source` should be the same buffer [`parse`] consumed to build `node`'s
/// tree. A node's byte range indexes that buffer, so a different one answers
/// with the wrong text.
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
