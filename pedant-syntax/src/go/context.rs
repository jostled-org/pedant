//! What the walk knows about the position it is standing in.
//!
//! Every fact but the file scope names the scope and the declaration that hold
//! it, and those two answers come from where the walk is rather than from the
//! node in front of it. Carrying them in one copy value keeps each extractor
//! reading the same context instead of re-deriving containment by climbing
//! parents.

use crate::go::binding::GoBindingKind;
use crate::go::declaration::GoDeclarationKind;
use crate::go::scope::GoScopeKind;
use crate::tree_sitter::{Node, node_text};

/// The lexical position one fact is extracted at.
///
/// Compared rather than only read: the walk opens a frame exactly when a node
/// changes the context, so equality is what keeps the frame stack holding one
/// entry per real change instead of one per node.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FactContext {
    /// The innermost open scope.
    pub(super) scope: u32,
    /// What kind of scope that is, which decides whether a `const`, `var`, or
    /// `type` states a package declaration or binds a local name.
    pub(super) scope_kind: GoScopeKind,
    /// The innermost open declaration, when one is open.
    pub(super) declaration: Option<u32>,
    /// What kind of declaration that is, which decides whether a field or a
    /// method element belongs to a named type.
    pub(super) declaration_kind: Option<GoDeclarationKind>,
    /// The role a parameter list gives the names it holds.
    pub(super) parameter_role: Option<GoBindingKind>,
    /// Whether the identifiers here are names being bound rather than
    /// references being read.
    pub(super) binds_names: bool,
}

impl FactContext {
    /// The context one file scope opens.
    pub(super) fn at_file(scope: u32) -> Self {
        Self {
            scope,
            scope_kind: GoScopeKind::File,
            declaration: None,
            declaration_kind: None,
            parameter_role: None,
            binds_names: false,
        }
    }
}

/// The exact source text one node covers.
pub(super) fn text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    node_text(node, source.as_bytes())
}

/// Every `name` field child of one node, in source order.
///
/// One owner because two collectors ask it: a `var` specification states a
/// declaration per name and a parameter declaration binds one, and both read
/// the same grammar field.
pub(super) fn named_children<'tree>(node: Node<'tree>) -> Box<[Node<'tree>]> {
    let mut cursor = node.walk();
    node.children_by_field_name("name", &mut cursor).collect()
}

/// The exact source text one node's named field covers.
pub(super) fn field_text<'source>(
    node: Node<'_>,
    field: &str,
    source: &'source str,
) -> Option<&'source str> {
    node.child_by_field_name(field)
        .map(|child| text(child, source))
}
