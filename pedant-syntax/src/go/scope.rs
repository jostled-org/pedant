//! The lexical scopes a Go source opens.

use crate::go::span::GoFactSpan;
use crate::tree_sitter::Node;

/// What kind of lexical scope one Go construct opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoScopeKind {
    /// The whole source, which holds its imports and package declarations.
    File,
    /// A function, method, or function literal, which holds its receiver,
    /// parameters, and results.
    Declaration,
    /// A block or a statement that opens one, which holds the names its own
    /// statements bind.
    Block,
}

/// One lexical scope, and the scope that holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoScopeFact {
    kind: GoScopeKind,
    span: GoFactSpan,
    parent: Option<u32>,
}

impl GoScopeFact {
    /// One scope opened by `node` inside `parent`.
    pub(super) fn new(kind: GoScopeKind, node: Node<'_>, parent: Option<u32>) -> Self {
        Self {
            kind,
            span: GoFactSpan::of_node(node),
            parent,
        }
    }

    /// What kind of scope this is.
    pub fn kind(&self) -> GoScopeKind {
        self.kind
    }

    /// The extent the scope covers.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The scope that holds this one, absent only for the file scope.
    pub fn parent(&self) -> Option<u32> {
        self.parent
    }
}

/// The scope a node of this kind opens, if it opens one.
///
/// A statement that can bind a name in its own header — `if`, `for`, `switch`,
/// and `select` — opens a scope of its own, because the name it binds is
/// visible in its body but not after it.
///
/// Each clause opens one too. The Go specification makes every `case` and
/// `default` an implicit block, so a name `case 1` binds is invisible to `case
/// 2`. A reader picks the innermost binding that opens before an occurrence, so
/// clauses sharing one scope hand a sibling's binding to an occurrence that
/// cannot see it — a wrong answer rather than a withheld one.
///
/// The file scope is absent here. The walk opens it itself, before it enters
/// its first node, so the context stack's base always names a scope the
/// inventory already holds and no node kind can open a second one.
pub(super) fn scope_kind_at(kind: &str) -> Option<GoScopeKind> {
    match kind {
        "function_declaration" | "method_declaration" | "func_literal" => {
            Some(GoScopeKind::Declaration)
        }
        "block"
        | "if_statement"
        | "for_statement"
        | "expression_switch_statement"
        | "type_switch_statement"
        | "select_statement"
        | "expression_case"
        | "default_case"
        | "type_case"
        | "communication_case" => Some(GoScopeKind::Block),
        _ => None,
    }
}
