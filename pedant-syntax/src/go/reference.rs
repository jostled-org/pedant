//! The reference sites one Go source states.

use crate::go::context::{FactContext, text};
use crate::go::span::GoFactSpan;
use crate::tree_sitter::Node;

/// What one occurrence refers to.
///
/// Syntax alone cannot say whether `Config(x)` calls a function or converts a
/// value, or whether `fmt` names a package or a variable. These kinds state the
/// shape the source wrote; a resolver holding a corpus decides what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoReferenceKind {
    /// A call whose callee is a bare name.
    Call,
    /// A call whose callee is a selector, so a qualifier stands before the
    /// name.
    QualifiedCall,
    /// A selector outside call position.
    Selector,
    /// A type written in type position.
    Type,
    /// A named value read or written outside a selector.
    Value,
}

/// One reference site, exactly as its source writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoReferenceFact<'source> {
    kind: GoReferenceKind,
    qualifier: Option<&'source str>,
    name: &'source str,
    span: GoFactSpan,
    name_span: GoFactSpan,
    declaration: Option<u32>,
    scope: u32,
}

impl<'source> GoReferenceFact<'source> {
    /// What shape the source wrote.
    pub fn kind(&self) -> GoReferenceKind {
        self.kind
    }

    /// The name standing before the referenced one, for a selector or a
    /// package-qualified type.
    pub fn qualifier(&self) -> Option<&'source str> {
        self.qualifier
    }

    /// The referenced name, in its source spelling.
    pub fn name(&self) -> &'source str {
        self.name
    }

    /// The extent of the whole reference site, which for a call is the call.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The extent of the referenced name alone.
    pub fn name_span(&self) -> GoFactSpan {
        self.name_span
    }

    /// The declaration the reference sits inside, when one holds it.
    pub fn declaration(&self) -> Option<u32> {
        self.declaration
    }

    /// The scope the reference is read in.
    pub fn scope(&self) -> u32 {
        self.scope
    }
}

/// The reference `node` states, if it states one.
///
/// `field` is the node's own field name inside its parent, which is what keeps
/// one occurrence from being counted twice: a selector in call position is
/// already the call's own name, and an identifier in `name` position is a
/// declaration rather than a read.
pub(super) fn reference_at<'source>(
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    match node.kind() {
        "call_expression" => call(node, source, context),
        "selector_expression" => selector(node, field, source, context),
        "qualified_type" => qualified_type(node, source, context),
        "type_identifier" => plain_type(node, field, source, context),
        "identifier" => value(node, field, source, context),
        _ => None,
    }
}

/// One reference naming `name_node`, covering `span`.
fn reference<'source>(
    kind: GoReferenceKind,
    qualifier: Option<&'source str>,
    name_node: Node<'_>,
    span: GoFactSpan,
    source: &'source str,
    context: FactContext,
) -> GoReferenceFact<'source> {
    GoReferenceFact {
        kind,
        qualifier,
        name: text(name_node, source),
        span,
        name_span: GoFactSpan::of_node(name_node),
        declaration: context.declaration,
        scope: context.scope,
    }
}

/// A call, qualified when its callee is a selector.
fn call<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    let callee = node.child_by_field_name("function")?;
    let span = GoFactSpan::of_node(node);
    match callee.kind() {
        "identifier" => Some(reference(
            GoReferenceKind::Call,
            None,
            callee,
            span,
            source,
            context,
        )),
        "selector_expression" => qualified_call(callee, span, source, context),
        _ => None,
    }
}

/// A call through a selector, whose qualifier is the selector's operand.
fn qualified_call<'source>(
    callee: Node<'_>,
    span: GoFactSpan,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    let operand = callee.child_by_field_name("operand")?;
    let named = callee.child_by_field_name("field")?;
    Some(reference(
        GoReferenceKind::QualifiedCall,
        Some(text(operand, source)),
        named,
        span,
        source,
        context,
    ))
}

/// A selector outside call position.
fn selector<'source>(
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    if field == Some("function") {
        return None;
    }
    let operand = node.child_by_field_name("operand")?;
    let named = node.child_by_field_name("field")?;
    Some(reference(
        GoReferenceKind::Selector,
        Some(text(operand, source)),
        named,
        GoFactSpan::of_node(node),
        source,
        context,
    ))
}

/// A type another package declares.
fn qualified_type<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    let package = node.child_by_field_name("package")?;
    let named = node.child_by_field_name("name")?;
    Some(reference(
        GoReferenceKind::Type,
        Some(text(package, source)),
        named,
        GoFactSpan::of_node(node),
        source,
        context,
    ))
}

/// A type this package declares, or a predeclared one.
///
/// A `name` field is the declaration's own identifier — the name of a `type`
/// specification, and the name half of a package-qualified type its own arm
/// already stated — so it names no reference.
fn plain_type<'source>(
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    match field {
        Some("name") => None,
        _ => Some(reference(
            GoReferenceKind::Type,
            None,
            node,
            GoFactSpan::of_node(node),
            source,
            context,
        )),
    }
}

/// A named value read or written.
///
/// A `name` field is a declaration's own identifier and a `function` field is a
/// call's callee, which the call arm already stated. An identifier standing
/// where the walk says names are bound is a binding, not a read.
fn value<'source>(
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
    context: FactContext,
) -> Option<GoReferenceFact<'source>> {
    let declared = matches!(field, Some("name" | "function")) || context.binds_names;
    (!declared).then(|| {
        reference(
            GoReferenceKind::Value,
            None,
            node,
            GoFactSpan::of_node(node),
            source,
            context,
        )
    })
}
