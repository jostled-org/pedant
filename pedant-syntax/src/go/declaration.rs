//! The declarations one Go source states, and which grammar nodes state them.

use crate::go::context::{FactContext, named_children, text};
use crate::go::span::GoFactSpan;
use crate::go::written_type::{ReadType, WrittenType, result_type, type_parts};
use crate::tree_sitter::Node;

/// What one Go declaration declares.
///
/// Closed against the Go grammar rather than against a graph vocabulary: a
/// consumer maps these onto its own kinds, so a new graph category cannot
/// silently change what this crate claims a source says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoDeclarationKind {
    /// A package-level `func` with no receiver.
    Function,
    /// A package-level `func` with a receiver.
    Method,
    /// A named type whose underlying type is a struct.
    Struct,
    /// A named type whose underlying type is an interface.
    Interface,
    /// A named type whose underlying type is neither a struct nor an
    /// interface.
    DefinedType,
    /// A `type A = B` alias.
    TypeAlias,
    /// A package-level `const` name.
    Constant,
    /// A package-level `var` name.
    Variable,
    /// A named field of a struct type.
    Field,
    /// A field or interface element written as a bare type, which embeds that
    /// type's own members.
    EmbeddedField,
    /// A method an interface declares.
    InterfaceMethod,
}

/// One declaration, exactly as its source writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoDeclarationFact<'source> {
    kind: GoDeclarationKind,
    name: &'source str,
    span: GoFactSpan,
    name_span: GoFactSpan,
    parent: Option<u32>,
    receiver: Option<u32>,
    scope: u32,
    general_terms: bool,
    result: WrittenType<'source>,
    embedded: WrittenType<'source>,
}

impl<'source> GoDeclarationFact<'source> {
    /// What this declaration declares.
    pub fn kind(&self) -> GoDeclarationKind {
        self.kind
    }

    /// The declared name, in its source spelling.
    pub fn name(&self) -> &'source str {
        self.name
    }

    /// The extent of the whole declaration.
    ///
    /// A specification that is all its `type`, `const`, or `var` declaration
    /// states returns that declaration, so the keyword opens the text. A
    /// specification inside a parenthesized group returns its own extent.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The extent of the declared name alone.
    pub fn name_span(&self) -> GoFactSpan {
        self.name_span
    }

    /// The declaration that holds this one: a struct for its fields, and an
    /// interface for its methods and embedded elements.
    ///
    /// A method's receiver type is not stated here, because the receiver may be
    /// declared in another file; the receiver binding names it instead.
    pub fn parent(&self) -> Option<u32> {
        self.parent
    }

    /// The receiver binding of a method declaration.
    pub fn receiver(&self) -> Option<u32> {
        self.receiver
    }

    /// The scope this declaration is stated in.
    pub fn scope(&self) -> u32 {
        self.scope
    }

    /// Whether an interface states an element that is a type set rather than a
    /// method or an embedded interface.
    ///
    /// A union, an approximation, and any other general term make the interface
    /// a type constraint, whose members are types rather than the methods a
    /// structural reader compares. False for every other declaration.
    pub fn states_general_terms(&self) -> bool {
        self.general_terms
    }

    /// The package qualifier of the single result this callable declares.
    pub fn result_qualifier(&self) -> Option<&'source str> {
        self.result.qualifier
    }

    /// The name of the single result this callable declares.
    ///
    /// Absent for a declaration that is not a callable, for a callable stating
    /// no result, and for one stating a result the model names no single type
    /// for — several results, or an unnamed composite. A caller reading a call's
    /// value therefore learns a type only when the source states exactly one.
    pub fn result_name(&self) -> Option<&'source str> {
        self.result.name
    }

    /// Whether the single declared result is a pointer form.
    pub fn result_pointer(&self) -> bool {
        self.result.pointer
    }

    /// The package qualifier of the type this field embeds.
    pub fn embedded_qualifier(&self) -> Option<&'source str> {
        self.embedded.qualifier
    }

    /// The name of the type this field embeds.
    pub fn embedded_name(&self) -> Option<&'source str> {
        self.embedded.name
    }

    /// Whether the embedded type is written in pointer form.
    pub fn embedded_pointer(&self) -> bool {
        self.embedded.pointer
    }

    /// Name the receiver binding a method declaration states.
    ///
    /// Filled after the fact is retained, because a receiver is a binding of
    /// its own and the walk reaches it inside the declaration it belongs to.
    pub(super) fn bind_receiver(&mut self, binding: u32) {
        self.receiver = Some(binding);
    }
}

/// Every declaration `node` states, in the order the source writes them.
///
/// Empty for a node that declares nothing here, which is most of them, and for
/// a declaration written somewhere the model states no node for: a `type`,
/// `const`, or `var` inside a function body binds a local name rather than
/// declaring a package member.
pub(super) fn declarations_at<'source>(
    node: Node<'_>,
    kind: &str,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    match kind {
        "function_declaration" => callable_declaration(
            node,
            GoDeclarationKind::Function,
            source,
            context,
            context.at_file_scope(),
            None,
        ),
        "method_declaration" => callable_declaration(
            node,
            GoDeclarationKind::Method,
            source,
            context,
            context.at_file_scope(),
            None,
        ),
        "method_elem" => callable_declaration(
            node,
            GoDeclarationKind::InterfaceMethod,
            source,
            context,
            context.declaration_kind == Some(GoDeclarationKind::Interface),
            context.declaration,
        ),
        "type_spec" => package_spec(node, declared_kind(node), source, context),
        "type_alias" => package_spec(node, GoDeclarationKind::TypeAlias, source, context),
        "const_spec" => package_names(node, GoDeclarationKind::Constant, source, context),
        "var_spec" => package_names(node, GoDeclarationKind::Variable, source, context),
        "field_declaration" => struct_members(node, source, context),
        "type_elem" => interface_embed(node, source, context),
        _ => Box::new([]),
    }
}

/// One declaration naming `name_node`, covering `span`.
fn declaration<'source>(
    kind: GoDeclarationKind,
    name_node: Node<'_>,
    span: GoFactSpan,
    source: &'source str,
    context: FactContext,
    parent: Option<u32>,
) -> GoDeclarationFact<'source> {
    GoDeclarationFact {
        kind,
        name: text(name_node, source),
        span,
        name_span: GoFactSpan::of_node(name_node),
        parent,
        receiver: None,
        scope: context.scope,
        general_terms: false,
        result: WrittenType::default(),
        embedded: WrittenType::default(),
    }
}

/// The same declaration, stating whether its interface body writes a type set.
fn constrained<'source>(
    declared: GoDeclarationFact<'source>,
    general_terms: bool,
) -> GoDeclarationFact<'source> {
    GoDeclarationFact {
        general_terms,
        ..declared
    }
}

/// The same declaration, carrying the single result its callable declares.
fn returning<'source>(
    declared: GoDeclarationFact<'source>,
    result: WrittenType<'source>,
) -> GoDeclarationFact<'source> {
    GoDeclarationFact { result, ..declared }
}

/// The same declaration, carrying the type its field embeds.
fn embedding<'source>(
    declared: GoDeclarationFact<'source>,
    embedded: WrittenType<'source>,
) -> GoDeclarationFact<'source> {
    GoDeclarationFact {
        embedded,
        ..declared
    }
}

/// One `func` declaration, whether a package states it or an interface does.
///
/// The one shape a function, a method, and an interface method share: a gate
/// its caller answers, the name its `name` field states, the whole node as its
/// extent, the declaration that holds it, and the single result its signature
/// declares. A gate that fails states no declaration at all, which is how a
/// `func` written inside a body and a method element written outside an
/// interface both answer nothing.
fn callable_declaration<'source>(
    node: Node<'_>,
    kind: GoDeclarationKind,
    source: &'source str,
    context: FactContext,
    admitted: bool,
    parent: Option<u32>,
) -> Box<[GoDeclarationFact<'source>]> {
    admitted
        .then(|| node.child_by_field_name("name"))
        .flatten()
        .map(|name| {
            returning(
                declaration(
                    kind,
                    name,
                    GoFactSpan::of_node(node),
                    source,
                    context,
                    parent,
                ),
                result_type(node, source),
            )
        })
        .into_iter()
        .collect()
}

/// A package-level `type` specification or alias.
fn package_spec<'source>(
    node: Node<'_>,
    kind: GoDeclarationKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    let named = context
        .at_file_scope()
        .then(|| node.child_by_field_name("name"))
        .flatten();
    named
        .map(|name| {
            constrained(
                declaration(kind, name, spec_span(node), source, context, None),
                states_general_terms(node),
            )
        })
        .into_iter()
        .collect()
}

/// Whether one `type` specification's interface body writes a type set.
///
/// The elements are read one level down rather than walked: an interface states
/// its own methods and its own embedded elements directly, and a term written
/// inside one of them belongs to that element's type rather than to this
/// interface's element list.
fn states_general_terms(node: Node<'_>) -> bool {
    let Some(body) = node
        .child_by_field_name("type")
        .filter(|declared| declared.kind() == "interface_type")
    else {
        return false;
    };
    let mut walk = body.walk();
    body.named_children(&mut walk)
        .filter(|element| element.kind() == "type_elem")
        .any(|element| embedded_type(element.named_child(0), false).name.is_none())
}

/// Every name one package-level `const` or `var` specification states.
fn package_names<'source>(
    node: Node<'_>,
    kind: GoDeclarationKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    match context.at_file_scope() {
        true => named_children(node)
            .iter()
            .map(|&name| declaration(kind, name, spec_span(node), source, context, None))
            .collect(),
        false => Box::new([]),
    }
}

/// Every member one struct field declaration states.
fn struct_members<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    if context.declaration_kind != Some(GoDeclarationKind::Struct) {
        return Box::new([]);
    }
    let named = named_children(node);
    match named.is_empty() {
        false => named
            .iter()
            .map(|&name| {
                declaration(
                    GoDeclarationKind::Field,
                    name,
                    GoFactSpan::of_node(node),
                    source,
                    context,
                    context.declaration,
                )
            })
            .collect(),
        true => embedded_member(node, source, context),
    }
}

/// A field written as a bare type, which embeds that type's own members.
fn embedded_member<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    embedded_declaration(
        node,
        node.child_by_field_name("type"),
        embedded_star(node),
        source,
        context,
    )
}

/// One declaration for an element written as a bare type.
///
/// The one tail a struct field and an interface element share: both are named
/// by the identifier the type recognizer found, both cover the whole element,
/// both belong to the declaration that holds them, and both carry the qualified
/// type their source wrote. An element naming no single type declares nothing
/// here, which is how an interface stating a union embeds no method set.
fn embedded_declaration<'source>(
    node: Node<'_>,
    written: Option<Node<'_>>,
    pointer: bool,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    let read = embedded_type(written, pointer);
    read.name
        .map(|name| {
            embedding(
                declaration(
                    GoDeclarationKind::EmbeddedField,
                    name,
                    GoFactSpan::of_node(node),
                    source,
                    context,
                    context.declaration,
                ),
                read.written(source),
            )
        })
        .into_iter()
        .collect()
}

/// The type an element writes, read once for both the name and the spelling.
///
/// An absent element names nothing, which is the same answer a shape this model
/// states no single type for gives, so both routes read one recognizer rather
/// than a second copy of its five arms.
fn embedded_type<'tree>(written: Option<Node<'tree>>, pointer: bool) -> ReadType<'tree> {
    written
        .map(|declared| type_parts(declared, pointer))
        .unwrap_or_default()
}

/// Whether a struct embeds `*T` rather than `T`.
///
/// The grammar writes the star of an embedded pointer beside the field's `type`
/// rather than inside it, so the written-type recognizer reads a bare name here
/// and the form has to be taken off the field declaration itself. A named
/// field's own `*T` sits inside its type, so no other star reaches this node.
fn embedded_star(node: Node<'_>) -> bool {
    let mut walk = node.walk();
    node.children(&mut walk).any(|child| child.kind() == "*")
}

/// An interface element written as a bare type, which embeds that interface.
fn interface_embed<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    let written = (context.declaration_kind == Some(GoDeclarationKind::Interface))
        .then(|| node.named_child(0))
        .flatten();
    embedded_declaration(node, written, false, source, context)
}

/// What a `type` specification's underlying type makes it.
fn declared_kind(node: Node<'_>) -> GoDeclarationKind {
    match node.child_by_field_name("type").map(|held| held.kind()) {
        Some("struct_type") => GoDeclarationKind::Struct,
        Some("interface_type") => GoDeclarationKind::Interface,
        _ => GoDeclarationKind::DefinedType,
    }
}

/// The extent one specification returns.
///
/// A sole specification returns its whole `type`, `const`, or `var`
/// declaration, so the keyword opens the text; one inside a parenthesized group
/// returns only its own range. The grammar states a group as `seq(keyword,
/// choice(spec, seq('(', …, ')')))`, so an ungrouped specification closes its
/// declaration and a grouped one is always followed by at least the closing
/// parenthesis. One sibling read answers that, where a fixed child index would
/// answer wrongly for `type /* note */ (`.
fn spec_span(spec: Node<'_>) -> GoFactSpan {
    let widened = spec
        .parent()
        .filter(|parent| is_sole_spec(*parent, spec))
        .unwrap_or(spec);
    GoFactSpan::of_node(widened)
}

/// Whether a specification is all its declaration states.
fn is_sole_spec(parent: Node<'_>, spec: Node<'_>) -> bool {
    matches!(
        parent.kind(),
        "type_declaration" | "const_declaration" | "var_declaration"
    ) && spec.next_sibling().is_none()
}
