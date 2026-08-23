//! The declarations one Go source states, and which grammar nodes state them.

use crate::go::context::{FactContext, named_children, text};
use crate::go::scope::GoScopeKind;
use crate::go::span::GoFactSpan;
use crate::go::written_type::{WrittenType, field_type, type_parts};
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
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    match node.kind() {
        "function_declaration" => {
            package_callable(node, GoDeclarationKind::Function, source, context)
        }
        "method_declaration" => package_callable(node, GoDeclarationKind::Method, source, context),
        "type_spec" => package_spec(node, declared_kind(node), source, context),
        "type_alias" => package_spec(node, GoDeclarationKind::TypeAlias, source, context),
        "const_spec" => package_names(node, GoDeclarationKind::Constant, source, context),
        "var_spec" => package_names(node, GoDeclarationKind::Variable, source, context),
        "field_declaration" => struct_members(node, source, context),
        "method_elem" => {
            interface_member(node, GoDeclarationKind::InterfaceMethod, source, context)
        }
        "type_elem" => interface_embed(node, source, context),
        _ => Box::new([]),
    }
}

/// Whether a declaration written here is a package member.
fn at_package_scope(context: FactContext) -> bool {
    matches!(context.scope_kind, GoScopeKind::File)
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

/// A package-level `func`, with or without a receiver.
fn package_callable<'source>(
    node: Node<'_>,
    kind: GoDeclarationKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    let named = at_package_scope(context)
        .then(|| node.child_by_field_name("name"))
        .flatten();
    named
        .map(|name| {
            returning(
                declaration(kind, name, GoFactSpan::of_node(node), source, context, None),
                field_type(node, "result", source),
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
    let named = at_package_scope(context)
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
        .any(|element| element.named_child(0).and_then(embedded_name).is_none())
}

/// Every name one package-level `const` or `var` specification states.
fn package_names<'source>(
    node: Node<'_>,
    kind: GoDeclarationKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    match at_package_scope(context) {
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
    node.child_by_field_name("type")
        .and_then(|written| {
            embedded_name(written).map(|name| {
                embedding(
                    declaration(
                        GoDeclarationKind::EmbeddedField,
                        name,
                        GoFactSpan::of_node(node),
                        source,
                        context,
                        context.declaration,
                    ),
                    type_parts(written, source, embedded_star(node)),
                )
            })
        })
        .into_iter()
        .collect()
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

/// A method an interface declares.
fn interface_member<'source>(
    node: Node<'_>,
    kind: GoDeclarationKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoDeclarationFact<'source>]> {
    let named = (context.declaration_kind == Some(GoDeclarationKind::Interface))
        .then(|| node.child_by_field_name("name"))
        .flatten();
    named
        .map(|name| {
            returning(
                declaration(
                    kind,
                    name,
                    GoFactSpan::of_node(node),
                    source,
                    context,
                    context.declaration,
                ),
                field_type(node, "result", source),
            )
        })
        .into_iter()
        .collect()
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
    written
        .and_then(|written| {
            embedded_name(written).map(|name| {
                embedding(
                    declaration(
                        GoDeclarationKind::EmbeddedField,
                        name,
                        GoFactSpan::of_node(node),
                        source,
                        context,
                        context.declaration,
                    ),
                    type_parts(written, source, false),
                )
            })
        })
        .into_iter()
        .collect()
}

/// What a `type` specification's underlying type makes it.
fn declared_kind(node: Node<'_>) -> GoDeclarationKind {
    match node.child_by_field_name("type").map(|held| held.kind()) {
        Some("struct_type") => GoDeclarationKind::Struct,
        Some("interface_type") => GoDeclarationKind::Interface,
        _ => GoDeclarationKind::DefinedType,
    }
}

/// The identifier a bare embedded type names.
fn embedded_name<'tree>(declared: Node<'tree>) -> Option<Node<'tree>> {
    match declared.kind() {
        "type_identifier" => Some(declared),
        "qualified_type" => declared.child_by_field_name("name"),
        "pointer_type" => declared.named_child(0).and_then(embedded_name),
        "generic_type" => declared.child_by_field_name("type").and_then(embedded_name),
        _ => None,
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
