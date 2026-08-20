//! The names one Go source binds inside a lexical scope.
//!
//! A binding is not a declaration: a parameter, a receiver, and a local name
//! participate in shadowing and in type inference, but none of them is a
//! package member a graph states a node for. Keeping the two apart is what lets
//! a resolver answer "which name does this occurrence see" without inventing
//! definitions.

use crate::go::context::{FactContext, field_text, named_children, text};
use crate::go::scope::GoScopeKind;
use crate::go::span::GoFactSpan;
use crate::tree_sitter::Node;

/// What binds one name into a scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoBindingKind {
    /// A method's receiver.
    Receiver,
    /// A parameter of a function, method, or function literal.
    Parameter,
    /// A named result.
    Result,
    /// A name a short variable declaration binds.
    Local,
    /// A name a `var` declaration inside a body binds.
    Variable,
    /// A name a `const` declaration inside a body binds.
    Constant,
    /// A name a `type` declaration inside a body binds.
    Type,
}

/// The type a binding's source writes for it, when it writes one.
///
/// A field group rather than three loose fields, because the three answers are
/// only ever read together: a receiver's method set depends on its name, its
/// package qualifier, and whether it was written in pointer form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct WrittenType<'source> {
    qualifier: Option<&'source str>,
    name: Option<&'source str>,
    pointer: bool,
}

/// One name bound into a scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoBindingFact<'source> {
    kind: GoBindingKind,
    name: &'source str,
    span: GoFactSpan,
    scope: u32,
    declaration: Option<u32>,
    written: WrittenType<'source>,
}

impl<'source> GoBindingFact<'source> {
    /// What binds this name.
    pub fn kind(&self) -> GoBindingKind {
        self.kind
    }

    /// The bound name, in its source spelling.
    pub fn name(&self) -> &'source str {
        self.name
    }

    /// The extent of the bound name.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The scope the name is visible in.
    pub fn scope(&self) -> u32 {
        self.scope
    }

    /// The declaration the binding sits inside, when one holds it.
    pub fn declaration(&self) -> Option<u32> {
        self.declaration
    }

    /// The package qualifier of the written type, for a type another package
    /// declares.
    pub fn type_qualifier(&self) -> Option<&'source str> {
        self.written.qualifier
    }

    /// The written type's own name, absent when the source states no type.
    pub fn type_name(&self) -> Option<&'source str> {
        self.written.name
    }

    /// Whether the written type is a pointer form.
    pub fn pointer(&self) -> bool {
        self.written.pointer
    }
}

/// Every name `node` binds, in the order the source writes them.
pub(super) fn bindings_at<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    match node.kind() {
        "parameter_declaration" | "variadic_parameter_declaration" => {
            parameters(node, source, context)
        }
        "short_var_declaration" => locals(node, source, context),
        "var_spec" => body_names(node, GoBindingKind::Variable, source, context),
        "const_spec" => body_names(node, GoBindingKind::Constant, source, context),
        "type_spec" | "type_alias" => body_type(node, source, context),
        _ => Box::new([]),
    }
}

/// Whether a name written here binds locally rather than declaring a package
/// member.
fn inside_a_body(context: FactContext) -> bool {
    !matches!(context.scope_kind, GoScopeKind::File)
}

/// One binding of `name_node`, carrying the type its source writes.
fn binding<'source>(
    kind: GoBindingKind,
    name_node: Node<'_>,
    written: WrittenType<'source>,
    source: &'source str,
    context: FactContext,
) -> GoBindingFact<'source> {
    GoBindingFact {
        kind,
        name: text(name_node, source),
        span: GoFactSpan::of_node(name_node),
        scope: context.scope,
        declaration: context.declaration,
        written,
    }
}

/// Every name one parameter, receiver, or result declaration binds.
///
/// The role comes from the list the declaration sits in, which the walk knows
/// and the declaration itself does not: the same grammar node states a
/// receiver, a parameter, and a named result.
fn parameters<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    let kind = context.parameter_role.unwrap_or(GoBindingKind::Parameter);
    let written = written_type(node, source);
    named_children(node)
        .iter()
        .map(|&name| binding(kind, name, written, source, context))
        .collect()
}

/// Every name one short variable declaration binds.
fn locals<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    node.child_by_field_name("left")
        .map(|left| identifiers(left))
        .unwrap_or_default()
        .iter()
        .map(|&name| {
            binding(
                GoBindingKind::Local,
                name,
                WrittenType::default(),
                source,
                context,
            )
        })
        .collect()
}

/// Every name one `var` or `const` specification inside a body binds.
fn body_names<'source>(
    node: Node<'_>,
    kind: GoBindingKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    match inside_a_body(context) {
        true => {
            let written = written_type(node, source);
            named_children(node)
                .iter()
                .map(|&name| binding(kind, name, written, source, context))
                .collect()
        }
        false => Box::new([]),
    }
}

/// The name one `type` specification inside a body binds.
fn body_type<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    let named = inside_a_body(context)
        .then(|| node.child_by_field_name("name"))
        .flatten();
    named
        .map(|name| {
            binding(
                GoBindingKind::Type,
                name,
                WrittenType::default(),
                source,
                context,
            )
        })
        .into_iter()
        .collect()
}

/// The type one declaration writes, if it writes one.
fn written_type<'source>(node: Node<'_>, source: &'source str) -> WrittenType<'source> {
    node.child_by_field_name("type")
        .map(|declared| type_parts(declared, source, false))
        .unwrap_or_default()
}

/// One written type split into its qualifier, its name, and its pointer form.
fn type_parts<'source>(
    declared: Node<'_>,
    source: &'source str,
    pointer: bool,
) -> WrittenType<'source> {
    match declared.kind() {
        "type_identifier" => WrittenType {
            qualifier: None,
            name: Some(text(declared, source)),
            pointer,
        },
        "qualified_type" => WrittenType {
            qualifier: field_text(declared, "package", source),
            name: field_text(declared, "name", source),
            pointer,
        },
        "pointer_type" => nested_type(declared.named_child(0), source, true),
        "generic_type" => nested_type(declared.child_by_field_name("type"), source, pointer),
        _ => WrittenType {
            qualifier: None,
            name: None,
            pointer,
        },
    }
}

/// The parts of a type one wrapper holds, or nothing when it holds none.
fn nested_type<'source>(
    inner: Option<Node<'_>>,
    source: &'source str,
    pointer: bool,
) -> WrittenType<'source> {
    inner
        .map(|held| type_parts(held, source, pointer))
        .unwrap_or(WrittenType {
            qualifier: None,
            name: None,
            pointer,
        })
}

/// Every identifier one expression list holds directly.
fn identifiers<'tree>(list: Node<'tree>) -> Box<[Node<'tree>]> {
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
        .collect()
}
