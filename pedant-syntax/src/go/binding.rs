//! The names one Go source binds inside a lexical scope.
//!
//! A binding is not a declaration: a parameter, a receiver, and a local name
//! participate in shadowing and in type inference, but none of them is a
//! package member a graph states a node for. Keeping the two apart is what lets
//! a resolver answer "which name does this occurrence see" without inventing
//! definitions.

use crate::go::context::{FactContext, named_children, named_nodes, text};
use crate::go::span::GoFactSpan;
use crate::go::written_type::{WrittenType, field_type, type_parts};
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

/// What shape a short variable declaration's initializer is written in.
///
/// A short variable declaration states no type, so the only evidence of what it
/// binds is the shape of the expression beside it. These are the shapes that
/// name a type; syntax alone cannot say what that name denotes, so a reader
/// holding a corpus decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoInitializerForm {
    /// `T{…}` or `pkg.T{…}`, which is a value of the type it names.
    CompositeLiteral,
    /// `&T{…}` or `&pkg.T{…}`, which is a pointer to the type it names.
    CompositeLiteralAddress,
    /// `f(…)`, `pkg.f(…)`, or `T(x)`. A call whose callee is a bare or
    /// package-qualified name is a call when the name denotes a function and a
    /// conversion when it denotes a type, and the grammar states neither.
    Call,
}

/// The type one short variable declaration's initializer names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoInitializer<'source> {
    form: GoInitializerForm,
    qualifier: Option<&'source str>,
    name: &'source str,
    pointer: bool,
}

impl<'source> GoInitializer<'source> {
    /// What shape the initializer is written in.
    pub fn form(&self) -> GoInitializerForm {
        self.form
    }

    /// The package qualifier written before the name, when the source writes
    /// one.
    pub fn qualifier(&self) -> Option<&'source str> {
        self.qualifier
    }

    /// The name the initializer states, in its source spelling.
    pub fn name(&self) -> &'source str {
        self.name
    }

    /// Whether the initializer states a pointer form.
    pub fn pointer(&self) -> bool {
        self.pointer
    }
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
    initializer: Option<GoInitializer<'source>>,
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

    /// The type this binding's initializer names, for a short variable
    /// declaration whose expression states one.
    ///
    /// Absent everywhere else: a parameter, a receiver, a result, and a `var`
    /// or `const` inside a body all state their type directly, and an
    /// initializer whose shape names no type states no evidence here rather
    /// than a guess.
    pub fn initializer(&self) -> Option<GoInitializer<'source>> {
        self.initializer
    }
}

/// Every name `node` binds, in the order the source writes them.
pub(super) fn bindings_at<'source>(
    node: Node<'_>,
    kind: &str,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    match kind {
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
        initializer: None,
    }
}

/// The same binding, carrying the type its initializer names.
fn initialized<'source>(
    bound: GoBindingFact<'source>,
    initializer: Option<GoInitializer<'source>>,
) -> GoBindingFact<'source> {
    GoBindingFact {
        initializer,
        ..bound
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
    let written = field_type(node, "type", source);
    named_children(node)
        .iter()
        .map(|&name| binding(kind, name, written, source, context))
        .collect()
}

/// Every name one short variable declaration binds.
///
/// A declaration binding one name also carries what its initializer names. One
/// binding several names distributes a call's results across them, and which
/// result reaches which name is not a grammar answer, so those bindings carry
/// no initializer evidence.
fn locals<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    let names = node
        .child_by_field_name("left")
        .map(|left| identifiers(left))
        .unwrap_or_default();
    let stated = (names.len() == 1)
        .then(|| initializer_of(node, source))
        .flatten();
    names
        .iter()
        .map(|&name| {
            initialized(
                binding(
                    GoBindingKind::Local,
                    name,
                    WrittenType::default(),
                    source,
                    context,
                ),
                stated,
            )
        })
        .collect()
}

/// The type one short variable declaration's sole initializer names.
fn initializer_of<'source>(node: Node<'_>, source: &'source str) -> Option<GoInitializer<'source>> {
    let right = node.child_by_field_name("right")?;
    let stated = (right.named_child_count() == 1)
        .then(|| right.named_child(0))
        .flatten()?;
    initializer_at(stated, source, false)
}

/// The type one expression names, when its shape names one.
///
/// A leading `&` is followed through once: `&T{…}` is a pointer to the literal's
/// type, and `&f(…)` is not a form Go accepts, so no other shape is reached
/// through it.
fn initializer_at<'source>(
    stated: Node<'_>,
    source: &'source str,
    address: bool,
) -> Option<GoInitializer<'source>> {
    match stated.kind() {
        "composite_literal" => composite(stated, source, address),
        "call_expression" => (!address).then(|| called(stated, source)).flatten(),
        "unary_expression" => addressed(stated, source, address),
        _ => None,
    }
}

/// A composite literal, which is a value of the type it names.
fn composite<'source>(
    stated: Node<'_>,
    source: &'source str,
    address: bool,
) -> Option<GoInitializer<'source>> {
    let declared = stated.child_by_field_name("type")?;
    let written = type_parts(declared, false).written(source);
    Some(GoInitializer {
        form: match address {
            true => GoInitializerForm::CompositeLiteralAddress,
            false => GoInitializerForm::CompositeLiteral,
        },
        qualifier: written.qualifier,
        name: written.name?,
        pointer: written.pointer || address,
    })
}

/// A call whose callee is a bare or package-qualified name.
fn called<'source>(stated: Node<'_>, source: &'source str) -> Option<GoInitializer<'source>> {
    let callee = stated.child_by_field_name("function")?;
    let (qualifier, name) = match callee.kind() {
        "identifier" | "type_identifier" => (None, text(callee, source)),
        "selector_expression" => (
            Some(text(callee.child_by_field_name("operand")?, source)),
            text(callee.child_by_field_name("field")?, source),
        ),
        _ => return None,
    };
    Some(GoInitializer {
        form: GoInitializerForm::Call,
        qualifier,
        name,
        pointer: false,
    })
}

/// The expression a leading `&` takes the address of.
fn addressed<'source>(
    stated: Node<'_>,
    source: &'source str,
    address: bool,
) -> Option<GoInitializer<'source>> {
    let operator = stated.child_by_field_name("operator")?;
    let operand = stated.child_by_field_name("operand")?;
    match (address, text(operator, source)) {
        (false, "&") => initializer_at(operand, source, true),
        _ => None,
    }
}

/// Every name one `var` or `const` specification inside a body binds.
fn body_names<'source>(
    node: Node<'_>,
    kind: GoBindingKind,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    match context.at_file_scope() {
        false => {
            let written = field_type(node, "type", source);
            named_children(node)
                .iter()
                .map(|&name| binding(kind, name, written, source, context))
                .collect()
        }
        true => Box::new([]),
    }
}

/// The name one `type` specification inside a body binds.
fn body_type<'source>(
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Box<[GoBindingFact<'source>]> {
    let named = (!context.at_file_scope())
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

/// Every identifier one expression list holds directly.
///
/// Collected rather than iterated, because the caller needs the count before it
/// needs the names: a declaration binding one name carries what its initializer
/// states, and one binding several does not.
fn identifiers<'tree>(list: Node<'tree>) -> Box<[Node<'tree>]> {
    let mut cursor = list.walk();
    named_nodes(list, &mut cursor)
        .filter(|child| child.kind() == "identifier")
        .collect()
}
