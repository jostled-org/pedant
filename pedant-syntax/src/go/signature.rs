//! The types one Go callable's signature states, term by term.
//!
//! A method set is compared by signature, and a signature is compared by its
//! terms in order, so the arity a source writes is part of the claim: a callable
//! taking one unnamed parameter and one taking none are different callables, and
//! the bindings a source states cannot tell them apart because an unnamed
//! parameter binds no name.
//!
//! Each term states the single named type its source writes. A term whose shape
//! names no single type — a slice, a map, a channel, a function type, an
//! anonymous composite — states no name here, so a reader learns that the term
//! exists and that this model cannot name it, rather than being handed a guess.

use crate::go::context::{name_count, named_nodes};
use crate::go::written_type::{WrittenType, field_type, type_parts};
use crate::tree_sitter::Node;

/// Where one signature term is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoSignatureRole {
    /// A parameter, in the order its callable declares it.
    Parameter,
    /// A result, in the order its callable declares it.
    Result,
}

/// One type a callable's signature states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoSignatureTermFact<'source> {
    declaration: u32,
    role: GoSignatureRole,
    position: u32,
    written: WrittenType<'source>,
    variadic: bool,
}

impl<'source> GoSignatureTermFact<'source> {
    /// The declaration whose signature states this term.
    pub fn declaration(&self) -> u32 {
        self.declaration
    }

    /// Whether the term is a parameter or a result.
    pub fn role(&self) -> GoSignatureRole {
        self.role
    }

    /// The term's place in its own role, counted from zero.
    pub fn position(&self) -> u32 {
        self.position
    }

    /// The package qualifier of the written type, for a type another package
    /// declares.
    pub fn type_qualifier(&self) -> Option<&'source str> {
        self.written.qualifier
    }

    /// The written type's own name, absent whenever the term's shape names no
    /// single type.
    pub fn type_name(&self) -> Option<&'source str> {
        self.written.name
    }

    /// Whether the written type is a pointer form.
    pub fn pointer(&self) -> bool {
        self.written.pointer
    }

    /// Whether the term is the variadic parameter its callable ends with.
    pub fn variadic(&self) -> bool {
        self.variadic
    }
}

/// Every term one callable declaration's signature states, parameters first.
///
/// Read at the callable itself rather than at each parameter node: an unnamed
/// parameter binds nothing, and a function type written inside a parameter
/// states parameters of its own, so the list a signature belongs to is the one
/// the callable names as its own field.
pub(super) fn signature_terms_at<'source>(
    node: Node<'_>,
    source: &'source str,
    declaration: u32,
) -> Box<[GoSignatureTermFact<'source>]> {
    let mut terms: Vec<GoSignatureTermFact<'source>> = node
        .child_by_field_name("parameters")
        .map(|list| list_terms(list, source, declaration, GoSignatureRole::Parameter))
        .unwrap_or_default();
    terms.extend(results(node, source, declaration));
    terms.into_boxed_slice()
}

/// Every term one result field states, whether it is a list or a single type.
///
/// A callable stating one result writes that type itself, and one stating none
/// or several writes a parameter list, so both shapes reach the same term model.
fn results<'source>(
    node: Node<'_>,
    source: &'source str,
    declaration: u32,
) -> Vec<GoSignatureTermFact<'source>> {
    let Some(result) = node.child_by_field_name("result") else {
        return Vec::new();
    };
    match result.kind() {
        "parameter_list" => list_terms(result, source, declaration, GoSignatureRole::Result),
        _ => vec![term(
            declaration,
            (GoSignatureRole::Result, 0),
            type_parts(result, false).written(source),
            false,
        )],
    }
}

/// Every term one parameter list states, in the order the source writes them.
///
/// One declaration states one term per name it binds, because `a, b int` is two
/// parameters of one type. A declaration binding no name still states one term:
/// an unnamed parameter is a parameter, and a signature that dropped it would
/// compare equal to one taking nothing at all.
///
/// Collected rather than grown: nothing in this crate but the checked walk may
/// push onto a list of facts, and a builder that grew one here would be a
/// second retention site whatever it did with the result.
fn list_terms<'source>(
    list: Node<'_>,
    source: &'source str,
    declaration: u32,
    role: GoSignatureRole,
) -> Vec<GoSignatureTermFact<'source>> {
    let mut cursor = list.walk();
    named_nodes(list, &mut cursor)
        .filter_map(|held| variadic_form(held).map(|variadic| (held, variadic)))
        .flat_map(|(held, variadic)| repeated(held, source, variadic))
        .enumerate()
        .map(|(position, (written, variadic))| {
            let counted = u32::try_from(position).unwrap_or(u32::MAX);
            term(declaration, (role, counted), written, variadic)
        })
        .collect()
}

/// The written type one parameter declaration states, once per name it binds.
///
/// The type is read once and repeated, because `a, b int` is two parameters of
/// one type and the type is the same `Copy` value both times. A declaration
/// binding no name still states one, so the arity a source wrote survives.
fn repeated<'source>(
    declared: Node<'_>,
    source: &'source str,
    variadic: bool,
) -> impl Iterator<Item = (WrittenType<'source>, bool)> {
    let written = field_type(declared, "type", source);
    std::iter::repeat_n((written, variadic), name_count(declared).max(1))
}

/// Whether one list member declares parameters, and whether it is the variadic
/// one.
fn variadic_form(declared: Node<'_>) -> Option<bool> {
    match declared.kind() {
        "parameter_declaration" => Some(false),
        "variadic_parameter_declaration" => Some(true),
        _ => None,
    }
}

/// One term of one callable's signature.
fn term<'source>(
    declaration: u32,
    stated: (GoSignatureRole, u32),
    written: WrittenType<'source>,
    variadic: bool,
) -> GoSignatureTermFact<'source> {
    let (role, position) = stated;
    GoSignatureTermFact {
        declaration,
        role,
        position,
        written,
        variadic,
    }
}
