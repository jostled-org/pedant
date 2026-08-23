//! The named type a Go source writes, split into the parts a reader needs.
//!
//! One owner, because the same grammar shape is read in five places: the type a
//! binding declares, the type a callable declares as its single result, the
//! type a short variable declaration's initializer names, the type a struct
//! field embeds, and the type an interface element embeds. A second copy of
//! this recognizer would be a second Go grammar mapping.

use crate::go::context::{name_count, named_nodes, text};
use crate::tree_sitter::Node;

/// One written type, as its source spells it.
///
/// A field group rather than three loose values, because the three answers are
/// only ever read together: a receiver's method set depends on the type's name,
/// its package qualifier, and whether it was written in pointer form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) struct WrittenType<'source> {
    pub(super) qualifier: Option<&'source str>,
    pub(super) name: Option<&'source str>,
    pub(super) pointer: bool,
}

/// One written type as its grammar states it, before any text is read.
///
/// Nodes rather than spellings, because two readers want different halves of
/// one answer: a retained fact keeps the text, and an embedded declaration is
/// named by the identifier itself. A reader that re-derived that identifier
/// would be the second grammar mapping this module exists to prevent.
///
/// A tree lifetime rather than the source one. A fact borrows the string and a
/// node borrows the tree, and only a bound session holds both, so this shape
/// stays inside the walk and never reaches a published fact.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ReadType<'tree> {
    /// The node naming the package a qualified type belongs to.
    pub(super) qualifier: Option<Node<'tree>>,
    /// The node naming the type itself, absent whenever the shape names no
    /// single type.
    pub(super) name: Option<Node<'tree>>,
    /// Whether the source wrote a pointer form.
    pub(super) pointer: bool,
}

impl<'tree> ReadType<'tree> {
    /// The same type, spelled the way `source` writes it.
    pub(super) fn written<'source>(self, source: &'source str) -> WrittenType<'source> {
        WrittenType {
            qualifier: self.qualifier.map(|node| text(node, source)),
            name: self.name.map(|node| text(node, source)),
            pointer: self.pointer,
        }
    }

    /// A shape this recognizer names no type for, keeping the form the source
    /// wrote.
    fn unnamed(pointer: bool) -> Self {
        Self {
            pointer,
            ..Default::default()
        }
    }
}

/// The type one node's named field writes, if it writes one.
pub(super) fn field_type<'source>(
    node: Node<'_>,
    field: &str,
    source: &'source str,
) -> WrittenType<'source> {
    node.child_by_field_name(field)
        .map(|declared| type_parts(declared, false).written(source))
        .unwrap_or_default()
}

/// The single type one callable declares as its result, if it declares one.
///
/// A callable writing a bare type states it directly. One writing `(sum int)`
/// or `(int)` writes a parameter list holding one declaration, and the type is
/// that declaration's own — the parenthesized form is the ordinary spelling of
/// a named result, and a reader that stopped at the list would name no type for
/// the most common single-result signature Go has. A list holding several
/// declarations, or one declaration binding several names, states several
/// results and therefore no single type.
pub(super) fn result_type<'source>(node: Node<'_>, source: &'source str) -> WrittenType<'source> {
    node.child_by_field_name("result")
        .and_then(sole_result)
        .map(|declared| type_parts(declared, false).written(source))
        .unwrap_or_default()
}

/// The node stating the sole type one `result` field writes.
fn sole_result<'tree>(result: Node<'tree>) -> Option<Node<'tree>> {
    match result.kind() {
        "parameter_list" => sole_parameter_type(result),
        _ => Some(result),
    }
}

/// The type the one parameter declaration in a list writes.
///
/// Absent for a list holding more than one declaration, for one holding
/// something other than a parameter declaration, and for one whose declaration
/// binds several names: `(a, b int)` states two results of one type, which is
/// no single result at all.
fn sole_parameter_type<'tree>(list: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = list.walk();
    let mut members = named_nodes(list, &mut cursor);
    let declared = members
        .next()
        .filter(|held| held.kind() == "parameter_declaration")?;
    match members.next().is_none() && name_count(declared) <= 1 {
        true => declared.child_by_field_name("type"),
        false => None,
    }
}

/// One written type split into the nodes that name it.
///
/// A shape this recognizer has no arm for — a map, a slice, a channel, a
/// function type, an anonymous composite — names no single type, so it answers
/// with no name rather than with a guess.
///
/// A loop rather than recursion. This runs inside the walk's `enter`, before
/// `descend` has paid the depth ceiling for the chain it is about to read, so a
/// recursive reader takes the stack down on `****…*T` beneath any ceiling at
/// all — including one set to four levels.
pub(super) fn type_parts<'tree>(declared: Node<'tree>, pointer: bool) -> ReadType<'tree> {
    let mut written = declared;
    let mut pointer = pointer;
    loop {
        let held = match written.kind() {
            "type_identifier" => {
                return ReadType {
                    qualifier: None,
                    name: Some(written),
                    pointer,
                };
            }
            "qualified_type" => {
                return ReadType {
                    qualifier: written.child_by_field_name("package"),
                    name: written.child_by_field_name("name"),
                    pointer,
                };
            }
            "pointer_type" => {
                pointer = true;
                written.named_child(0)
            }
            "generic_type" => written.child_by_field_name("type"),
            _ => return ReadType::unnamed(pointer),
        };
        let Some(held) = held else {
            return ReadType::unnamed(pointer);
        };
        written = held;
    }
}
