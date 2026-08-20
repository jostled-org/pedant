//! The named type a Go source writes, split into the parts a reader needs.
//!
//! One owner, because the same grammar shape is read in three places: the type
//! a binding declares, the type a function declares as its single result, and
//! the type a short variable declaration's initializer names. A second copy of
//! this recognizer would be a second Go grammar mapping.

use crate::go::context::{field_text, text};
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

/// The type one node's named field writes, if it writes one.
pub(super) fn field_type<'source>(
    node: Node<'_>,
    field: &str,
    source: &'source str,
) -> WrittenType<'source> {
    node.child_by_field_name(field)
        .map(|declared| type_parts(declared, source, false))
        .unwrap_or_default()
}

/// One written type split into its qualifier, its name, and its pointer form.
///
/// A shape this recognizer has no arm for — a parameter list stating several
/// results, a map, a slice, a channel — names no single type, so it answers
/// with no name rather than with a guess.
pub(super) fn type_parts<'source>(
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
