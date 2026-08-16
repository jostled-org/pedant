//! One parse session, bound to the exact source that produced it.
//!
//! A session parses nothing. It holds the tree [`parse_bound`](super::parse_bound)
//! handed it beside the source string that tree indexes, and answers
//! declaration questions by delegating to the shared recognizer and the shared
//! checked source index. Binding the two together is the point: a caller cannot
//! pair a tree with a source it was not built from, so an anchor's byte
//! position always names the caller's own text.

use ::tree_sitter::Tree;

use crate::extract::select::UnitSelector;
use crate::extract::ts::offer_declarations;
use crate::language::SyntaxLanguage;
use crate::location::Location;
use crate::tree_sitter::Node;
use crate::unit::SourceUnitKind;

/// The narrowest declaration containing a location, without its text.
///
/// [`SourceUnit`](crate::SourceUnit) copies the declaration's bytes because its
/// caller wants to read them. An anchor names the declaration instead, so a
/// caller grouping many findings by owner pays one small record per group
/// rather than one full declaration body per finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUnitAnchor {
    /// What kind of declaration contains the location.
    pub kind: SourceUnitKind,
    /// The declared name, when the grammar names the declaration.
    pub name: Option<Box<str>>,
    /// One-based position of the declaration's first byte. Its `column` is
    /// always present, because the position comes from a byte offset rather
    /// than from a caller's line reference.
    pub start: Location,
}

/// A parsed tree and the source it was parsed from.
///
/// Both fields are private and are only ever filled together, so the tree and
/// the string its node ranges index cannot drift apart. The `'source` lifetime
/// keeps the string alive for as long as the session can be asked about it.
pub struct ParsedSyntax<'source> {
    source: &'source str,
    language: SyntaxLanguage,
    tree: Tree,
}

impl<'source> ParsedSyntax<'source> {
    /// Bind one freshly parsed tree to the source that produced it.
    ///
    /// Visible to the parser module alone, which is the only place a tree comes
    /// from, so no other code can assemble a mismatched pair.
    pub(super) fn bind(source: &'source str, language: SyntaxLanguage, tree: Tree) -> Self {
        Self {
            source,
            language,
            tree,
        }
    }

    /// The parsed tree's root node.
    pub fn root(&self) -> Node<'_> {
        self.tree.root_node()
    }

    /// Whether the parser recovered from at least one syntax error.
    ///
    /// A recovery tree is still a tree and still holds recognizable nodes, so
    /// this is a caller's question rather than an absence at
    /// [`parse_bound`](super::parse_bound).
    pub fn has_errors(&self) -> bool {
        self.tree.root_node().has_error()
    }

    /// The narrowest recognized declaration containing `at`.
    ///
    /// Parses nothing: the bound tree, the shared declaration recognizer, and
    /// the shared checked source index answer between them.
    ///
    /// Returns `None` when the tree carries errors, when `at` is not
    /// addressable — a zero line or column, a line past the source, a column
    /// past its line, or a column inside a UTF-8 code point — when no
    /// recognized declaration contains it, and when the winning declaration
    /// opens at a byte offset the source does not hold.
    pub fn enclosing_unit_anchor(&self, at: Location) -> Option<SourceUnitAnchor> {
        let root = self.tree.root_node();
        if root.has_error() {
            return None;
        }
        let mut selector = UnitSelector::new(self.source, at)?;
        offer_declarations(root, self.source, self.language, &mut selector);
        selector.finish_anchor()
    }
}
