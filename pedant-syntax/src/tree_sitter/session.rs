//! One parse session, bound to the exact source that produced it.
//!
//! A session parses nothing. It holds the tree [`parse_bound`](super::parse_bound)
//! handed it beside the source string that tree indexes, and answers
//! declaration questions by delegating to the shared recognizer and the shared
//! checked source index. Binding the two together is the point: a caller cannot
//! pair a tree with a source it was not built from, so an anchor's byte
//! position always names the caller's own text.
//!
//! The batch answer is the primary one. A caller asking about many locations in
//! one source asks once: the session indexes that source once and walks the
//! tree once, and the selector keeps a narrowest declaration per location. The
//! single-location answer is one slot of the same call, so there is one
//! selection rule here rather than a batch rule beside a single one.

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

    /// The narrowest recognized declaration containing each location in `at`,
    /// answered in one pass and returned in the caller's order.
    ///
    /// Parses nothing: the bound tree, the shared declaration recognizer, and
    /// the shared checked source index answer between them. One call indexes
    /// the source once and walks the tree once, whatever `at`'s length, so a
    /// caller grouping many findings by owner pays for one scan and one walk
    /// rather than one of each per finding.
    ///
    /// A slot is `None` when its location is not addressable — a zero line or
    /// column, a line past the source, a column past its line, or a column
    /// inside a UTF-8 code point — when no recognized declaration contains it,
    /// and when the winning declaration opens at a byte offset the source does
    /// not hold. Every slot is `None` when the tree carries errors, because a
    /// recovery tree states no complete declaration inventory to select from,
    /// and every slot is `None` when the backend refuses.
    ///
    /// A Go session answers through [`GoFileFacts`](crate::go::GoFileFacts),
    /// which is the sole Go declaration index and states the whole selection
    /// rule for it. Restating that rule here is what let the two drift.
    pub fn enclosing_unit_anchors(&self, at: &[Location]) -> Box<[Option<SourceUnitAnchor>]> {
        #[cfg(feature = "ts-go")]
        if matches!(self.language, SyntaxLanguage::Go) {
            return self.go_anchors(at);
        }
        if self.has_errors() {
            return withheld(at);
        }
        let mut selector = UnitSelector::over(self.source, at);
        match offer_declarations(
            self.tree.root_node(),
            self.source,
            self.language,
            &mut selector,
        ) {
            Ok(()) => selector.finish_anchors(),
            Err(_) => withheld(at),
        }
    }

    /// The anchors the Go fact inventory answers.
    ///
    /// The recovery-tree rule travels inside the inventory rather than being
    /// asked here: `go_file_facts` hands it [`Self::has_errors`], and the
    /// inventory withholds every slot on a recovery tree. A refused extraction
    /// withholds every slot too — a walk that states no declaration set is not
    /// a file that declares nothing.
    #[cfg(feature = "ts-go")]
    fn go_anchors(&self, at: &[Location]) -> Box<[Option<SourceUnitAnchor>]> {
        match self.go_file_facts(crate::go::GoFactLimits::UNBOUNDED) {
            Ok(facts) => facts.enclosing_unit_anchors(at),
            Err(_) => withheld(at),
        }
    }

    /// Every structured Go grammar fact this session's source states.
    ///
    /// Walks the bound tree once and parses nothing. The bound grammar must be
    /// Go: a session of any other language states no Go fact and returns
    /// [`GoFactError::LanguageMismatch`](crate::go::GoFactError::LanguageMismatch),
    /// rather than an empty inventory a
    /// caller could read as "this Go file declares nothing".
    ///
    /// Both ceilings in `limits` refuse before the state they would pay for is
    /// retained, so a lowered ceiling returns an error and no inventory. The
    /// result carries the same recovery answer [`Self::has_errors`] gives, so a
    /// consumer that rejects incomplete source reads one value rather than
    /// pairing two.
    #[cfg(feature = "ts-go")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ts-go")))]
    pub fn go_file_facts(
        &self,
        limits: crate::go::GoFactLimits,
    ) -> Result<crate::go::GoFileFacts<'source>, crate::go::GoFactError> {
        match self.language {
            SyntaxLanguage::Go => crate::go::GoFileFacts::extract(
                self.tree.root_node(),
                self.source,
                self.has_errors(),
                limits,
            ),
            language => Err(crate::go::GoFactError::LanguageMismatch { language }),
        }
    }

    /// The narrowest recognized declaration containing `at`.
    ///
    /// One slot of [`Self::enclosing_unit_anchors`], which owns the whole
    /// route: which backend answers, the error tree, the unaddressable
    /// location, the narrowest containing declaration, and the anchor
    /// conversion. Nothing about selection is stated twice, so the single
    /// answer and the batch answer cannot drift.
    pub fn enclosing_unit_anchor(&self, at: Location) -> Option<SourceUnitAnchor> {
        self.enclosing_unit_anchors(std::slice::from_ref(&at))
            .into_iter()
            .next()
            .flatten()
    }
}

/// One withheld slot per location the caller asked about.
///
/// The one spelling of "this session states no declaration set to select from",
/// so a recovery tree and a refused backend answer identically rather than by
/// two separate constructions.
fn withheld(at: &[Location]) -> Box<[Option<SourceUnitAnchor>]> {
    at.iter().map(|_| None).collect()
}
