//! Where one analysis reads the declarations its findings sit in.
//!
//! Two things can answer: a bound parse session, which walks its tree, and a Go
//! fact inventory, which already holds every Go declaration. Naming the answer
//! rather than the answerer is what keeps the projection single: it asks one
//! question of whatever its backend handed over, and no backend needs a
//! projection of its own.

use pedant_syntax::Location;
use pedant_syntax::tree_sitter::{ParsedSyntax, SourceUnitAnchor};

/// What can say which declaration holds a location.
pub(crate) trait DeclarationAnchors {
    /// Whether the parse behind this authority recovered from an error.
    ///
    /// A recovery tree states no complete declaration inventory, so its
    /// findings stay flat and attribution does not run.
    fn has_errors(&self) -> bool;

    /// The narrowest declaration containing each location, in caller order.
    ///
    /// One batch question, so a source is indexed once and read once for a
    /// whole file rather than once per finding.
    fn anchors(&self, at: &[Location]) -> Box<[Option<SourceUnitAnchor>]>;
}

impl DeclarationAnchors for ParsedSyntax<'_> {
    fn has_errors(&self) -> bool {
        ParsedSyntax::has_errors(self)
    }

    fn anchors(&self, at: &[Location]) -> Box<[Option<SourceUnitAnchor>]> {
        self.enclosing_unit_anchors(at)
    }
}

/// Go answers from the inventory its analysis already extracted, so the same
/// source is neither parsed nor walked for declarations a second time.
#[cfg(feature = "ts-go")]
impl DeclarationAnchors for pedant_syntax::go::GoFileFacts<'_> {
    fn has_errors(&self) -> bool {
        pedant_syntax::go::GoFileFacts::has_errors(self)
    }

    fn anchors(&self, at: &[Location]) -> Box<[Option<SourceUnitAnchor>]> {
        self.enclosing_unit_anchors(at)
    }
}
