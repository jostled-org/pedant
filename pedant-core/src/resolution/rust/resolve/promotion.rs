//! What a later tier proves about one reference.
//!
//! Tier 1 proves nothing beyond its own lookup, so it promotes nothing. Tier 2
//! answers for the sites a verified semantic database resolved and stays silent
//! about the rest, which leaves every other record exactly as Tier 1 wrote it.

use pedant_types::SourceSpan;

/// One reference, addressed the way both tiers can name it: the unit it was
/// written in, the snapshot source it sits in, and its report coordinates.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PromotionSite {
    /// The snapshot-local unit index.
    pub(super) unit: usize,
    /// The index of the source in the snapshot's sorted store.
    pub(super) file: usize,
    /// The zero-based line the reference starts at.
    pub(super) line: u32,
    /// The zero-based UTF-8 byte column the reference starts at.
    pub(super) column: u32,
}

impl PromotionSite {
    /// The site one unit's reference at `span` occupies.
    pub(super) fn new(unit: usize, file: usize, span: &SourceSpan) -> Self {
        Self {
            unit,
            file,
            line: span.start().line(),
            column: span.start().column(),
        }
    }
}

/// What a later tier proved one reference denotes.
pub(super) struct Promoted {
    /// The definition slots the tier proved, in slot order.
    pub(super) candidates: Box<[usize]>,
    /// Whether the candidates are one dispatch set rather than one proved
    /// definition, which keeps every candidate possible.
    pub(super) enumerated: bool,
}

/// A tier that may replace what Tier 1 wrote for one reference.
pub(super) trait Promotion {
    /// What this tier proves about the reference at `site`, if anything.
    fn promote(&self, site: PromotionSite) -> Option<Promoted>;
}

/// Tier 1 promotes nothing: its lookup is its whole answer.
pub(super) struct NoPromotion;

impl Promotion for NoPromotion {
    fn promote(&self, _site: PromotionSite) -> Option<Promoted> {
        None
    }
}
