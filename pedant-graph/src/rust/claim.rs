//! The key one retained source-unit projection is selected by.
//!
//! Everything the key holds is stated by the snapshot and the plan: the
//! unit-qualified source identity a projection answers for, the digest of the
//! bytes it was derived from, the report tier, and the unit's own language and
//! container vocabulary. Nothing in it is read back out of a derived projection,
//! so a build knows which retained projection to ask for before it has derived
//! anything at all for that source.
//!
//! A digest identifies unchanged bytes, and unchanged bytes are not the whole
//! question: a definition added in another source changes what a reference in
//! this one resolves to, and that source is semantically changed for graph
//! projection even though nothing in it was edited. The key therefore selects
//! the one candidate a source could reuse, and the planner proves the complete
//! local claim against the current report before it reuses it.

use pedant_core::resolution::rust::RustResolutionSnapshot;
use pedant_types::{Language, ResolutionTier};

use crate::error::GraphBuildError;
use crate::node::GraphNodeKind;

use super::fragment::UnitPlan;
use super::identity::SourceIdentity;
use super::validation;

/// Everything one retained source-unit projection was derived under.
pub(crate) struct SourceKey {
    digest: [u8; 32],
    tier: ResolutionTier,
    language: Language,
    vocabulary: GraphNodeKind,
    source: SourceIdentity,
}

impl SourceKey {
    /// The key one placed source states, under the plan that placed it.
    pub(crate) fn stated(
        snapshot: &RustResolutionSnapshot,
        planned: (&[UnitPlan], u32),
        stated: (&SourceIdentity, ResolutionTier),
    ) -> Result<Self, GraphBuildError> {
        let (units, unit) = planned;
        let (source, tier) = stated;
        let plan = validation::planned_unit(units, unit)?;
        Ok(Self {
            digest: validation::source_digest(snapshot, unit, source.path())?,
            tier,
            language: plan.language,
            vocabulary: plan.kind.clone(),
            source: source.shared(),
        })
    }
}

/// Cheapest fields first: a differing digest decides the comparison before a
/// unit key or a normalized path is read.
impl PartialEq for SourceKey {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
            && self.tier == other.tier
            && self.language == other.language
            && self.vocabulary == other.vocabulary
            && self.source == other.source
    }
}
