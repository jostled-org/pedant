//! The validated result one resolution run produces.

use serde::{Deserialize, Deserializer, Serialize};

use super::builder::ResolutionReportLimits;
use super::definition::SymbolDefinition;
use super::record::ResolutionRecord;
use super::reference::SymbolReference;
use super::unit::ResolutionUnit;

/// Which mechanism produced a report.
///
/// Data-flow analysis is not a resolution tier.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionTier {
    /// Parse-only resolution.
    Syntactic,
    /// Resolution promoted through a verified semantic database.
    Semantic,
}

/// A complete, validated resolution result.
///
/// Every value of this type has passed the shared validator, whether it came
/// from [`super::ResolutionReportBuilder::finish`] or from deserialization, so
/// a consumer may read the slices positionally: an identifier is its own index.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ResolutionReport {
    tier: ResolutionTier,
    units: Box<[ResolutionUnit]>,
    definitions: Box<[SymbolDefinition]>,
    references: Box<[SymbolReference]>,
    resolutions: Box<[ResolutionRecord]>,
}

impl ResolutionReport {
    /// Deserialize one report while bounding every retained top-level record.
    ///
    /// Resolution records share `limits.max_references`: a validated report
    /// carries exactly one record per reference. Ordinary [`Deserialize`]
    /// delegates here with [`ResolutionReportLimits::default`].
    pub fn deserialize_with_limits<'de, D>(
        deserializer: D,
        limits: ResolutionReportLimits,
    ) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::wire::deserialize_with_limits(deserializer, limits)
    }

    pub(crate) fn new(
        tier: ResolutionTier,
        units: Box<[ResolutionUnit]>,
        definitions: Box<[SymbolDefinition]>,
        references: Box<[SymbolReference]>,
        resolutions: Box<[ResolutionRecord]>,
    ) -> Self {
        Self {
            tier,
            units,
            definitions,
            references,
            resolutions,
        }
    }

    /// Which mechanism produced this report.
    pub fn tier(&self) -> ResolutionTier {
        self.tier
    }

    /// The report's units, sorted by their stable key.
    pub fn units(&self) -> &[ResolutionUnit] {
        &self.units
    }

    /// The report's definitions, sorted by unit, span, kind, and name.
    pub fn definitions(&self) -> &[SymbolDefinition] {
        &self.definitions
    }

    /// The report's references, sorted by unit, span, kind, and text.
    pub fn references(&self) -> &[SymbolReference] {
        &self.references
    }

    /// One record per reference, in reference order.
    pub fn resolutions(&self) -> &[ResolutionRecord] {
        &self.resolutions
    }
}
