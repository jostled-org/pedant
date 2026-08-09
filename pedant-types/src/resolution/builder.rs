//! The one cross-crate writer for resolution reports.
//!
//! A writer states facts and receives handles; identifiers, ordering, and
//! validation belong to [`ResolutionReportBuilder::finish`]. An unvalidated
//! report is therefore unrepresentable outside this crate.

use std::sync::Arc;

use crate::Language;

use super::definition::SymbolKind;
use super::error::ResolutionReportError;
use super::finish::assemble;
use super::handle::{
    BuilderBrand, CandidateInput, DefinitionHandle, ReferenceHandle, ResolutionUnitHandle,
};
use super::record::{ResolutionCertainty, ResolutionGap};
use super::reference::ReferenceKind;
use super::report::{ResolutionReport, ResolutionTier};
use super::span::SourceSpan;

/// How many units, definitions, references, and resolution records one report
/// may contain.
///
/// The default is the fixed-width identifier ceiling, so on the writer path the
/// configured limit and the ceiling are enforced by the same check rather than
/// by two rules that can disagree. Callers may apply the same limits while
/// decoding through [`ResolutionReport::deserialize_with_limits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolutionReportLimits {
    /// Maximum number of resolution units.
    pub max_units: u32,
    /// Maximum number of definitions.
    pub max_definitions: u32,
    /// Maximum number of references.
    ///
    /// Decoding applies the same ceiling to resolution records because a valid
    /// report carries exactly one record per reference.
    pub max_references: u32,
}

impl Default for ResolutionReportLimits {
    fn default() -> Self {
        Self {
            max_units: u32::MAX,
            max_definitions: u32::MAX,
            max_references: u32::MAX,
        }
    }
}

impl ResolutionReportLimits {
    /// The index the next unit would take, or the capacity refusal.
    pub fn admit_unit(&self, count: usize) -> Result<u32, ResolutionReportError> {
        admit(count, self.max_units, |limit| {
            ResolutionReportError::UnitCapacityExceeded { limit }
        })
    }

    /// The index the next definition would take, or the capacity refusal.
    pub fn admit_definition(&self, count: usize) -> Result<u32, ResolutionReportError> {
        admit(count, self.max_definitions, |limit| {
            ResolutionReportError::DefinitionCapacityExceeded { limit }
        })
    }

    /// The index the next reference would take, or the capacity refusal.
    pub fn admit_reference(&self, count: usize) -> Result<u32, ResolutionReportError> {
        admit(count, self.max_references, |limit| {
            ResolutionReportError::ReferenceCapacityExceeded { limit }
        })
    }
}

/// The one capacity rule: `count` entries admit index `count` while it is both
/// representable and below the limit.
fn admit(
    count: usize,
    limit: u32,
    exceeded: impl Fn(u32) -> ResolutionReportError,
) -> Result<u32, ResolutionReportError> {
    u32::try_from(count)
        .ok()
        .filter(|next| *next < limit)
        .ok_or_else(|| exceeded(limit))
}

/// A unit a writer has stated but that has no identifier yet.
pub(crate) struct DraftUnit {
    pub(crate) language: Language,
    pub(crate) key: Arc<str>,
    pub(crate) name: Arc<str>,
}

/// A definition a writer has stated, pointing at drafts by local index.
pub(crate) struct DraftDefinition {
    pub(crate) unit: u32,
    pub(crate) kind: SymbolKind,
    pub(crate) name: Arc<str>,
    pub(crate) span: SourceSpan,
    pub(crate) parent: Option<u32>,
}

/// A reference a writer has stated, pointing at drafts by local index.
pub(crate) struct DraftReference {
    pub(crate) unit: u32,
    pub(crate) kind: ReferenceKind,
    pub(crate) text: Arc<str>,
    pub(crate) span: SourceSpan,
    pub(crate) enclosing: Option<u32>,
}

/// One reference's answer, pointing at draft definitions by local index.
pub(crate) struct DraftResolution {
    pub(crate) candidates: Box<[(u32, ResolutionCertainty)]>,
    pub(crate) gaps: Box<[ResolutionGap]>,
}

/// The fallible writer every report passes through.
pub struct ResolutionReportBuilder {
    brand: Arc<BuilderBrand>,
    tier: ResolutionTier,
    limits: ResolutionReportLimits,
    units: Vec<DraftUnit>,
    definitions: Vec<DraftDefinition>,
    references: Vec<DraftReference>,
    resolutions: Vec<Option<DraftResolution>>,
}

impl ResolutionReportBuilder {
    /// An empty builder for one tier under one set of limits.
    pub fn new(tier: ResolutionTier, limits: ResolutionReportLimits) -> Self {
        Self {
            brand: Arc::new(BuilderBrand),
            tier,
            limits,
            units: Vec::new(),
            definitions: Vec::new(),
            references: Vec::new(),
            resolutions: Vec::new(),
        }
    }

    /// State one resolution unit.
    pub fn add_unit(
        &mut self,
        language: Language,
        key: Arc<str>,
        name: Arc<str>,
    ) -> Result<ResolutionUnitHandle, ResolutionReportError> {
        let index = self.limits.admit_unit(self.units.len())?;
        self.units.push(DraftUnit {
            language,
            key,
            name,
        });
        Ok(ResolutionUnitHandle::new(&self.brand, index))
    }

    /// State one definition inside a unit this builder issued.
    pub fn add_definition(
        &mut self,
        unit: &ResolutionUnitHandle,
        kind: SymbolKind,
        name: Arc<str>,
        span: SourceSpan,
        parent: Option<&DefinitionHandle>,
    ) -> Result<DefinitionHandle, ResolutionReportError> {
        let unit = self.local_unit(unit)?;
        let parent = self.local_definition_option(parent)?;
        let index = self.limits.admit_definition(self.definitions.len())?;
        self.definitions.push(DraftDefinition {
            unit,
            kind,
            name,
            span,
            parent,
        });
        Ok(DefinitionHandle::new(&self.brand, index))
    }

    /// State one reference inside a unit this builder issued.
    pub fn add_reference(
        &mut self,
        unit: &ResolutionUnitHandle,
        kind: ReferenceKind,
        text: Arc<str>,
        span: SourceSpan,
        enclosing_definition: Option<&DefinitionHandle>,
    ) -> Result<ReferenceHandle, ResolutionReportError> {
        let unit = self.local_unit(unit)?;
        let enclosing = self.local_definition_option(enclosing_definition)?;
        let index = self.limits.admit_reference(self.references.len())?;
        self.references.push(DraftReference {
            unit,
            kind,
            text,
            span,
            enclosing,
        });
        self.resolutions.push(None);
        Ok(ReferenceHandle::new(&self.brand, index))
    }

    /// State the answer for one reference this builder issued.
    pub fn set_resolution(
        &mut self,
        reference: &ReferenceHandle,
        candidates: Box<[CandidateInput]>,
        gaps: Box<[ResolutionGap]>,
    ) -> Result<(), ResolutionReportError> {
        let index = reference
            .resolve(&self.brand)
            .ok_or(ResolutionReportError::ForeignReferenceHandle)?;
        let stated = candidates
            .into_vec()
            .into_iter()
            .map(|candidate| {
                let (definition, certainty) = candidate.into_parts();
                self.local_definition(&definition)
                    .map(|definition| (definition, certainty))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slot = self
            .resolutions
            .get_mut(index as usize)
            .ok_or(ResolutionReportError::ForeignReferenceHandle)?;
        match slot.is_some() {
            true => Err(ResolutionReportError::DuplicateResolution { reference: index }),
            false => {
                *slot = Some(DraftResolution {
                    candidates: stated.into_boxed_slice(),
                    gaps,
                });
                Ok(())
            }
        }
    }

    /// Sort, assign identifiers, validate, and return the report.
    ///
    /// The drafts move into the report: a writer that has finished stating
    /// facts owns nothing the report needs to copy.
    pub fn finish(self) -> Result<ResolutionReport, ResolutionReportError> {
        assemble(
            self.tier,
            self.units,
            self.definitions,
            self.references,
            self.resolutions,
        )
    }

    fn local_unit(&self, unit: &ResolutionUnitHandle) -> Result<u32, ResolutionReportError> {
        unit.resolve(&self.brand)
            .ok_or(ResolutionReportError::ForeignUnitHandle)
    }

    fn local_definition(
        &self,
        definition: &DefinitionHandle,
    ) -> Result<u32, ResolutionReportError> {
        definition
            .resolve(&self.brand)
            .ok_or(ResolutionReportError::ForeignDefinitionHandle)
    }

    fn local_definition_option(
        &self,
        definition: Option<&DefinitionHandle>,
    ) -> Result<Option<u32>, ResolutionReportError> {
        definition
            .map(|handle| self.local_definition(handle))
            .transpose()
    }
}
