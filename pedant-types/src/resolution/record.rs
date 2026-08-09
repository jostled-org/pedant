//! What one reference resolved to, and what stopped it from resolving.

use serde::{Deserialize, Serialize};

use super::id::{DefinitionId, ReferenceId};

/// How much a candidate is known.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionCertainty {
    /// Language rules identify this one definition without inference.
    Resolved,
    /// Source evidence identifies the definition, but conditional compilation,
    /// dispatch, or incomplete type knowledge prevents proof.
    Possible,
}

/// Why a reference did not resolve, or resolved only to possibilities.
///
/// Filesystem closure failures are errors before a report exists, so they are
/// not gaps.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionGap {
    /// The target is outside the indexed corpus.
    ExternalDefinition,
    /// The target is chosen at run time.
    DynamicDispatch,
    /// The target would come from an expansion this tier does not perform.
    MacroExpansion,
    /// The corpus contains no matching definition.
    MissingDefinition,
    /// The reference form is not one this tier resolves.
    UnsupportedSyntax,
    /// Conditional compilation leaves the active universe unknown.
    ConditionalCompilation,
    /// More than one definition matches and none is provably the target.
    Ambiguous,
}

/// One definition a reference may denote.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolutionCandidate {
    definition: DefinitionId,
    certainty: ResolutionCertainty,
}

impl ResolutionCandidate {
    pub(crate) fn new(definition: DefinitionId, certainty: ResolutionCertainty) -> Self {
        Self {
            definition,
            certainty,
        }
    }

    /// The candidate definition.
    pub fn definition(&self) -> DefinitionId {
        self.definition
    }

    /// How much this candidate is known.
    pub fn certainty(&self) -> ResolutionCertainty {
        self.certainty
    }
}

/// The complete answer for one reference.
///
/// A record either names one resolved definition and no gap, names one or more
/// possible definitions, or names no definition and at least one gap.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRecord {
    reference: ReferenceId,
    candidates: Box<[ResolutionCandidate]>,
    gaps: Box<[ResolutionGap]>,
}

impl ResolutionRecord {
    pub(crate) fn new(
        reference: ReferenceId,
        candidates: Box<[ResolutionCandidate]>,
        gaps: Box<[ResolutionGap]>,
    ) -> Self {
        Self {
            reference,
            candidates,
            gaps,
        }
    }

    /// The reference this record answers.
    pub fn reference(&self) -> ReferenceId {
        self.reference
    }

    /// The definitions this reference may denote, in definition order.
    pub fn candidates(&self) -> &[ResolutionCandidate] {
        &self.candidates
    }

    /// Why the answer is incomplete, in gap order.
    pub fn gaps(&self) -> &[ResolutionGap] {
        &self.gaps
    }
}
