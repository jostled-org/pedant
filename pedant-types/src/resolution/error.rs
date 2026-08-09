//! Every refusal the resolution report contract produces.
//!
//! One error type covers both writer boundaries — the builder and custom
//! deserialization — because both reach the same validator, and a consumer
//! comparing a builder refusal with a wire refusal should compare one value.

use std::fmt;

use thiserror::Error;

use crate::Language;

use super::ResolutionGap;

/// Which report collection a structural rule names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportCollection {
    /// The report's resolution units.
    Units,
    /// The report's symbol definitions.
    Definitions,
    /// The report's symbol references.
    References,
    /// The report's resolution records.
    Resolutions,
}

impl fmt::Display for ReportCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Units => "units",
            Self::Definitions => "definitions",
            Self::References => "references",
            Self::Resolutions => "resolutions",
        })
    }
}

/// A rejected resolution report, or a rejected write into one.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResolutionReportError {
    /// A unit handle another builder issued.
    #[error("the unit handle belongs to another builder")]
    ForeignUnitHandle,
    /// A definition handle another builder issued.
    #[error("the definition handle belongs to another builder")]
    ForeignDefinitionHandle,
    /// A reference handle another builder issued.
    #[error("the reference handle belongs to another builder")]
    ForeignReferenceHandle,
    /// The configured or fixed-width unit capacity is reached.
    #[error("the report already holds its limit of {limit} units")]
    UnitCapacityExceeded {
        /// The capacity that refused the insertion.
        limit: u32,
    },
    /// The configured or fixed-width definition capacity is reached.
    #[error("the report already holds its limit of {limit} definitions")]
    DefinitionCapacityExceeded {
        /// The capacity that refused the insertion.
        limit: u32,
    },
    /// The configured or fixed-width reference capacity is reached.
    #[error("the report already holds its limit of {limit} references")]
    ReferenceCapacityExceeded {
        /// The capacity that refused the insertion.
        limit: u32,
    },
    /// The configured or fixed-width resolution-record capacity is reached.
    ///
    /// A document may state more records than it states references, so this
    /// ceiling is reached by a decoded report rather than by a writer.
    #[error("the report already holds its limit of {limit} resolution records")]
    ResolutionCapacityExceeded {
        /// The capacity that refused the record.
        limit: u32,
    },
    /// More than one record names one reference.
    #[error("reference {reference} already carries a resolution record")]
    DuplicateResolution {
        /// The reference named twice.
        reference: u32,
    },
    /// A definition or reference names a unit the report does not contain.
    #[error("unit {unit} is not in the report")]
    UnknownUnit {
        /// The absent unit identifier.
        unit: u32,
    },
    /// A parent, enclosing definition, or candidate names an absent definition.
    #[error("definition {definition} is not in the report")]
    UnknownDefinition {
        /// The absent definition identifier.
        definition: u32,
    },
    /// A record names a reference the report does not contain.
    #[error("reference {reference} is not in the report")]
    UnknownReference {
        /// The absent reference identifier.
        reference: u32,
    },
    /// An identifier does not equal its own sorted slice position.
    #[error("{collection} position {position} carries identifier {id}")]
    NonDenseId {
        /// The collection holding the entry.
        collection: ReportCollection,
        /// The entry's position in the collection.
        position: u32,
        /// The identifier the entry carried.
        id: u32,
    },
    /// A collection is not in its stable structural order.
    #[error("{collection} position {position} breaks the structural order")]
    UnsortedEntries {
        /// The collection holding the entry.
        collection: ReportCollection,
        /// The position that follows a greater predecessor.
        position: u32,
    },
    /// Two units share one stable key.
    #[error("two units share the key `{key}`")]
    DuplicateUnitKey {
        /// The repeated key.
        key: Box<str>,
    },
    /// A definition or reference contradicts its unit's language.
    ///
    /// The offender is named by its own coordinates, so a bad definition and a
    /// bad reference at two positions never produce one value.
    #[error("{collection} position {position} claims {claimed:?} in {unit_language:?} unit {unit}")]
    UnitLanguageMismatch {
        /// The collection holding the offending record.
        collection: ReportCollection,
        /// The offender's position in that collection.
        position: u32,
        /// The unit whose language was contradicted.
        unit: u32,
        /// The language the record claimed.
        claimed: Language,
        /// The language the unit states.
        unit_language: Language,
    },
    /// A parent definition belongs to another unit.
    #[error("definition {definition} has parent {parent} from another unit")]
    ForeignParentDefinition {
        /// The child definition.
        definition: u32,
        /// The parent in the other unit.
        parent: u32,
    },
    /// An enclosing definition belongs to another unit.
    #[error("reference {reference} is enclosed by definition {enclosing} from another unit")]
    ForeignEnclosingDefinition {
        /// The reference.
        reference: u32,
        /// The enclosing definition in the other unit.
        enclosing: u32,
    },
    /// The definition-parent relation contains a cycle.
    #[error("definition {definition} is its own ancestor")]
    DefinitionParentCycle {
        /// A definition on the cycle.
        definition: u32,
    },
    /// A reference carries no resolution record.
    #[error("reference {reference} carries no resolution record")]
    MissingResolution {
        /// The unrecorded reference.
        reference: u32,
    },
    /// One record names one definition twice.
    #[error("reference {reference} names candidate definition {definition} twice")]
    DuplicateCandidate {
        /// The record's reference.
        reference: u32,
        /// The repeated candidate definition.
        definition: u32,
    },
    /// A record's candidates are out of order.
    #[error("reference {reference} carries candidates out of order at position {position}")]
    UnsortedCandidates {
        /// The record's reference.
        reference: u32,
        /// The position that follows a greater predecessor.
        position: u32,
    },
    /// One record names one gap twice.
    #[error("reference {reference} names the gap {gap:?} twice")]
    DuplicateGap {
        /// The record's reference.
        reference: u32,
        /// The repeated gap.
        gap: ResolutionGap,
    },
    /// A record's gaps are out of order.
    #[error("reference {reference} carries gaps out of order at position {position}")]
    UnsortedGaps {
        /// The record's reference.
        reference: u32,
        /// The position that follows a greater predecessor.
        position: u32,
    },
    /// A record mixes resolved and possible candidates.
    #[error("reference {reference} mixes resolved and possible candidates")]
    MixedCandidateCertainty {
        /// The record's reference.
        reference: u32,
    },
    /// A resolved record does not name exactly one definition.
    #[error("reference {reference} is resolved to {candidates} candidates")]
    ResolvedCandidateCount {
        /// The record's reference.
        reference: u32,
        /// How many candidates the record carried.
        candidates: u32,
    },
    /// A resolved record carries a gap.
    #[error("reference {reference} is resolved and still carries a gap")]
    ResolvedWithGaps {
        /// The record's reference.
        reference: u32,
    },
    /// A candidate-free record carries no gap.
    #[error("reference {reference} has neither a candidate nor a gap")]
    EmptyResolution {
        /// The record's reference.
        reference: u32,
    },
    /// A span names a path that is not normalized repository-relative.
    #[error("`{path}` is not a normalized repository-relative path")]
    InvalidSourcePath {
        /// The rejected path.
        path: Box<str>,
    },
    /// A span ends before it starts.
    #[error("a span in `{path}` ends before it starts")]
    ReversedSiteSpan {
        /// The span's path.
        path: Box<str>,
    },
    /// A span covers no source.
    #[error("a span in `{path}` is zero width")]
    EmptySiteSpan {
        /// The span's path.
        path: Box<str>,
    },
}
