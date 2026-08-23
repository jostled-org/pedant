//! Typed failures returned while resolving a Go snapshot into a report.

use pedant_types::{ReferenceKind, ResolutionReportError, SymbolKind};

/// Failure encountered while turning a Go resolution snapshot into a validated,
/// snapshot-bound report.
#[derive(Debug, thiserror::Error)]
pub enum GoResolutionError {
    /// The report's units do not describe this snapshot's package contexts.
    #[error("report unit {unit} does not describe this snapshot: {reason}")]
    UnitMapping {
        /// The report-local unit identifier that could not be bound.
        unit: u32,
        /// Why the unit does not describe a snapshot unit.
        reason: Box<str>,
    },
    /// A site names a definition position this resolution never recorded.
    ///
    /// Every candidate and every enclosing definition is a position the index
    /// answered for when it recorded it. A position it no longer answers for
    /// would drop a candidate the ceiling already counted, so the whole
    /// resolution refuses rather than stating a shorter answer than it proved.
    #[error("definition position {slot} is not recorded by this resolution: {reason}")]
    DefinitionMapping {
        /// The index-local position that could not be read.
        slot: u32,
        /// Why the position names no definition.
        reason: Box<str>,
    },
    /// A site names a file this snapshot does not hold.
    #[error("{file} is not a source of this snapshot")]
    UnknownFile {
        /// The repository-relative path the site named.
        file: Box<str>,
    },
    /// A report definition states a kind no Go resolution emits.
    ///
    /// The shared report vocabulary is one closed set for every language it
    /// carries. A Go resolution states the Go subset of it, and a report naming
    /// another language's kind describes something this snapshot's sources
    /// cannot declare.
    #[error("definition {definition} states {kind:?}, which no Go resolution emits")]
    UnsupportedDefinitionKind {
        /// The report-local definition identifier that states it.
        definition: u32,
        /// The kind outside the Go subset.
        kind: SymbolKind,
    },
    /// A report reference states a kind no Go resolution emits.
    #[error("reference {reference} states {kind:?}, which no Go resolution emits")]
    UnsupportedReferenceKind {
        /// The report-local reference identifier that states it.
        reference: u32,
        /// The kind outside the Go subset.
        kind: ReferenceKind,
    },
    /// A site's coordinate does not exist in the exact snapshotted source.
    #[error("{file}:{line}:{column} is not a coordinate of the snapshotted source")]
    InvalidCoordinate {
        /// The source the coordinate claimed to sit in.
        file: Box<str>,
        /// The zero-based line.
        line: u32,
        /// The zero-based UTF-8 byte column.
        column: u32,
    },
    /// One reference carries more candidates than the configured ceiling.
    ///
    /// Candidate fan-out is never truncated: an overflowing reference refuses
    /// the whole resolution rather than reporting a misleading complete answer.
    #[error("a reference carries more than {limit} candidates")]
    CandidateLimitExceeded {
        /// The configured candidate ceiling.
        limit: u32,
    },
    /// The corpus states more concrete-type-to-interface comparisons than the
    /// configured ceiling.
    ///
    /// Structural implementation is a whole-corpus question, so a comparison
    /// left unmade is a relation the report would omit without saying so. The
    /// resolution refuses instead.
    #[error("the corpus states more than {limit} interface comparisons")]
    InterfaceComparisonLimitExceeded {
        /// The configured comparison ceiling.
        limit: u32,
    },
    /// The report contract refused the stated facts.
    #[error(transparent)]
    Report(#[from] ResolutionReportError),
}
