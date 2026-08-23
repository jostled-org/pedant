//! Typed failures returned while resolving a snapshot into a report.

use pedant_types::{ReferenceKind, ResolutionReportError, SymbolKind};

use crate::resolution::rust::warning::RustResolutionWarning;

/// Failure encountered while turning a resolution snapshot into a validated,
/// snapshot-bound report.
#[derive(Debug, thiserror::Error)]
pub enum RustResolutionError {
    /// The report's units do not describe this snapshot's units.
    #[error("report unit {unit} does not describe this snapshot: {reason}")]
    UnitMapping {
        /// The report-local unit identifier that could not be bound.
        unit: u32,
        /// Why the unit does not describe a snapshot unit.
        reason: Box<str>,
    },
    /// The report and the snapshot state different numbers of units.
    ///
    /// Its own variant rather than a [`Self::UnitMapping`] refusal, because no
    /// report-local unit identifier is the one that failed: the two sides
    /// disagree about how many units there are before any key is compared, and
    /// reporting a count where an identifier is documented reads as a unit that
    /// exists.
    #[error("the report states {report} units and this snapshot holds {snapshot}")]
    UnitCountMismatch {
        /// How many units the report states.
        report: u32,
        /// How many units the snapshot holds.
        snapshot: u32,
    },
    /// A site names a file this snapshot does not hold.
    #[error("{file} is not a source of this snapshot")]
    UnknownFile {
        /// The repository-relative path the site named.
        file: Box<str>,
    },
    /// A report definition states a kind no Rust resolution emits.
    ///
    /// The shared report vocabulary is one closed set for every language it
    /// carries. A Rust resolution states the Rust subset of it, and a report
    /// naming another language's kind describes something this snapshot's
    /// sources cannot declare.
    #[error("definition {definition} states {kind:?}, which no Rust resolution emits")]
    UnsupportedDefinitionKind {
        /// The report-local definition identifier that states it.
        definition: u32,
        /// The kind outside the Rust subset.
        kind: SymbolKind,
    },
    /// A report reference states a kind no Rust resolution emits.
    #[error("reference {reference} states {kind:?}, which no Rust resolution emits")]
    UnsupportedReferenceKind {
        /// The report-local reference identifier that states it.
        reference: u32,
        /// The kind outside the Rust subset.
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
    LimitExceeded {
        /// The configured candidate ceiling.
        limit: u32,
    },
    /// The names `use` items bind did not settle within the bounded rounds.
    ///
    /// Each round strictly adds, so a re-export chain shallower than the bound
    /// always settles. A chain deeper than it refuses the whole resolution
    /// rather than reporting the tail's unfilled bindings as names that do not
    /// exist.
    #[error("the names imports bind did not settle within {rounds} rounds")]
    ImportsNotConverged {
        /// The number of rounds the fixed point was given.
        rounds: u32,
    },
    /// The semantic database does not hold what the snapshot claims.
    ///
    /// Tier 2 never falls back: a database that holds other units, other
    /// sources, or other bytes answers for another repository state, so no
    /// candidate is promoted against it.
    #[error("the semantic database does not describe this snapshot: {reason}")]
    SemanticContextMismatch {
        /// Which identity disagrees, and how.
        reason: Box<str>,
    },
    /// One physical source belongs to multiple resolution units that the
    /// semantic database cannot distinguish.
    #[error("semantic resolution cannot represent this snapshot: {warning}")]
    SemanticSharedSourceMismatch {
        /// The project-level warning with the path, unit identities, and
        /// remediation.
        warning: RustResolutionWarning,
    },
    /// The report contract refused the stated facts.
    #[error(transparent)]
    Report(#[from] ResolutionReportError),
}
