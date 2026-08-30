//! Why a source provider states no Go record for a normalized path.
//!
//! The physical refusals, in the one vocabulary every Go provider answers in. A
//! provider owns the read, the decode, the parse, and the fact walk, so it owns
//! their failures; the snapshot that asked names the path each is reported
//! against and turns it into the typed
//! [`GoSnapshotError`](super::GoSnapshotError) its own seam publishes.
//!
//! Each ceiling variant carries the ceiling that refused rather than naming a
//! field, because a provider's ceilings and the asking snapshot's are allowed
//! to differ: a message that named the asker's number for the provider's
//! refusal would state a limit nothing checked.
//!
//! The displayed sentence is this fault's own summary. Where a variant already
//! carries a path it names it; where it does not, the seam that asked owns the
//! path, and the sentence it builds around this one stays where it is.

use pedant_syntax::go::GoFactError;

use crate::resolution::read::ReadFault;

use super::limits::GoResolutionLimits;
use super::paths::PathFault;
use super::snapshot_error::GoSourceDefect;

/// One physical reason a Go source did not become a record.
#[derive(Debug, thiserror::Error)]
pub enum GoSourceFault {
    /// The file could not be opened, or failed part-way through the read.
    #[error("the source could not be read: {0}")]
    Unreadable(#[source] std::io::Error),
    /// The path resolves outside the root the provider reads beneath.
    ///
    /// The root is not carried. A provider states which path escaped; the seam
    /// that formats the refusal holds the root it was measured against, and a
    /// foreign provider that does not hold one would otherwise have to invent a
    /// placeholder for a field the message prints as fact.
    #[error("path {path} lies outside the provider's root")]
    OutOfRoot {
        /// The canonical path that escaped.
        path: Box<str>,
    },
    /// The path beneath the root has no UTF-8 spelling.
    #[error("path {path} beneath the provider's root is not valid UTF-8")]
    NonUtf8Path {
        /// The offending path, rendered lossily for the message only.
        path: Box<str>,
    },
    /// The path could not be resolved, so where it points is unknown.
    #[error("failed to resolve {path}: {source}")]
    PathRead {
        /// The path that could not be resolved.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// One more source would pass the provider's distinct-file ceiling.
    #[error("the provider already holds its ceiling of {ceiling} source files")]
    SourceFiles {
        /// The ceiling that refused.
        ceiling: u32,
    },
    /// The bytes that arrived exceed the provider's per-source ceiling.
    #[error("the source holds more than the provider's ceiling of {ceiling} bytes")]
    SourceBytes {
        /// The ceiling that refused.
        ceiling: u64,
    },
    /// The bytes would take the provider's running total past its ceiling.
    #[error("the source passes the provider's ceiling of {ceiling} total source bytes")]
    TotalBytes {
        /// The ceiling that refused.
        ceiling: u64,
    },
    /// The bytes are not valid UTF-8, as the decoder described it.
    #[error("the source is not valid UTF-8: {reason}")]
    NonUtf8 {
        /// The refusal the decoder stated, naming the offending byte.
        reason: Box<str>,
    },
    /// The source is not valid Go, as the parser described it.
    ///
    /// Distinct from [`Self::Incomplete`], which is this provider's own verdict
    /// on a tree it holds. This is a refusal a foreign provider's parser stated
    /// in its own words, and it must not be reported as a projection that
    /// refused when the grammar is what did.
    #[error("the source is not valid Go: {reason}")]
    Unparsed {
        /// The refusal the parser stated.
        reason: Box<str>,
    },
    /// The grammar stated no complete tree for the source.
    #[error("the source states no complete tree: {0}")]
    Incomplete(GoSourceDefect),
    /// The bounded fact walk refused before it completed.
    #[error("the bounded fact walk refused: {0}")]
    FactExtraction(#[source] GoFactError),
    /// The source declares no package clause, so it belongs to no package.
    #[error("the source states no package clause")]
    MissingPackageClause,
    /// The provider already refused this path once and did not read it again.
    ///
    /// Not the first refusal repeated: that one carried a moved `io::Error`, a
    /// parser's own sentence, or a bounded walk's refusal, and a provider that
    /// reconstructed any of them would be stating a reason nothing produced
    /// this time. What this says is exactly what happened — the path was
    /// refused before, and the second request cost no read.
    #[error("{path} was already refused by this provider")]
    Refused {
        /// The path whose first admission failed.
        path: Box<str>,
    },
    /// The structure projection over those facts refused before it completed.
    ///
    /// Carried as text rather than as the syntax crate's own refusal, because
    /// the projection reads facts this provider already admitted: what a caller
    /// needs is which source refused and why, not a second copy of a structure
    /// vocabulary the resolution seam never otherwise names.
    #[error("the source states no complete structure inventory: {reason}")]
    StructureProjection {
        /// The refusal the projection stated.
        reason: Box<str>,
    },
}

impl GoSourceFault {
    /// This language's own name for one refused bounded read.
    ///
    /// One owner for both readers of the byte ceilings: the provider that reads
    /// a source for the first time, and the snapshot store holding a record some
    /// other snapshot already read to its own ceilings. Naming the refusal twice
    /// would let the two report different limits for one comparison.
    pub(super) fn of_read(fault: ReadFault, limits: GoResolutionLimits) -> Self {
        match fault {
            ReadFault::Unreadable(source) => Self::Unreadable(source),
            ReadFault::SourceBytes => Self::SourceBytes {
                ceiling: limits.max_source_file_bytes,
            },
            ReadFault::TotalBytes => Self::TotalBytes {
                ceiling: limits.max_total_source_bytes,
            },
        }
    }
}

/// Every path refusal reads the same whichever stage asked, so the shared
/// answer is adapted here rather than restated at the provider.
///
/// The root a `PathFault` measured against is dropped: this fault states which
/// path escaped, and the seam that formats the refusal names its own root.
impl From<PathFault> for GoSourceFault {
    fn from(fault: PathFault) -> Self {
        match fault {
            PathFault::OutOfRoot { path, .. } => Self::OutOfRoot { path },
            PathFault::NonUtf8 { path } => Self::NonUtf8Path { path },
            PathFault::Unreadable { path, source } => Self::PathRead { path, source },
        }
    }
}
