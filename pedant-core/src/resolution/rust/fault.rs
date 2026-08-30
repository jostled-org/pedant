//! Why a source provider states no Rust record for a normalized path.
//!
//! The physical refusals, in the one vocabulary every Rust provider answers in.
//! A provider owns the read, the decode, and the parse, so it owns their
//! failures; the snapshot that asked owns the closure site those failures are
//! reported against, and turns each of these into the typed
//! [`SourceClosureFailure`](super::SourceClosureFailure) its own seam publishes.
//!
//! Each ceiling variant carries the ceiling that refused rather than naming a
//! field, because the provider's ceilings and the asking snapshot's are allowed
//! to differ: a message that named the asker's number for the provider's
//! refusal would state a limit nothing checked.
//!
//! The displayed sentence is this fault's own summary. Where a variant already
//! carries a path it names it; where it does not, the seam that asked owns the
//! path, and the sentence it builds around this one stays where it is.

use crate::resolution::read::ReadFault;

use super::limits::ResolutionLimits;

/// One physical reason a Rust source did not become a record.
#[derive(Debug, thiserror::Error)]
pub enum RustSourceFault {
    /// The file could not be opened, or failed part-way through the read.
    #[error("the source could not be read: {0}")]
    Unreadable(#[source] std::io::Error),
    /// The path resolves outside the root the provider reads beneath.
    ///
    /// Both spellings, because neither answers alone: the request is what the
    /// caller wrote and can act on, while a request that escaped through a link
    /// is spelled inside the root and says nothing about where it went.
    #[error("{path} resolves outside the root the provider reads beneath, at {landing}")]
    OutOfRoot {
        /// The requested path that escaped.
        path: Box<str>,
        /// Where that request landed, after every link was followed.
        landing: Box<str>,
    },
    /// One more source would pass the provider's distinct-file ceiling.
    #[error("the provider already holds its ceiling of {ceiling} source files")]
    SourceFiles {
        /// The ceiling that refused.
        ceiling: u64,
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
    InvalidUtf8 {
        /// The refusal the decoder stated.
        reason: Box<str>,
    },
    /// The source nests deeper than the provider's ceiling admits.
    #[error("the source nests deeper than the provider's ceiling of {ceiling}")]
    SyntaxDepth {
        /// The ceiling that refused.
        ceiling: u64,
    },
    /// The source is not valid Rust, as the parser described it.
    #[error("the source is not valid Rust: {reason}")]
    Unparsed {
        /// The refusal the parser stated.
        reason: Box<str>,
    },
    /// The provider already refused this path once and did not read it again.
    ///
    /// Not the first refusal repeated: that one carried a moved `io::Error` or
    /// a parser's own sentence, and a provider that reconstructed either would
    /// be stating a reason nothing produced this time. What this says is
    /// exactly what happened — the path was refused before, and the second
    /// request cost no read.
    #[error("{path} was already refused by this provider")]
    Refused {
        /// The path whose first admission failed.
        path: Box<str>,
    },
}

impl RustSourceFault {
    /// This language's own name for one refused bounded read.
    ///
    /// One owner for both readers of the byte ceilings: the provider that reads
    /// a source for the first time, and the snapshot store holding a record some
    /// other snapshot already read to its own ceilings. Naming the refusal twice
    /// would let the two report different limits for one comparison.
    pub(crate) fn of_read(fault: ReadFault, limits: ResolutionLimits) -> Self {
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
