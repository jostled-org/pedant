//! Reading one source's bytes under the two byte ceilings a snapshot owns.
//!
//! At most one byte past the per-source ceiling ever enters memory, and the
//! length both ceilings are compared against is the length that was actually
//! read. A separate stat could not state that, because a file may grow between
//! the stat and the read, and because the length a running total is charged
//! would then be a length nothing in this process ever held.
//!
//! One owner, because a second copy of this read would be a second answer to
//! "how many bytes may reach memory", and the language that kept the weaker
//! answer would be the one an oversized source arrived through.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The two byte ceilings one seam charges its sources against.
///
/// A trait rather than a shared limits struct, because each language publishes
/// its own ceilings under its own field names and these two are the whole of
/// what the byte rule reads. Every seam that charges bytes — the shared record
/// cache reading for the first time, and each language's snapshot store holding
/// a record a provider already read — asks through this, so a snapshot cannot
/// hold a source to a ceiling the read never applied.
pub(crate) trait ByteCeilings {
    /// The most bytes one source may itself hold.
    fn source_bytes(&self) -> u64;

    /// The most bytes every retained source may hold together.
    fn total_bytes(&self) -> u64;

    /// The bounds one seam reads under, given what it has already spent.
    ///
    /// Assemble both byte ceilings with the amount already retained.
    fn bounds(&self, consumed: u64) -> ReadBounds {
        ReadBounds {
            source_bytes: self.source_bytes(),
            total_bytes: self.total_bytes(),
            consumed,
        }
    }

    /// Whether a source of `length` bytes may be retained beside `consumed`.
    ///
    /// The gate a store applies to a record it did not read itself. A provider
    /// may work beneath looser ceilings than the snapshot that asked, so a
    /// record another snapshot already read is charged here exactly as a first
    /// read is charged by [`bounded`] below.
    fn retention(&self, consumed: u64, length: u64) -> Option<ReadFault> {
        exceeded(self.bounds(consumed), length)
    }
}

/// The two byte ceilings one read must respect, and the total already spent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadBounds {
    /// The most bytes one source may itself hold.
    pub(crate) source_bytes: u64,
    /// The most bytes every read source may hold together.
    pub(crate) total_bytes: u64,
    /// The bytes already charged against that total.
    pub(crate) consumed: u64,
}

/// Why one bounded read states no bytes.
///
/// Crate-private and never published: each language's reader maps it into the
/// typed error its own seam refuses through, so a caller still reads which
/// stage failed rather than one shared cause every stage returns.
pub(crate) enum ReadFault {
    /// The file could not be opened, or failed part-way through the read.
    Unreadable(std::io::Error),
    /// The bytes that arrived exceed the per-source ceiling.
    SourceBytes,
    /// The bytes that arrived would take the running total past its ceiling.
    TotalBytes,
}

/// Which of the two ceilings `length` crosses, if either.
///
/// The one owner of that comparison. Every seam that charges bytes reaches it:
/// the bounded read below directly, and each language's snapshot store through
/// [`ByteCeilings::retention`], holding a record a provider already read to the
/// snapshot's own ceilings. A second copy of the comparison would be a second
/// answer to "is this length admissible", and the looser one would be the one
/// an oversized source arrived through.
///
/// The per-source ceiling is answered first, because a source that is itself too
/// large is too large whatever the total has already spent.
pub(crate) fn exceeded(bounds: ReadBounds, length: u64) -> Option<ReadFault> {
    match (
        length > bounds.source_bytes,
        bounds.consumed.saturating_add(length) > bounds.total_bytes,
    ) {
        (true, _) => Some(ReadFault::SourceBytes),
        (false, true) => Some(ReadFault::TotalBytes),
        (false, false) => None,
    }
}

/// Read one file, holding it to both ceilings by the length that arrived.
pub(crate) fn bounded(path: &Path, bounds: ReadBounds) -> Result<Vec<u8>, ReadFault> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(bounds.source_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(ReadFault::Unreadable)?;
    match exceeded(bounds, byte_count(&bytes)) {
        Some(fault) => Err(fault),
        None => Ok(bytes),
    }
}

/// The read length, as the ceilings count it.
pub(crate) fn byte_count(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}
