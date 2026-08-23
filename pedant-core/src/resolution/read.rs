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

/// Read one file, holding it to both ceilings by the length that arrived.
pub(crate) fn bounded(path: &Path, bounds: ReadBounds) -> Result<Vec<u8>, ReadFault> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(bounds.source_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(ReadFault::Unreadable)?;
    let length = byte_count(&bytes);
    match (
        length > bounds.source_bytes,
        bounds.consumed.saturating_add(length) > bounds.total_bytes,
    ) {
        (true, _) => Err(ReadFault::SourceBytes),
        (false, true) => Err(ReadFault::TotalBytes),
        (false, false) => Ok(bytes),
    }
}

/// The read length, as the ceilings count it.
pub(crate) fn byte_count(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}
