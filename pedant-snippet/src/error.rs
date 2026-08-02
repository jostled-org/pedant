//! The one failure mode snippet extraction reports.

use std::path::Path;

/// A source file that could not be read.
///
/// Extraction has exactly one operation that can fail. Absence — an unsupported
/// language, an unaddressable location, a parser failure, or a point in no
/// declaration — is a successful `None`, so this error always means the bytes
/// never arrived.
#[derive(Debug, thiserror::Error)]
pub enum SnippetError {
    /// The file could not be read as UTF-8 text.
    ///
    /// The path is the caller's spelling, relative or absolute, because nothing
    /// canonicalizes it. Bytes that are not UTF-8 arrive here with
    /// [`std::io::ErrorKind::InvalidData`].
    #[error("failed to read {}: {source}", path.display())]
    Read {
        /// The path exactly as the caller supplied it.
        path: Box<Path>,
        /// The underlying I/O cause.
        #[source]
        source: std::io::Error,
    },
}
