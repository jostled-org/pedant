use thiserror::Error;

/// Failure modes during workspace indexing.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Disk I/O failure.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Absolute path of the unreadable file.
        path: Box<str>,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The shared Cargo project authority rejected the workspace.
    #[error("failed to load the Cargo project: {source}")]
    Project {
        /// Underlying project-loading failure.
        #[source]
        source: pedant_core::resolution::rust::RustProjectError,
    },
    /// `syn` could not parse a Rust source file.
    #[error("failed to parse Rust source {path}: {source}")]
    RustParse {
        /// Path of the unparseable source file.
        path: Box<str>,
        /// Underlying parse error.
        source: pedant_core::ParseError,
    },
}
