//! Typed failures returned while snapshotting a Go module project.

use std::fmt;

use pedant_syntax::go::GoFactError;

/// Why one admitted source states no complete inventory.
///
/// Capability detection keeps findings from a recovered tree beside an
/// unavailable attribution status. A resolution snapshot cannot: a declaration
/// the parser dropped becomes a missing definition in a report and a missing
/// node in a graph, with nothing to say it was ever there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoSourceDefect {
    /// The grammar produced no tree for the source at all.
    Unparsed,
    /// The grammar produced a tree by recovering from a syntax error.
    Recovered,
}

impl fmt::Display for GoSourceDefect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unparsed => formatter.write_str("the grammar produced no tree"),
            Self::Recovered => formatter.write_str("the parser recovered from a syntax error"),
        }
    }
}

/// Failure encountered while walking a Go project's packages and sources.
#[derive(Debug, thiserror::Error)]
pub enum GoSnapshotError {
    /// A path the walk reached is not inside the repository root.
    #[error("path {path} lies outside the project root {root}")]
    OutOfRoot {
        /// The canonical path that escaped.
        path: Box<str>,
        /// The root that does not contain it.
        root: Box<str>,
    },
    /// A path beneath the repository root is not valid UTF-8.
    #[error("path {path} beneath the project root is not valid UTF-8")]
    NonUtf8Path {
        /// The offending path, rendered lossily for the message only.
        path: Box<str>,
    },
    /// A package directory could not be listed.
    #[error("failed to list {path}: {source}")]
    DirectoryRead {
        /// The unreadable directory, repository-relative.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A source could not be read.
    #[error("failed to read {path}: {source}")]
    SourceRead {
        /// The unreadable source, repository-relative.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A source's bytes are not valid UTF-8, so they state no Go text.
    #[error("source {path} is not valid UTF-8")]
    NonUtf8Source {
        /// The rejected source, repository-relative.
        path: Box<str>,
    },
    /// A source states no complete tree.
    #[error("source {path} cannot be snapshotted: {defect}")]
    IncompleteSource {
        /// The rejected source, repository-relative.
        path: Box<str>,
        /// Why the tree is not complete.
        defect: GoSourceDefect,
    },
    /// A source states no package clause, so it belongs to no package.
    #[error("source {path} states no package clause")]
    MissingPackageClause {
        /// The rejected source, repository-relative.
        path: Box<str>,
    },
    /// One directory's sources state package clauses Go cannot compile
    /// together.
    #[error("directory {directory} declares both {first} and {second}")]
    ConflictingPackageClause {
        /// The directory holding both clauses, repository-relative.
        directory: Box<str>,
        /// The clause the directory's package was taken from.
        first: Box<str>,
        /// The clause that cannot join it.
        second: Box<str>,
    },
    /// A source's fact inventory was refused.
    #[error("failed to extract Go facts from {path}: {source}")]
    FactExtraction {
        /// The refused source, repository-relative.
        path: Box<str>,
        /// The ceiling or grammar mismatch that refused it.
        #[source]
        source: GoFactError,
    },
    /// The package walk reached more directory entries than the limit allows.
    #[error("snapshot visits more than {limit} directory entries")]
    DirectoryEntryLimitExceeded {
        /// The configured directory-entry ceiling.
        limit: u32,
    },
    /// The snapshot holds more package units than the limit allows.
    #[error("snapshot holds more than {limit} resolution units")]
    UnitLimitExceeded {
        /// The configured unit ceiling.
        limit: u32,
    },
    /// The snapshot holds more distinct sources than the limit allows.
    #[error("snapshot holds more than {limit} source files")]
    SourceFileLimitExceeded {
        /// The configured source-file ceiling.
        limit: u32,
    },
    /// One source is larger than the per-file limit allows.
    #[error("source {path} holds more than {limit} bytes")]
    SourceBytesLimitExceeded {
        /// The oversized source, repository-relative.
        path: Box<str>,
        /// The configured per-file byte ceiling.
        limit: u64,
    },
    /// The snapshot's sources hold more bytes together than the limit allows.
    #[error("snapshot holds more than {limit} source bytes")]
    TotalSourceBytesLimitExceeded {
        /// The configured total byte ceiling.
        limit: u64,
    },
}
