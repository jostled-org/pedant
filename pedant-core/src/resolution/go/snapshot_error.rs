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
    ///
    /// Both spellings, because neither answers alone: the request is what the
    /// snapshot asked for and what a caller can act on, while a request that
    /// escaped through a link is spelled inside the root and says nothing about
    /// where it went.
    #[error("request {request} lies outside the project root {root}, at {path}")]
    OutOfRoot {
        /// The canonical path that escaped.
        path: Box<str>,
        /// The root that does not contain it.
        root: Box<str>,
        /// The path that was asked for, before any link was followed.
        request: Box<str>,
    },
    /// A path beneath the repository root is not valid UTF-8.
    #[error("path {path} beneath the project root is not valid UTF-8")]
    NonUtf8Path {
        /// The offending path, rendered lossily for the message only.
        path: Box<str>,
    },
    /// A path beneath the repository root could not be resolved.
    ///
    /// Absence is not this: a directory holding no source and a replacement
    /// target holding no manifest are both reported by the stage that asked.
    /// This is a path the filesystem refused to answer for — a denied
    /// permission, a symlink loop, an over-long name — which must not read as
    /// a file the repository never held.
    #[error("failed to resolve {path}: {source}")]
    PathRead {
        /// The path that could not be resolved.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
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
    /// A path the store produced is not a normalized repository-relative
    /// request.
    ///
    /// Deliberately not [`Self::OutOfRoot`]: a path holding a backslash or a
    /// `.` segment may sit well inside the root, and reporting it as an escape
    /// states something false about where it is.
    #[error("path {path} is not a normalized repository-relative path")]
    UnnormalizedPath {
        /// The path that states no request.
        path: Box<str>,
    },
    /// A source's bytes are not valid UTF-8, so they state no Go text.
    #[error("source {path} is not valid UTF-8: {reason}")]
    NonUtf8Source {
        /// The rejected source, repository-relative.
        path: Box<str>,
        /// The refusal the decoder stated, naming the offending byte.
        reason: Box<str>,
    },
    /// A source the parser refused, in the parser's own words.
    ///
    /// Distinct from [`Self::IncompleteSource`], which is this crate's verdict
    /// on a tree it holds: this is a refusal the provider's own parser stated.
    #[error("source {path} is not valid Go: {reason}")]
    UnparsedSource {
        /// The rejected source, repository-relative.
        path: Box<str>,
        /// The refusal the parser stated.
        reason: Box<str>,
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
    /// A source the provider had already refused, refused again from memory.
    ///
    /// The first refusal named its own cause and is the one to act on. This
    /// says only that the provider did not open the file a second time, which
    /// is what keeps one bad source from being re-read once per package
    /// context that reaches it.
    #[error("source {path} was already refused by the provider reading for this snapshot")]
    AlreadyRefused {
        /// The refused source, repository-relative.
        path: Box<str>,
    },
    /// The structure projection over one source's facts refused.
    #[error("source {path} states no complete structure inventory: {reason}")]
    StructureProjection {
        /// The rejected source, repository-relative.
        path: Box<str>,
        /// The refusal the projection stated.
        reason: Box<str>,
    },
    /// A path the store interned names no source the store holds.
    ///
    /// Defensive, and deliberately not a missing package clause: the store
    /// refuses any source without one before it retains it, so a path it just
    /// returned that answers with no clause is the store disagreeing with
    /// itself rather than a repository stating a source that declares nothing.
    #[error("source {path} was interned but is not held by the store")]
    MissingStoredSource {
        /// The interned path that names no stored source.
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
    /// One retained source states more facts than this snapshot's limit allows.
    ///
    /// Not a [`Self::FactExtraction`]: the walk that produced these facts
    /// completed, beneath the provider's own looser ceiling. This snapshot
    /// refuses the result, and says so in its own name rather than attributing
    /// a refusal to a walk that never made one.
    #[error("source {path} states more than {limit} facts")]
    RetainedFactsExceeded {
        /// The refused source, repository-relative.
        path: Box<str>,
        /// The configured per-source fact ceiling.
        limit: u32,
    },
    /// One retained source nests deeper than this snapshot's limit allows.
    ///
    /// Refused for the same reason, and by the same authority, as
    /// [`Self::RetainedFactsExceeded`].
    #[error("source {path} nests deeper than {limit}")]
    RetainedDepthExceeded {
        /// The refused source, repository-relative.
        path: Box<str>,
        /// The configured nesting ceiling.
        limit: u32,
    },
}
