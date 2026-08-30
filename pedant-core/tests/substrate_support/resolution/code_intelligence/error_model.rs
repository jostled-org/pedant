//! Which typed errors the completed product publishes, and where each is
//! declared.
//!
//! No lint states which seam refuses through which enum. A variant deleted as
//! unreachable, a seam that borrowed another's enum, and an enum that stopped
//! leaving its crate all compile and pass every behavioural case.

/// One typed error the product publishes, and the module that declares it.
pub(crate) struct ErrorFamily {
    /// The enum's name.
    pub(crate) name: &'static str,
    /// The one module that declares it, repository-relative.
    pub(crate) module: &'static str,
    /// Whether the declaration leaves the crate.
    pub(crate) published: bool,
}

/// The three error families, and no fourth.
///
/// One per seam. The library refuses a build or a query through
/// `CodeIntelligenceError`; the live owner refuses a rebuild or a watcher
/// through `LiveIndexError`; and the binary refuses a run through
/// `CommandError`, which is the only one a caller outside the process never
/// sees. A fourth enum would be a seam that started refusing in its own
/// vocabulary, and every caller matching on the three would silently stop
/// covering it.
pub(crate) const ERROR_FAMILIES: &[ErrorFamily] = &[
    ErrorFamily {
        name: "CodeIntelligenceError",
        module: "pedant-snippet/src/index/error.rs",
        published: true,
    },
    ErrorFamily {
        name: "LiveIndexError",
        module: "pedant-snippet/src/live/error.rs",
        published: true,
    },
    ErrorFamily {
        name: "CommandError",
        module: "pedant-snippet/src/main.rs",
        published: false,
    },
];
