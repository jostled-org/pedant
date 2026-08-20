//! One `replace` directive from the root manifest, and what it names.

use std::sync::Arc;

/// One `replace` directive from the root manifest.
#[derive(Debug)]
pub struct GoReplacement {
    pub(super) path: Box<str>,
    pub(super) version: Option<Box<str>>,
    pub(super) target: GoReplacementTarget,
    pub(super) applied: bool,
}

impl GoReplacement {
    /// The replaced module path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The replaced version, or `None` for a path-only entry that applies at
    /// every version.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// What this entry replaces the module with.
    pub fn target(&self) -> &GoReplacementTarget {
        &self.target
    }

    /// Whether an admitted requirement selected this entry.
    ///
    /// A path-only entry outranked by an exact one, and an entry no admitted
    /// module requires, both stay unapplied and cause no read.
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

/// What a `replace` directive names on its right-hand side.
#[derive(Debug)]
pub enum GoReplacementTarget {
    /// A filesystem directory, stated relative to the root manifest's directory
    /// and `/`-separated.
    LocalDirectory(Box<str>),
    /// Another module at another version.
    Module {
        /// The replacing module path, shared with every requirement this entry
        /// answers.
        path: Arc<str>,
        /// The replacing version, shared for the same reason.
        version: Arc<str>,
    },
}
