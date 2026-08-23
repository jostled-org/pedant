//! The source view: one snapshotted Go file, its exact bytes, its retained
//! predicates, and its fact inventory.

use std::sync::Arc;

use crate::resolution::line_index::SnapshotSource;

use super::condition::GoBuildCondition;
use super::facts::GoSourceFacts;

/// One Go source a snapshot reached, read, parsed, and walked exactly once.
///
/// A source is stored once even when several package contexts instantiate it,
/// so per-context identities never cost a second read, parse, or walk.
#[derive(Debug)]
pub struct GoSource {
    pub(super) path: Arc<str>,
    pub(super) text: Arc<str>,
    pub(super) digest: [u8; 32],
    pub(super) conditions: Box<[GoBuildCondition]>,
    pub(super) facts: GoSourceFacts,
}

impl GoSource {
    /// The repository-relative, `/`-separated path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The exact UTF-8 text this snapshot read.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// SHA-256 of the exact bytes behind [`Self::text`].
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Every unevaluated build predicate this source carries.
    ///
    /// Empty for a source every build compiles. A non-empty list is evidence a
    /// consumer states as possible, never a decision this tier made.
    pub fn conditions(&self) -> &[GoBuildCondition] {
        &self.conditions
    }

    /// The structured grammar facts extracted while this source was
    /// snapshotted.
    pub fn facts(&self) -> &GoSourceFacts {
        &self.facts
    }
}

impl SnapshotSource for GoSource {
    fn path(&self) -> &str {
        &self.path
    }

    fn text(&self) -> &str {
        &self.text
    }
}

/// The source at `path`, when the sorted slice holds one.
pub(super) fn find<'a>(sources: &'a [GoSource], path: &str) -> Option<&'a GoSource> {
    sources
        .binary_search_by(|source| (*source.path).cmp(path))
        .ok()
        .and_then(|index| sources.get(index))
}
