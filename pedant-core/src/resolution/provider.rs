//! The facade every reference source provider is one instantiation of.
//!
//! [`RecordCache`] already owns the admission sequence — the order the ceilings
//! are charged in, the digest, the counters. This owns the facade over it: the
//! four questions a caller asks a provider that has already read, and the one
//! [`SourceProvider`] method a snapshot reaches it through. One owner, because a
//! second copy of that facade is a second chance for one language's provider to
//! answer "what have you admitted" differently from the other's, for records
//! that came out of the same cache.
//!
//! A language module keeps exactly what the two genuinely disagree on: its
//! [`SourceLanguage`] rules, and a constructor naming its own root error.
//!
//! The inventory and the fault are parameters of their own rather than
//! projections of the rules type, because the rules trait is crate-private and a
//! published facade must not state an associated item nothing outside this crate
//! can name. Each is pinned to the rules by an equality bound, so the two
//! parameters a caller sees are still whatever the language decided.

use std::path::PathBuf;
use std::sync::Arc;

use pedant_types::{SourcePath, SourceProvider, SourceRecord};

use super::record_cache::RecordCache;
use super::source_language::SourceLanguage;

/// Every source one provider has admitted, keyed by normalized path.
#[derive(Debug)]
pub struct SourceProviderOf<Rules, Inventory> {
    cache: RecordCache<Inventory>,
    rules: Rules,
}

impl<Rules, Inventory> SourceProviderOf<Rules, Inventory> {
    /// A provider that reads beneath one already-canonical repository root.
    ///
    /// The root is canonical by construction here, not by trust: every
    /// confinement test compares a canonicalized source path against it, so a
    /// root that is relative, or that reaches its directory through a symlink,
    /// would fail that test for every file and refuse the whole repository as
    /// outside itself. Each language's own constructor is what canonicalizes,
    /// because only it can name the error a bad root is reported as.
    pub(crate) fn at_canonical_root(root: PathBuf, rules: Rules) -> Self {
        Self {
            cache: RecordCache::new(root),
            rules,
        }
    }

    /// The record this provider already holds for one path, reading nothing.
    ///
    /// A snapshot that failed leaves its completed records here, so a consumer
    /// with no resolved project can still read what was successfully admitted.
    pub fn retained(&self, path: &str) -> Option<&SourceRecord<Inventory>> {
        self.cache.retained(path)
    }

    /// Every normalized path this provider admitted, sorted.
    ///
    /// The answer shares the paths retained by this provider.
    pub fn admitted_paths(&self) -> Box<[Arc<str>]> {
        self.cache.admitted_paths()
    }

    /// How many distinct physical sources this provider admitted.
    ///
    /// One per physical record: a source several project slices reached is one
    /// admission, because the repository holds one file.
    pub fn admitted_sources(&self) -> usize {
        self.cache.admitted_sources()
    }

    /// How many bytes of source text this provider retains, charged once per
    /// physical record.
    pub fn retained_bytes(&self) -> u64 {
        self.cache.retained_bytes()
    }
}

impl<Rules, Inventory, Fault> SourceProvider<Inventory> for SourceProviderOf<Rules, Inventory>
where
    Rules: SourceLanguage<Inventory = Inventory, Fault = Fault>,
{
    type Error = Fault;

    fn source(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<Inventory>, Self::Error> {
        self.cache.source(&self.rules, path)
    }
}
