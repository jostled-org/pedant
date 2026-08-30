//! What every reference source provider is: one bounded read and one inventory
//! per normalized path, beneath one canonical repository root.
//!
//! One owner, because a second copy of this sequence would be a second answer to
//! "what does admitting a source cost, and in what order is it charged", and the
//! language that kept the weaker answer would be the one an unconfined or
//! oversized source arrived through. Capacity is checked before the read, the
//! read is bounded before the bytes are charged, and the record is inserted
//! last, so a refusal leaves the cache holding nothing it would have to unwind.
//!
//! The counters here are repository counters: they charge one physical record
//! once, when it is first admitted. They are deliberately not the ceilings a
//! snapshot checks — a snapshot measures the corpus it selected, and two
//! snapshots that share a file both selected it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use pedant_types::{SourcePath, SourceRecord};

use crate::hash::digest_bytes;
use crate::observe::{self, Observation};

use super::capacity::admits_one_more;
use super::read;
use super::source_language::SourceLanguage;

/// Every source one provider has admitted, keyed by normalized path.
#[derive(Debug)]
pub(crate) struct RecordCache<Inventory> {
    root: PathBuf,
    records: BTreeMap<Arc<str>, SourceRecord<Inventory>>,
    /// Every path an admission already refused, so the refusal is stated again
    /// from what this cache remembers rather than from a second read.
    ///
    /// Without it a source that cannot be admitted is opened, decoded, and
    /// inventoried once per unit that reaches it and once per snapshot that
    /// shares this cache — the exact multiplication the cache exists to remove,
    /// paid only by the repositories that already have something wrong.
    ///
    /// Charged against the distinct-source ceiling beside the records, because
    /// this table is retained for the provider's whole life exactly as they
    /// are. A walk that collects a failure and keeps going reaches as many
    /// distinct refusals as it does sources, and a refusal set no ceiling
    /// counted would grow with nothing naming a limit.
    refused: BTreeSet<Arc<str>>,
    consumed: u64,
}

impl<Inventory> RecordCache<Inventory> {
    /// An empty cache beneath one canonical repository root.
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            records: BTreeMap::new(),
            refused: BTreeSet::new(),
            consumed: 0,
        }
    }

    /// The record this cache already holds for one path, reading nothing.
    ///
    /// A snapshot that failed leaves its completed records here, so a consumer
    /// with no resolved project can still read what was successfully admitted.
    pub(crate) fn retained(&self, path: &str) -> Option<&SourceRecord<Inventory>> {
        self.records.get(path)
    }

    /// Every normalized path this cache admitted, sorted.
    ///
    /// The keys share the paths retained by this cache.
    pub(crate) fn admitted_paths(&self) -> Box<[Arc<str>]> {
        self.records.keys().map(Arc::clone).collect()
    }

    /// How many distinct physical sources this cache admitted.
    ///
    /// One per physical record: a source several project slices reached is one
    /// admission, because the repository holds one file.
    pub(crate) fn admitted_sources(&self) -> usize {
        self.records.len()
    }

    /// How many bytes of source text this cache retains, charged once per
    /// physical record.
    pub(crate) fn retained_bytes(&self) -> u64 {
        self.consumed
    }

    /// The record for one normalized path, admitting it on first request.
    ///
    /// Three answers, not two: a path this cache holds, a path it has already
    /// refused, and a path it has not yet met. The middle one is what keeps a
    /// bad source from being re-read once per unit that reaches it.
    ///
    /// The refusal table is searched only when the record table states nothing.
    /// The two are disjoint by construction — a path is inserted into one or the
    /// other and never both — so probing both for every request charged the
    /// answer this cache exists to give quickly a second string-comparing tree
    /// walk, once per unit that reaches an admitted source.
    pub(crate) fn source<L>(
        &mut self,
        language: &L,
        path: SourcePath<'_>,
    ) -> Result<SourceRecord<Inventory>, L::Fault>
    where
        L: SourceLanguage<Inventory = Inventory>,
    {
        match self.records.get(path.as_str()) {
            Some(record) => Ok(record.clone()),
            None => self.unheld(language, path),
        }
    }

    /// The answer for a path this cache holds no record for.
    ///
    /// The remembered refusal, or the first admission. Reached only from the
    /// miss above, so an admitted source never pays for the refusal table.
    fn unheld<L>(
        &mut self,
        language: &L,
        path: SourcePath<'_>,
    ) -> Result<SourceRecord<Inventory>, L::Fault>
    where
        L: SourceLanguage<Inventory = Inventory>,
    {
        match self.refused.contains(path.as_str()) {
            true => Err(language.refused_again(path.as_str())),
            false => self.admit(language, path),
        }
    }

    /// Read, hash, and inventory one confined source, remembering a refusal.
    ///
    /// Capacity is checked before memoization because the refusal table counts
    /// toward that capacity. Confinement, read, decode, and inventory refusals
    /// are stable for the provider's lifetime and are remembered.
    fn admit<L>(
        &mut self,
        language: &L,
        path: SourcePath<'_>,
    ) -> Result<SourceRecord<Inventory>, L::Fault>
    where
        L: SourceLanguage<Inventory = Inventory>,
    {
        self.check_capacity(language)?;
        match self.attempt(language, path) {
            Ok(record) => Ok(record),
            Err(fault) => {
                self.refused.insert(Arc::from(path.as_str()));
                Err(fault)
            }
        }
    }

    /// The admission sequence itself, in the one order every ceiling is charged.
    fn attempt<L>(
        &mut self,
        language: &L,
        path: SourcePath<'_>,
    ) -> Result<SourceRecord<Inventory>, L::Fault>
    where
        L: SourceLanguage<Inventory = Inventory>,
    {
        let relative = path.as_str();
        let canonical = language.confine(&self.root, relative)?;
        observe::record(Observation::SourceRead(relative));
        let bytes = read::bounded(&canonical, language.bounds(self.consumed))
            .map_err(|fault| language.refusal(fault))?;
        let charged = read::byte_count(&bytes);
        let text = language.decode(bytes)?;
        let inventory = language.inventory(relative, &text)?;
        let record = SourceRecord::new(
            Arc::from(text.as_str()),
            digest_bytes(text.as_bytes()),
            Arc::new(inventory),
        );
        self.consumed = self.consumed.saturating_add(charged);
        self.records.insert(Arc::from(relative), record.clone());
        Ok(record)
    }

    /// One more distinct path must still fit under the configured ceiling.
    ///
    /// Both retained tables are counted. A refused path costs this cache a key
    /// for the rest of its life so the source behind it is never read again,
    /// which is the same retention a record is, and charging only the records
    /// left the whole refusal table outside every ceiling this module states.
    fn check_capacity<L>(&self, language: &L) -> Result<(), L::Fault>
    where
        L: SourceLanguage<Inventory = Inventory>,
    {
        let retained = self.records.len().saturating_add(self.refused.len());
        match admits_one_more(retained, language.max_source_files()) {
            true => Ok(()),
            false => Err(language.source_files_fault()),
        }
    }
}
