//! What every language's snapshot source store is: one interning table of
//! normalized repository-relative paths, held to that snapshot's own ceilings.
//!
//! One owner, because a second copy of this table would be a second answer to
//! "what does retaining a source cost this snapshot, and in what order is it
//! charged", and the language that kept the weaker answer would be the one an
//! oversized or unnormalized source was retained through. The key buffer, the
//! interning map, the distinct-file ceiling, the byte charge, and the sorted
//! finish are stated here and nowhere else.
//!
//! A language keeps exactly what the two genuinely disagree on: the extra
//! ceilings one retained record owes — Go's fact and depth counts, Rust's
//! nesting depth and edition compatibility — and the vocabulary each refusal is
//! published in. The refusals arrive through
//! [`SnapshotRules`](super::snapshot_rules::SnapshotRules); the extra ceilings
//! arrive as the callback that builds the record this store retains, so a
//! language's own refusal still happens before the table grows.
//!
//! This is the same collapse the crate already made for the provider beneath
//! it, where one [`SourceProviderOf`](super::SourceProviderOf) admits for both
//! languages and each states only its own rules.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use pedant_types::{SourcePath, SourceRecord};

use super::capacity::admits_one_more;
use super::path_normalization;
use super::read::byte_count;
use super::snapshot_rules::SnapshotRules;
use super::supply::SourceSupply;

/// Which answer one intern request got, beside where the source now sits.
///
/// Two variants rather than a flag, because the two are different events. A
/// held path was admitted under some earlier request and every ceiling it owes
/// was charged then; an admitted path was charged by this one. A seam with a
/// per-request question to ask about a source it already holds — whether the
/// unit now asking may also compile it — is the one that has to tell them
/// apart.
///
/// Where the source sits is the same answer either way, so both events carry
/// one [`Placement`] rather than restating its fields. A seam that does not
/// have to tell the two apart reads the placement out of either.
pub(crate) enum Interned {
    /// A path this store already held.
    Held(Placement),
    /// A path this request admitted.
    Admitted(Placement),
}

/// Where one source sits in this store once the request is answered.
pub(crate) struct Placement {
    /// The key this store holds the source under.
    pub(crate) path: Arc<str>,
    /// Where the source sits among the stored records.
    pub(crate) index: usize,
}

/// Every distinct source one snapshot reached, keyed by normalized path.
pub(crate) struct SnapshotStoreOf<Rules: SnapshotRules> {
    rules: Rules,
    indexes: BTreeMap<Arc<str>, usize>,
    stored: Vec<Rules::Stored>,
    /// The buffer every relative key is rendered into before it is looked up.
    ///
    /// Reused for lookups and promoted to a shared key only on admission.
    key: String,
    consumed: u64,
}

impl<Rules: SnapshotRules> SnapshotStoreOf<Rules> {
    /// An empty store under one language's rules.
    pub(crate) fn new(rules: Rules) -> Self {
        Self {
            rules,
            indexes: BTreeMap::new(),
            stored: Vec::new(),
            key: String::new(),
            consumed: 0,
        }
    }

    /// The language rules this store retains beneath.
    pub(crate) fn rules(&self) -> &Rules {
        &self.rules
    }

    /// Retain `canonical` unless this store already holds it, and answer with
    /// the key it is held under and the position it occupies.
    ///
    /// One map lookup answers both questions the held branch asks — which key
    /// to hand back, and which stored record a caller may then check — so a
    /// source reached many times is searched for once per reach rather than
    /// twice.
    ///
    /// Every ceiling is stated before the store grows, so a refusal leaves the
    /// snapshot holding nothing it would have to unwind and naming no path it
    /// did not complete. The caller's `retain` is the last of those ceilings:
    /// it states whatever this language holds one record to beyond the bytes,
    /// and it builds the record only once it has passed.
    pub(crate) fn intern<P, Retain>(
        &mut self,
        provider: &mut P,
        canonical: &Path,
        at: &Rules::Site,
        retain: Retain,
    ) -> Result<Interned, Rules::Refusal>
    where
        P: SourceSupply<Rules::Inventory, Rules::Fault>,
        Retain: FnOnce(
            &Arc<str>,
            &SourceRecord<Rules::Inventory>,
        ) -> Result<Rules::Stored, Rules::Refusal>,
    {
        self.render_key(canonical, at)?;
        let held = self
            .indexes
            .get_key_value(self.key.as_str())
            .map(|(interned, index)| (Arc::clone(interned), *index));
        match held {
            Some((path, index)) => Ok(Interned::Held(Placement { path, index })),
            None => {
                let path: Arc<str> = Arc::from(self.key.as_str());
                let index = self.admit(provider, &path, at, retain)?;
                Ok(Interned::Admitted(Placement { path, index }))
            }
        }
    }

    /// One retained record by position, which is what an intern answer names.
    ///
    /// Absence names an index this store issued and no longer holds, which is
    /// the store disagreeing with itself rather than a source it never met.
    pub(crate) fn stored(&self, index: usize) -> Option<&Rules::Stored> {
        self.stored.get(index)
    }

    /// One retained record by its normalized path.
    pub(crate) fn stored_at(&self, path: &str) -> Option<&Rules::Stored> {
        self.indexes
            .get(path)
            .and_then(|index| self.stored.get(*index))
    }

    /// The sorted normalized paths this store reached.
    ///
    /// The answer shares the keys retained by this store.
    pub(crate) fn keys(&self) -> Box<[Arc<str>]> {
        self.indexes.keys().map(Arc::clone).collect()
    }

    /// Every retained record, sorted by normalized path.
    pub(crate) fn finish(self) -> Box<[Rules::Stored]> {
        let mut stored = self.stored;
        stored.sort_by(|left, right| Rules::stored_path(left).cmp(Rules::stored_path(right)));
        stored.into_boxed_slice()
    }

    /// Charge, admit, and retain one source this store had not yet held.
    fn admit<P, Retain>(
        &mut self,
        provider: &mut P,
        path: &Arc<str>,
        at: &Rules::Site,
        retain: Retain,
    ) -> Result<usize, Rules::Refusal>
    where
        P: SourceSupply<Rules::Inventory, Rules::Fault>,
        Retain: FnOnce(
            &Arc<str>,
            &SourceRecord<Rules::Inventory>,
        ) -> Result<Rules::Stored, Rules::Refusal>,
    {
        let relative: &str = path;
        self.check_capacity(at, relative)?;
        let request =
            SourcePath::new(relative).ok_or_else(|| self.rules.unnormalized((at, relative)))?;
        let record = provider
            .supply(request)
            .map_err(|fault| self.rules.refused(fault, (at, relative)))?;
        let charged = self.charge(&record, (at, relative))?;
        let stored = retain(path, &record)?;
        let index = self.stored.len();
        self.consumed = self.consumed.saturating_add(charged);
        self.indexes.insert(Arc::clone(path), index);
        self.stored.push(stored);
        Ok(index)
    }

    /// Render the repository-relative key of `canonical` into the buffer.
    fn render_key(&mut self, canonical: &Path, at: &Rules::Site) -> Result<(), Rules::Refusal> {
        let rendered =
            path_normalization::write_relative(&mut self.key, self.rules.root(), canonical);
        rendered.map_err(|error| self.rules.unrelative(error, (at, canonical)))
    }

    /// Hold one supplied record to this snapshot's own byte ceilings, and
    /// answer what it costs the running total.
    ///
    /// A provider may read beneath looser ceilings than the snapshot that asked
    /// — that is the point of sharing one — so a record another snapshot
    /// already read is charged here exactly as a first read is.
    fn charge(
        &self,
        record: &SourceRecord<Rules::Inventory>,
        at: (&Rules::Site, &str),
    ) -> Result<u64, Rules::Refusal> {
        let charged = byte_count(record.text().as_bytes());
        match self.rules.retention(self.consumed, charged) {
            Some(fault) => Err(self.rules.oversized(fault, at)),
            None => Ok(charged),
        }
    }

    /// One more source must still fit under this snapshot's own ceiling.
    ///
    /// Reconciled by the one owner of the count-against-ceiling comparison, so
    /// this store cannot disagree with the provider that reads for it about how
    /// many distinct sources a ceiling of `n` admits.
    fn check_capacity(&self, at: &Rules::Site, path: &str) -> Result<(), Rules::Refusal> {
        match admits_one_more(self.stored.len(), self.rules.max_source_files()) {
            true => Ok(()),
            false => Err(self.rules.source_files((at, path))),
        }
    }
}
