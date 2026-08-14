//! Bounded retention whose eviction order is least recently used.
//!
//! The store holds admitted values only. It never decides whether a value is
//! correct, and evicting one can never turn an answer a caller asked for into a
//! failure: the value is computed and returned whatever the store retains.

use crate::id::index_of;

/// One retained value beside the key it answers for.
struct Entry<K, V> {
    key: K,
    value: V,
}

/// A bounded store, most recently used last.
///
/// Recency is the position in one vector rather than a separate queue, so the
/// order a case observes through eviction counters and the order the store
/// evicts by cannot drift apart. The retained multiplicity is small by
/// construction — it is the ceiling a host chose — so a linear scan is the
/// whole lookup.
pub(crate) struct BoundedStore<K, V> {
    ceiling: u32,
    entries: Vec<Entry<K, V>>,
}

impl<K: PartialEq, V: Clone> BoundedStore<K, V> {
    /// An empty store bounded by `ceiling`.
    pub(crate) fn new(ceiling: u32) -> Self {
        Self {
            ceiling,
            entries: Vec::new(),
        }
    }

    /// The value `key` selects, promoted to most recently used.
    pub(crate) fn get(&mut self, key: &K) -> Option<V> {
        self.selected(key, |_| true)
    }

    /// The value `key` selects, when `states` accepts it, promoted to most
    /// recently used.
    ///
    /// A key narrower than the claim its value was retained under does not
    /// decide reuse on its own, so the caller supplies the rest of the decision
    /// and a selected entry the caller rejects is no answer. One key selects at
    /// most one entry — retaining under a key the store already holds replaces
    /// it — so this scan can never have two candidates to choose between.
    pub(crate) fn selected(&mut self, key: &K, states: impl Fn(&V) -> bool) -> Option<V> {
        let found = self
            .entries
            .iter()
            .rposition(|entry| entry.key == *key && states(&entry.value))?;
        let entry = self.entries.remove(found);
        let value = entry.value.clone();
        self.entries.push(entry);
        Some(value)
    }

    /// Retain `value` under `key`, answering how many entries were evicted.
    ///
    /// The entry this one supersedes goes first, so one key is held once and a
    /// caller that missed on a narrower test cannot leave a dead entry behind
    /// to spend a live one's room. Eviction runs next, before the insertion
    /// rather than after it, so the store never holds more than its ceiling
    /// even momentarily. A zero ceiling retains nothing and evicts nothing.
    pub(crate) fn retain(&mut self, key: K, value: V) -> u64 {
        self.discard(&key);
        let evicted = self.evict_beyond(self.ceiling.saturating_sub(1));
        match self.ceiling {
            0 => evicted,
            _ => {
                self.entries.push(Entry { key, value });
                evicted
            }
        }
    }

    /// Drop the entry `key` supersedes, if the store holds one.
    ///
    /// A replacement is not an eviction and is not counted as one: the store
    /// held one answer for this key before and holds one after, so no ceiling
    /// dropped anything. Counting it would report pressure no budget a host set
    /// explains.
    fn discard(&mut self, key: &K) {
        self.entries.retain(|entry| entry.key != *key);
    }

    /// Drop least-recently-used entries until at most `remaining` are held.
    fn evict_beyond(&mut self, remaining: u32) -> u64 {
        let kept = index_of(remaining);
        let evicted = self.entries.len().saturating_sub(kept);
        self.entries.drain(..evicted);
        u64::try_from(evicted).unwrap_or(u64::MAX)
    }

    /// Drop every retained entry.
    ///
    /// The cache owns strong references, never the only ones: a value a caller
    /// still holds stays valid and immutable after its entry is gone.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}
