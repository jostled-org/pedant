//! The one repository reader every code-intelligence build goes through.
//!
//! One physical file, one read, one decode, one declaration walk — for every
//! project slice that reaches it and for the loose corpus alike. That is the
//! whole reason this type exists: a Cargo workspace whose library is compiled
//! into four targets reaches the same sources four times, and a store that
//! answered from what it already holds turns four parses into one.
//!
//! It is also the only place a repository byte ceiling can be honest. The
//! counters here charge one physical record once, when it is first admitted;
//! the ceilings a snapshot checks measure the corpus that snapshot selected, and
//! two snapshots that share a file both selected it.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{Language, StructureRecord};

use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError, capacity};
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use super::file_inventory::FileInventory;
use super::limits::CodeIntelligenceLimits;
#[cfg(feature = "test-support")]
use super::observe::{SourceStep, SourceWork};
use super::path::CanonicalRoot;
use super::read;
use super::source::StoredSource;
use super::syntax;

/// One physical source this repository has already read and paid for.
///
/// Held apart from an admitted record because the two disagree exactly where
/// the second read lives: a language-owner admission that read a file and then
/// refused it retains no record, and the loose corpus reaches the same file
/// afterwards. The decoded text and the digest are kept so that second
/// admission re-reads nothing — the bytes are already charged against the
/// repository, and reading them again would spend the work the charge accounts
/// for.
#[derive(Clone)]
struct ChargedSource {
    text: Arc<str>,
    digest: [u8; 32],
}

/// Every physical source one index revision admitted, keyed by normalized path.
pub(crate) struct RepositorySourceStore {
    root: CanonicalRoot,
    limits: CodeIntelligenceLimits,
    records: BTreeMap<Arc<str>, StoredSource>,
    /// Every path this store has already resolved, with what that read
    /// produced — the retained text, or the refusal that ended it.
    ///
    /// A refusal is retained beside a success because it answers the same
    /// question: has this physical file already been opened? A non-UTF-8 or
    /// oversized source is reached again by every compiled target and once more
    /// by the loose corpus, and each of those retries re-read a whole
    /// `max_source_file_bytes` to arrive at the refusal the first one already
    /// stated.
    charged: BTreeMap<Arc<str>, Result<ChargedSource, CodeIntelligenceError>>,
    /// What the Rust language owner's parse of each path it reached produced.
    #[cfg(feature = "graph-rust")]
    parsed_rust:
        super::file_inventory::ParseOutcomes<pedant_core::resolution::rust::RustFileInventory>,
    /// What the Go language owner's parse of each path it reached produced.
    #[cfg(feature = "graph-go")]
    parsed_go: super::file_inventory::ParseOutcomes<pedant_core::resolution::go::GoFileInventory>,
    /// How many distinct physical files are charged against the repository.
    ///
    /// Counted rather than read from `charged`, which now also holds the paths
    /// no read retained: a refused file consumes no file allowance, so counting
    /// the map would let one unreadable source spend a slot the repository
    /// still has.
    charged_files: u64,
    consumed_bytes: u64,
    structures: u64,
    #[cfg(feature = "test-support")]
    work: Arc<SourceWork>,
}

impl RepositorySourceStore {
    /// A store that reads beneath one canonical root under `limits`.
    pub(crate) fn new(root: CanonicalRoot, limits: CodeIntelligenceLimits) -> Self {
        Self {
            root,
            limits,
            records: BTreeMap::new(),
            charged: BTreeMap::new(),
            #[cfg(feature = "graph-rust")]
            parsed_rust: BTreeMap::new(),
            #[cfg(feature = "graph-go")]
            parsed_go: BTreeMap::new(),
            charged_files: 0,
            consumed_bytes: 0,
            structures: 0,
            #[cfg(feature = "test-support")]
            work: Arc::new(SourceWork::default()),
        }
    }

    /// What this store has spent, shared with the index it seals into.
    #[cfg(feature = "test-support")]
    pub(crate) fn work(&self) -> &Arc<SourceWork> {
        &self.work
    }

    /// Every admitted record, in normalized path order.
    pub(crate) fn records(&self) -> impl Iterator<Item = (&Arc<str>, &StoredSource)> {
        self.records.iter()
    }

    /// How many records the seal will map, exactly.
    pub(crate) fn file_count(&self) -> usize {
        self.records.len()
    }

    /// How many structures those records declare, together.
    ///
    /// The running total `retain` already charges. The seal reserves against
    /// both counts rather than growing by doubling to as many as a million
    /// elements and then reallocating once more to box them.
    pub(crate) fn structure_count(&self) -> usize {
        super::count::sized(self.structures)
    }

    /// The record this store already holds for one path, reading nothing.
    pub(crate) fn retained(&self, path: &str) -> Option<&StoredSource> {
        self.records.get(path)
    }

    /// Admit one recognized source through its language's own inventory.
    ///
    /// Returns the record whether this call read it or an earlier one did. A
    /// cache hit changes no counter, because the repository still holds one
    /// copy of the file.
    pub(crate) fn admit(
        &mut self,
        path: &Arc<str>,
        language: Language,
    ) -> Result<StoredSource, CodeIntelligenceError> {
        if let Some(record) = self.records.get(path) {
            return Ok(record.clone());
        }
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        if let Some(refusal) = parse_refusal(self, path, language) {
            return Err(refusal);
        }
        let held = self.read_source(path)?;
        let structures = self.recognize(path, language, &held.text)?;
        self.retain(
            path,
            StoredSource::syntax(held.text, held.digest, language, structures),
        )
    }

    /// What one physical read of `path` produced, reading it at most once.
    ///
    /// One physical read per path, not one per call, and that holds for a read
    /// that refused as much as for one that succeeded. A language owner that
    /// read a file and then refused it retains no record, so the loose corpus
    /// reaches the same file again — and whether the first attempt ended in
    /// bytes or in a refusal, repeating it opens, hashes, and decodes a whole
    /// file to reach an answer this store already holds.
    fn read_source(&mut self, path: &Arc<str>) -> Result<ChargedSource, CodeIntelligenceError> {
        if let Some(held) = self.charged.get(path) {
            return held.clone();
        }
        let read = self.read_once(path);
        self.charged.insert(Arc::clone(path), read.clone());
        read
    }

    /// Read, decode, and hash one confined source beneath every byte ceiling.
    ///
    /// The per-file ceiling is checked while reading rather than after it, so a
    /// file past it never enters the buffer; the total ceiling is checked
    /// before the decoded text is retained, so a repository past it never holds
    /// the string.
    fn read_once(&mut self, path: &Arc<str>) -> Result<ChargedSource, CodeIntelligenceError> {
        let ceiling = u64::from(self.limits.repository.max_files);
        if self.charged_files >= ceiling {
            return Err(capacity(
                CapacityOwner::Repository,
                CapacityCollection::File,
                self.charged_files.saturating_add(1),
                ceiling,
            ));
        }
        let canonical = self.root.resolve(path)?;
        let bytes = read::bounded(
            &canonical,
            path,
            self.limits.repository.max_source_file_bytes,
        )?;
        #[cfg(feature = "test-support")]
        self.work.recorded(SourceStep::StoreRead, path);
        let total = self.consumption(bytes.len())?;
        let digest = read::digest(&bytes);
        let text =
            String::from_utf8(bytes).map_err(|error| CodeIntelligenceError::SourceEncoding {
                path: Box::from(&**path),
                reason: error.utf8_error().to_string().into_boxed_str(),
            })?;
        Ok(self.charge(total, Arc::from(text.as_str()), digest))
    }

    /// What the repository will have consumed once it is charged for `length`
    /// more bytes, or the ceiling that refuses them.
    ///
    /// Asked only of a path this store has not read before, because one
    /// physical file admitted through two routes is one file: charging the
    /// second route would state a total this repository does not hold.
    fn consumption(&self, length: usize) -> Result<u64, CodeIntelligenceError> {
        let total = self
            .consumed_bytes
            .saturating_add(super::count::widened(length));
        match total > self.limits.repository.max_total_source_bytes {
            true => Err(capacity(
                CapacityOwner::Repository,
                CapacityCollection::TotalBytes,
                total,
                self.limits.repository.max_total_source_bytes,
            )),
            false => Ok(total),
        }
    }

    /// Charge one physical read to the repository and keep what it produced.
    ///
    /// The retention is the caller's: `read_source` keys every outcome, so a
    /// refusal and a success are recorded by one insertion rather than by two
    /// routes that could disagree about which paths this store has opened.
    fn charge(&mut self, total: u64, text: Arc<str>, digest: [u8; 32]) -> ChargedSource {
        self.consumed_bytes = total;
        self.charged_files = self.charged_files.saturating_add(1);
        ChargedSource { text, digest }
    }

    /// The structures one source declares, beneath the remaining repository
    /// allowance.
    ///
    /// The per-source ceiling is clamped to what the repository has left,
    /// because every structure a loose inventory emits is a new physical
    /// record: a source ceiling above the remaining repository allowance would
    /// recognize structures the index then has to throw away.
    fn recognize(
        &self,
        path: &Arc<str>,
        language: Language,
        text: &str,
    ) -> Result<Box<[StructureRecord]>, CodeIntelligenceError> {
        let remaining =
            u64::from(self.limits.repository.max_structures).saturating_sub(self.structures);
        #[cfg(feature = "test-support")]
        self.work.recorded(SourceStep::LanguageParse, path);
        let inventory = syntax::inventory(path, language, text, self.limits.syntax, remaining)?;
        #[cfg(feature = "test-support")]
        self.work.recorded(SourceStep::DeclarationInventory, path);
        Ok(inventory)
    }

    /// Retain one admitted source and charge its structures to the repository.
    ///
    /// The charge is the difference against what this path already holds, not
    /// the whole count: the insertion replaces any earlier record of the same
    /// path, so a re-admission — a language owner reaching a source the loose
    /// corpus already outlined — charged the repository twice for one retained
    /// set of structures and could refuse a ceiling it was nowhere near.
    fn retain(
        &mut self,
        path: &Arc<str>,
        record: StoredSource,
    ) -> Result<StoredSource, CodeIntelligenceError> {
        let count = super::count::widened(record.structures().len());
        let held = self.records.get(path).map_or(0, |replaced| {
            super::count::widened(replaced.structures().len())
        });
        let total = self.structures.saturating_sub(held).saturating_add(count);
        let ceiling = u64::from(self.limits.repository.max_structures);
        if total > ceiling {
            return Err(capacity(
                CapacityOwner::Repository,
                CapacityCollection::Structure,
                total,
                ceiling,
            ));
        }
        self.structures = total;
        self.records.insert(Arc::clone(path), record.clone());
        Ok(record)
    }

    /// The limits this store admits beneath.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn limits(&self) -> &CodeIntelligenceLimits {
        &self.limits
    }

    /// Admit one source through the language owner `Inventory` names.
    ///
    /// One sequence for every language: answer from the record already held,
    /// otherwise read once, parse once, retain, and hand back the record. The
    /// two owners differ in the cache field probed, the ceilings, the fault
    /// vocabulary, and the constructor — every one of which the owner states
    /// for itself through [`FileInventory`], so the sequence is written here
    /// rather than once per owner.
    ///
    /// The path is borrowed rather than shared, because the ordinary answer is
    /// the first branch: a shared key is minted only where one is retained.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn admit_resolved<Inventory: FileInventory>(
        &mut self,
        path: &str,
    ) -> Result<pedant_types::SourceRecord<Inventory>, CodeIntelligenceError> {
        if let Some(record) = self.records.get(path)
            && let Some(inventory) = Inventory::held(record)
        {
            return Ok(pedant_types::SourceRecord::new(
                Arc::clone(record.text()),
                *record.digest(),
                inventory,
            ));
        }
        if let Some(Err(held)) = Inventory::outcomes(self).get(path) {
            return Err(held.clone());
        }
        let shared: Arc<str> = Arc::from(path);
        let held = self.read_source(&shared)?;
        let inventory = self.parsed::<Inventory>(&shared, &held.text)?;
        self.retain(
            &shared,
            Inventory::stored(Arc::clone(&held.text), held.digest, Arc::clone(&inventory)),
        )?;
        Ok(pedant_types::SourceRecord::new(
            held.text,
            held.digest,
            inventory,
        ))
    }

    /// What one language owner's parse of `path` produced, parsing it at most
    /// once.
    ///
    /// One parse per physical path, including a parse that refuses. Loose
    /// admission consults this outcome before selecting a syntax grammar, so a
    /// refusal cannot cause a second parser to replace the first answer.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    fn parsed<Inventory: FileInventory>(
        &mut self,
        path: &Arc<str>,
        text: &Arc<str>,
    ) -> Result<Arc<Inventory>, CodeIntelligenceError> {
        if let Some(held) = Inventory::outcomes(self).get(path) {
            return held.clone();
        }
        #[cfg(feature = "test-support")]
        self.work.recorded(SourceStep::LanguageParse, path);
        let parsed = match Inventory::of_source(path, text, Inventory::limits(&self.limits)) {
            Ok(inventory) => {
                #[cfg(feature = "test-support")]
                self.work.recorded(SourceStep::DeclarationInventory, path);
                Ok(Arc::new(inventory))
            }
            Err(fault) => Err(Inventory::fault(path, &fault)),
        };
        Inventory::outcomes(self).insert(Arc::clone(path), parsed.clone());
        parsed
    }

    /// Where the Rust owner's parse outcomes are kept.
    #[cfg(feature = "graph-rust")]
    pub(super) fn rust_parses(
        &mut self,
    ) -> &mut super::file_inventory::ParseOutcomes<pedant_core::resolution::rust::RustFileInventory>
    {
        &mut self.parsed_rust
    }

    /// Where the Go owner's parse outcomes are kept.
    #[cfg(feature = "graph-go")]
    pub(super) fn go_parses(
        &mut self,
    ) -> &mut super::file_inventory::ParseOutcomes<pedant_core::resolution::go::GoFileInventory>
    {
        &mut self.parsed_go
    }
}

/// A project owner's retained parser refusal for this physical source.
///
/// Resolution runs before loose admission. Once that parser has answered,
/// loose admission must not invoke a second grammar to replace the answer.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn parse_refusal(
    store: &RepositorySourceStore,
    path: &str,
    language: Language,
) -> Option<CodeIntelligenceError> {
    match language {
        #[cfg(feature = "graph-rust")]
        Language::Rust => store
            .parsed_rust
            .get(path)
            .and_then(|outcome| outcome.as_ref().err())
            .cloned(),
        #[cfg(feature = "graph-go")]
        Language::Go => store
            .parsed_go
            .get(path)
            .and_then(|outcome| outcome.as_ref().err())
            .cloned(),
        _ => None,
    }
}
