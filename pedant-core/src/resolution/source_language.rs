//! Everything one language decides about admitting its own sources.
//!
//! Four decisions, and they are the four the two reference providers genuinely
//! disagree on: the ceilings they run beneath, where a repository-relative
//! request lands on disk, what a refused read or decode is called, and what a
//! decoded source states. Everything else about an admission — the order the
//! ceilings are charged in, the digest, the counters — belongs to the one
//! [`RecordCache`](super::record_cache::RecordCache) that reads through this.

use std::path::{Path, PathBuf};

use super::read::{ByteCeilings, ReadFault};

/// The language-owned half of one source admission.
///
/// The byte ceilings are the supertrait's, because they are the one part of
/// this contract the bounded read itself enforces: a language that stated them
/// here as well would be stating them twice for one comparison.
pub(crate) trait SourceLanguage: ByteCeilings {
    /// The fact inventory this language's owner extracts from one source.
    type Inventory;

    /// Why this language states no record for a normalized path.
    type Fault;

    /// The most distinct sources one provider may admit.
    fn max_source_files(&self) -> u32;

    /// This language's own refusal for one source past that ceiling.
    fn source_files_fault(&self) -> Self::Fault;

    /// This language's own refusal for a path this provider already refused.
    ///
    /// A refused admission is remembered, so a path several units reach is
    /// opened, decoded, and inventoried at most once however often it is asked
    /// for. The first refusal cannot be handed out twice — an `io::Error` and a
    /// parser's own reason are moved into it — so each language states what a
    /// path it has already refused reads like in its own vocabulary.
    fn refused_again(&self, path: &str) -> Self::Fault;

    /// Where one repository-relative request lands beneath `root`.
    ///
    /// The one deliberate difference between the two languages: a Rust request
    /// the filesystem cannot resolve is unreadable rather than absent, while a
    /// Go request the root does not hold yet falls through to the read, which
    /// reports it with the filesystem's own reason.
    fn confine(&self, root: &Path, relative: &str) -> Result<PathBuf, Self::Fault>;

    /// This language's own fault for one refused read.
    fn refusal(&self, fault: ReadFault) -> Self::Fault;

    /// The text those bytes state, or this language's own fault for bytes that
    /// state none.
    fn decode(&self, bytes: Vec<u8>) -> Result<String, Self::Fault>;

    /// Everything one decoded source declares, extracted exactly once.
    fn inventory(&self, path: &str, text: &str) -> Result<Self::Inventory, Self::Fault>;
}
