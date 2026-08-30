//! The seam between one project loader's paths and the repository's.
//!
//! A project loader is rooted at its own authority's directory and asks for
//! paths relative to that. The store keys records by the path the repository
//! knows them under, because that is the only key under which two slices asking
//! for the same file ask the same question. This wrapper is where those two
//! spellings meet, through the same [`join::beneath_into`](super::join) the
//! slice producers join a directory and a relative path with — one join, so a
//! loader's request and the path its slice reports cannot become two strings
//! for one file.
//!
//! It also records what each slice reached, which is not something either side
//! knows on its own: the loader knows the paths it asked for and the store
//! knows every path anyone asked for.

use std::collections::BTreeSet;
use std::sync::Arc;

use pedant_types::{SourcePath, SourceProvider, SourceRecord};

use super::error::{CodeIntelligenceError, LoaderCeiling};
use super::file_inventory::FileInventory;
use super::join::beneath_into;
use super::store::RepositorySourceStore;

/// One project slice's view of the shared store.
pub(crate) struct ScopedSources<'store> {
    store: &'store mut RepositorySourceStore,
    prefix: Box<str>,
    /// The repository spelling of the path being asked for, reused across every
    /// request. A loader asks for one path at a time and the store answers from
    /// what it holds, so the joined spelling dies inside the lookup that reads
    /// it.
    joined: String,
    reached: BTreeSet<Arc<str>>,
    capacity: Option<CodeIntelligenceError>,
}

impl<'store> ScopedSources<'store> {
    /// A view whose requests are resolved beneath `prefix`.
    ///
    /// The prefix is the authority's own directory, empty for an authority at
    /// the repository root.
    pub(crate) fn new(store: &'store mut RepositorySourceStore, prefix: &str) -> Self {
        Self {
            store,
            prefix: Box::from(prefix),
            joined: String::new(),
            reached: BTreeSet::new(),
            capacity: None,
        }
    }

    /// Record that this slice reached the path now in the buffer.
    ///
    /// The shared key is minted only where the set does not already hold one. A
    /// compilation closure asks for the same module through several units, and
    /// every one of those asks used to mint an `Arc<str>` for a set that already
    /// held it.
    fn reaching(&mut self) {
        if !self.reached.contains(self.joined.as_str()) {
            self.reached.insert(Arc::from(self.joined.as_str()));
        }
    }

    /// Every repository path this slice reached, sorted.
    pub(crate) fn reached(self) -> Box<[Arc<str>]> {
        self.reached.into_iter().collect()
    }

    /// Take the typed capacity refusal a loader vocabulary could not preserve.
    pub(crate) fn take_capacity(&mut self) -> Option<CodeIntelligenceError> {
        self.capacity.take()
    }

    /// Retain one capacity refusal before translating it for a loader.
    ///
    /// First wins. A closure walk collects failures and keeps going, so several
    /// refusals can arrive inside one snapshot, and the slice producers state
    /// the rule this must hold to: the provider refused first and named the
    /// ceiling it crossed. Overwriting reported the last ceiling instead.
    fn remember_capacity(&mut self, error: CodeIntelligenceError) {
        if self.capacity.is_none() && matches!(&error, CodeIntelligenceError::Capacity { .. }) {
            self.capacity = Some(error);
        }
    }

    /// One loader's request, answered from the shared store.
    ///
    /// The whole sequence a `SourceProvider` owes, written once: join into the
    /// repository spelling, ask the store, retain the typed refusal before the
    /// loader's vocabulary flattens it, and record what the slice reached only
    /// on the answer. Each language differs in the inventory it asks for and in
    /// how it spells a refusal, and both of those are arguments — so the order
    /// of the four steps is stated in one place rather than once per owner,
    /// where a second copy could record a reach the store never granted.
    fn admitted<Inventory: FileInventory, Fault>(
        &mut self,
        path: SourcePath<'_>,
        stated: fn(&CodeIntelligenceError) -> Fault,
    ) -> Result<SourceRecord<Inventory>, Fault> {
        beneath_into(&mut self.joined, &self.prefix, path.as_str());
        match self.store.admit_resolved(&self.joined) {
            Ok(record) => {
                self.reaching();
                Ok(record)
            }
            Err(error) => {
                let fault = stated(&error);
                self.remember_capacity(error);
                Err(fault)
            }
        }
    }
}

/// One store refusal as the Rust loader's own fault vocabulary states it.
///
/// The three ceilings the loader has a word for are classified by
/// [`LoaderCeiling`] and spelled here. Everything else — a refusal the loader's
/// vocabulary cannot name, and every ceiling that is not one of the three —
/// reaches it as this crate's own sentence, through the one tail below.
#[cfg(feature = "graph-rust")]
fn rust_fault(error: &CodeIntelligenceError) -> pedant_core::resolution::rust::RustSourceFault {
    use pedant_core::resolution::rust::RustSourceFault;

    match error {
        CodeIntelligenceError::SymlinkEscape { path, landing } => RustSourceFault::OutOfRoot {
            path: path.clone(),
            landing: landing.clone(),
        },
        CodeIntelligenceError::SourceEncoding { reason, .. } => RustSourceFault::InvalidUtf8 {
            reason: reason.clone(),
        },
        CodeIntelligenceError::Parser { reason, .. } => RustSourceFault::Unparsed {
            reason: reason.clone(),
        },
        CodeIntelligenceError::Capacity {
            collection, limit, ..
        } => rust_ceiling(LoaderCeiling::of_collection(*collection), *limit, error),
        other => RustSourceFault::Unreadable(std::io::Error::other(other.to_string())),
    }
}

/// One classified repository ceiling as the Rust loader spells it.
///
/// An unclassified ceiling is one the loader has no word for, and it reaches
/// the loader as the refusal's own sentence rather than as a source-file count
/// it never crossed.
#[cfg(feature = "graph-rust")]
fn rust_ceiling(
    ceiling: Option<LoaderCeiling>,
    limit: u64,
    error: &CodeIntelligenceError,
) -> pedant_core::resolution::rust::RustSourceFault {
    use pedant_core::resolution::rust::RustSourceFault;

    match ceiling {
        Some(LoaderCeiling::SourceFiles) => RustSourceFault::SourceFiles { ceiling: limit },
        Some(LoaderCeiling::SourceBytes) => RustSourceFault::SourceBytes { ceiling: limit },
        Some(LoaderCeiling::TotalBytes) => RustSourceFault::TotalBytes { ceiling: limit },
        None => RustSourceFault::Unreadable(std::io::Error::other(error.to_string())),
    }
}

/// One store refusal as the Go loader's own fault vocabulary states it.
///
/// The same shape as [`rust_fault`], over the same classification and the same
/// tail. Only the spelling of each answer is this language's.
#[cfg(feature = "graph-go")]
fn go_fault(error: &CodeIntelligenceError) -> pedant_core::resolution::go::GoSourceFault {
    use pedant_core::resolution::go::GoSourceFault;

    match error {
        CodeIntelligenceError::SymlinkEscape { landing, .. } => GoSourceFault::OutOfRoot {
            path: landing.clone(),
        },
        CodeIntelligenceError::SourceEncoding { reason, .. } => GoSourceFault::NonUtf8 {
            reason: reason.clone(),
        },
        CodeIntelligenceError::Parser { reason, .. } => GoSourceFault::Unparsed {
            reason: reason.clone(),
        },
        CodeIntelligenceError::Capacity {
            collection, limit, ..
        } => go_ceiling(LoaderCeiling::of_collection(*collection), *limit, error),
        other => GoSourceFault::Unreadable(std::io::Error::other(other.to_string())),
    }
}

/// One classified repository ceiling as the Go loader spells it.
///
/// The same tail as [`rust_ceiling`], for the same reason.
#[cfg(feature = "graph-go")]
fn go_ceiling(
    ceiling: Option<LoaderCeiling>,
    limit: u64,
    error: &CodeIntelligenceError,
) -> pedant_core::resolution::go::GoSourceFault {
    use pedant_core::resolution::go::GoSourceFault;

    match ceiling {
        Some(LoaderCeiling::SourceFiles) => GoSourceFault::SourceFiles {
            ceiling: super::count::narrowed(limit),
        },
        Some(LoaderCeiling::SourceBytes) => GoSourceFault::SourceBytes { ceiling: limit },
        Some(LoaderCeiling::TotalBytes) => GoSourceFault::TotalBytes { ceiling: limit },
        None => GoSourceFault::Unreadable(std::io::Error::other(error.to_string())),
    }
}

#[cfg(feature = "graph-rust")]
impl SourceProvider<pedant_core::resolution::rust::RustFileInventory> for ScopedSources<'_> {
    type Error = pedant_core::resolution::rust::RustSourceFault;

    fn source(
        &mut self,
        path: SourcePath<'_>,
    ) -> Result<
        SourceRecord<pedant_core::resolution::rust::RustFileInventory>,
        pedant_core::resolution::rust::RustSourceFault,
    > {
        self.admitted(path, rust_fault)
    }
}

#[cfg(feature = "graph-go")]
impl SourceProvider<pedant_core::resolution::go::GoFileInventory> for ScopedSources<'_> {
    type Error = pedant_core::resolution::go::GoSourceFault;

    fn source(
        &mut self,
        path: SourcePath<'_>,
    ) -> Result<
        SourceRecord<pedant_core::resolution::go::GoFileInventory>,
        pedant_core::resolution::go::GoSourceFault,
    > {
        self.admitted(path, go_fault)
    }
}
