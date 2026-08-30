//! What every language owner states about one source it parsed.
//!
//! Each owner publishes the same admission: read the file, parse it beneath its
//! own ceilings, translate its own refusal, keep the inventory beside the text,
//! and answer from what is already held. Reached through their concrete types,
//! the store wrote that whole sequence once per language — two bodies differing
//! in four names.
//!
//! Named here instead, so a third owner adds an implementation rather than a
//! third copy of the sequence, and so a change to what a definition site or a
//! parse refusal means changes one place. The same collapse `SourceProviderOf`
//! is in `pedant-core`, from the other side of the same seam.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{StructureRecord, StructureSpan};

use super::error::CodeIntelligenceError;
use super::limits::CodeIntelligenceLimits;
use super::source::StoredSource;
use super::store::RepositorySourceStore;

/// What one language owner's parse of each path it reached produced.
///
/// Keyed for the reason a read outcome is: a refusal retains no record, so the
/// next target reaching the same unparseable file finds nothing to answer from.
/// A workspace whose library compiles into four targets parsed each malformed
/// source four times, to arrive four times at the sentence the first parse
/// already stated.
pub(crate) type ParseOutcomes<Inventory> =
    BTreeMap<Arc<str>, Result<Arc<Inventory>, CodeIntelligenceError>>;

/// One language owner's file inventory, and everything admitting it takes.
///
/// A generic bound rather than a trait object: every implementor is known at
/// the call site that names it, and the dispatch costs nothing.
pub(crate) trait FileInventory: Sized {
    /// The ceilings this owner parses one source beneath.
    type Limits: Copy;

    /// The refusal this owner states when it cannot.
    type Fault;

    /// Every logical structure the source declares, in source order.
    fn structures(&self) -> &[StructureRecord];

    /// Where the definition the structure at `position` states sits.
    ///
    /// Absent for a declaration that states no definition, which is how a
    /// structure comes to have no graph node to be joined to.
    fn definition_span(&self, position: usize) -> Option<StructureSpan>;

    /// This owner's own ceilings, out of the index's configured limits.
    fn limits(limits: &CodeIntelligenceLimits) -> Self::Limits;

    /// Parse one source's exact retained text.
    ///
    /// # Errors
    ///
    /// Whatever this owner's own parse states, unchanged.
    fn of_source(path: &str, text: &str, limits: Self::Limits) -> Result<Self, Self::Fault>;

    /// One parse refusal as this crate's own vocabulary names it, keeping the
    /// typed ceiling where the fault carried one.
    fn fault(path: &str, fault: &Self::Fault) -> CodeIntelligenceError;

    /// The inventory an admitted record already holds for this owner.
    fn held(record: &StoredSource) -> Option<Arc<Self>>;

    /// One admitted record this owner parsed.
    fn stored(text: Arc<str>, digest: [u8; 32], inventory: Arc<Self>) -> StoredSource;

    /// Where this owner's parse outcomes are kept in the shared store.
    fn outcomes(store: &mut RepositorySourceStore) -> &mut ParseOutcomes<Self>;
}

// Each structure and definition-site answer forwards to the owner's own
// accessor of the same name, qualified through the concrete type. Inherent
// resolution would pick that accessor unqualified too, which is exactly the
// problem: an accessor removed there turns the forward into a call to this
// trait method, and the forward becomes unbounded recursion that compiles.
#[cfg(feature = "graph-rust")]
impl FileInventory for pedant_core::resolution::rust::RustFileInventory {
    type Limits = u32;
    type Fault = pedant_core::resolution::rust::RustSourceFault;

    fn structures(&self) -> &[StructureRecord] {
        pedant_core::resolution::rust::RustFileInventory::structures(self)
    }

    fn definition_span(&self, position: usize) -> Option<StructureSpan> {
        pedant_core::resolution::rust::RustFileInventory::definition_span(self, position)
    }

    fn limits(limits: &CodeIntelligenceLimits) -> Self::Limits {
        limits.rust.max_syntax_depth
    }

    fn of_source(path: &str, text: &str, limits: Self::Limits) -> Result<Self, Self::Fault> {
        pedant_core::resolution::rust::RustFileInventory::of_source(path, text, limits)
    }

    fn fault(path: &str, fault: &Self::Fault) -> CodeIntelligenceError {
        match super::rust_slices::source_capacity(fault) {
            Some(error) => error,
            None => parser_fault(path, fault),
        }
    }

    fn held(record: &StoredSource) -> Option<Arc<Self>> {
        record.rust_inventory().map(Arc::clone)
    }

    fn stored(text: Arc<str>, digest: [u8; 32], inventory: Arc<Self>) -> StoredSource {
        StoredSource::rust(text, digest, inventory)
    }

    fn outcomes(store: &mut RepositorySourceStore) -> &mut ParseOutcomes<Self> {
        store.rust_parses()
    }
}

#[cfg(feature = "graph-go")]
impl FileInventory for pedant_core::resolution::go::GoFileInventory {
    type Limits = pedant_syntax::go::GoFactLimits;
    type Fault = pedant_core::resolution::go::GoSourceFault;

    fn structures(&self) -> &[StructureRecord] {
        pedant_core::resolution::go::GoFileInventory::structures(self)
    }

    fn definition_span(&self, position: usize) -> Option<StructureSpan> {
        pedant_core::resolution::go::GoFileInventory::definition_span(self, position)
    }

    fn limits(limits: &CodeIntelligenceLimits) -> Self::Limits {
        pedant_syntax::go::GoFactLimits::new(
            limits.go.max_syntax_depth,
            limits.go.max_facts_per_source,
        )
    }

    fn of_source(path: &str, text: &str, limits: Self::Limits) -> Result<Self, Self::Fault> {
        pedant_core::resolution::go::GoFileInventory::of_source(path, text, limits)
    }

    fn fault(path: &str, fault: &Self::Fault) -> CodeIntelligenceError {
        match super::go_slices::source_capacity(fault) {
            Some(error) => error,
            None => parser_fault(path, fault),
        }
    }

    fn held(record: &StoredSource) -> Option<Arc<Self>> {
        record.go_inventory().map(Arc::clone)
    }

    fn stored(text: Arc<str>, digest: [u8; 32], inventory: Arc<Self>) -> StoredSource {
        StoredSource::go(text, digest, inventory)
    }

    fn outcomes(store: &mut RepositorySourceStore) -> &mut ParseOutcomes<Self> {
        store.go_parses()
    }
}

/// One language owner's non-capacity parse fault, as this crate states it.
///
/// The owner's own displayed sentence, not its `Debug` shape. Every fault type
/// reaching here is a `thiserror` enum whose variants each author the sentence
/// that names the failure, and a derive dump printed in its place would hand an
/// operator the field names instead of the reason. The loose inventory refusal
/// beside this one reads the same `Display`.
fn parser_fault(path: &str, fault: &impl std::fmt::Display) -> CodeIntelligenceError {
    CodeIntelligenceError::Parser {
        path: Box::from(path),
        reason: fault.to_string().into_boxed_str(),
    }
}
