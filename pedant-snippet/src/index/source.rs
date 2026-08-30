//! One admitted physical source, and everything this index retained about it.
//!
//! Held apart from the store that admits it. The store owns the reading, the
//! charging, and the ceilings; a record owns what one file turned out to be —
//! its exact text, the digest of exactly those bytes, the structures it
//! declares, and the language owner's inventory where one parsed it.
//!
//! The two constructors below are the whole difference between a syntax-only
//! outline and a resolved source. Everything else about a record is the same
//! derivation over both, which is why the language-specific inventory is the
//! only field either constructor sets on its own.

use std::sync::Arc;

use pedant_types::{Language, StructureRecord};

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use super::file_inventory::FileInventory;

/// One admitted physical source: its text, its digest, and what it declares.
#[derive(Clone, Debug)]
pub(crate) struct StoredSource {
    text: Arc<str>,
    digest: [u8; 32],
    language: Language,
    structures: Arc<[StructureRecord]>,
    /// Where the definition each structure states sits, as its own language
    /// owner named it. Empty for a source no resolver reads, because a
    /// syntax-only outline has no report to join to.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    definitions: Arc<[Option<pedant_types::StructureSpan>]>,
    #[cfg(feature = "graph-rust")]
    rust: Option<Arc<pedant_core::resolution::rust::RustFileInventory>>,
    #[cfg(feature = "graph-go")]
    go: Option<Arc<pedant_core::resolution::go::GoFileInventory>>,
}

impl StoredSource {
    /// One source whose structures are the whole answer its language states.
    pub(super) fn syntax(
        text: Arc<str>,
        digest: [u8; 32],
        language: Language,
        structures: Box<[StructureRecord]>,
    ) -> Self {
        Self {
            text,
            digest,
            language,
            structures: structures.into(),
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            definitions: Arc::from([]),
            #[cfg(feature = "graph-rust")]
            rust: None,
            #[cfg(feature = "graph-go")]
            go: None,
        }
    }

    /// One source its own language owner parsed, with the definition sites that
    /// owner stated beside each structure.
    ///
    /// The language-specific inventory is left absent and set by the caller,
    /// because that one field is the whole difference between the two owners:
    /// the structures, the definition sites, and the text are the same
    /// derivation over both.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    fn resolved<Inventory: FileInventory>(
        text: Arc<str>,
        digest: [u8; 32],
        language: Language,
        inventory: &Inventory,
    ) -> Self {
        let structures = inventory.structures();
        Self {
            text,
            digest,
            language,
            definitions: (0..structures.len())
                .map(|position| inventory.definition_span(position))
                .collect(),
            structures: Arc::from(structures),
            #[cfg(feature = "graph-rust")]
            rust: None,
            #[cfg(feature = "graph-go")]
            go: None,
        }
    }

    /// One source the Rust language owner parsed.
    #[cfg(feature = "graph-rust")]
    pub(super) fn rust(
        text: Arc<str>,
        digest: [u8; 32],
        inventory: Arc<pedant_core::resolution::rust::RustFileInventory>,
    ) -> Self {
        let stated = Self::resolved(text, digest, Language::Rust, inventory.as_ref());
        Self {
            rust: Some(inventory),
            ..stated
        }
    }

    /// One source the Go language owner parsed.
    #[cfg(feature = "graph-go")]
    pub(super) fn go(
        text: Arc<str>,
        digest: [u8; 32],
        inventory: Arc<pedant_core::resolution::go::GoFileInventory>,
    ) -> Self {
        let stated = Self::resolved(text, digest, Language::Go, inventory.as_ref());
        Self {
            go: Some(inventory),
            ..stated
        }
    }

    /// The Rust inventory this record was parsed by, when a Rust owner parsed
    /// it.
    #[cfg(feature = "graph-rust")]
    pub(super) fn rust_inventory(
        &self,
    ) -> Option<&Arc<pedant_core::resolution::rust::RustFileInventory>> {
        self.rust.as_ref()
    }

    /// The Go inventory this record was parsed by, when a Go owner parsed it.
    #[cfg(feature = "graph-go")]
    pub(super) fn go_inventory(
        &self,
    ) -> Option<&Arc<pedant_core::resolution::go::GoFileInventory>> {
        self.go.as_ref()
    }

    /// The exact UTF-8 text that was read.
    pub(crate) fn text(&self) -> &Arc<str> {
        &self.text
    }

    /// SHA-256 of the exact bytes behind that text.
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The language the source was recognized as.
    pub(crate) fn language(&self) -> Language {
        self.language
    }

    /// Every logical structure the source declares, in source order.
    pub(crate) fn structures(&self) -> &[StructureRecord] {
        &self.structures
    }

    /// Where the definition the structure at `position` states sits.
    ///
    /// Absent for a source no resolver read and for a declaration that states
    /// no definition, which are the two ways a structure has no graph node to
    /// be joined to.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn definition_span(&self, position: usize) -> Option<pedant_types::StructureSpan> {
        self.definitions.get(position).copied().flatten()
    }
}
