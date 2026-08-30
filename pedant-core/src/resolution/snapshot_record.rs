//! One snapshotted source, whatever language read it.
//!
//! Every language's snapshot source is the same four values — the path this
//! snapshot reached the file by, the exact bytes, their digest, and the one
//! shared inventory the provider extracted — and the same two answers a line
//! table is built from. One owner, because two copies of that record were two
//! places for "which path is this source named under" and "which bytes was this
//! digest taken over" to drift apart between languages that must agree.
//!
//! What a language type adds is its own projection of the inventory: a Rust
//! source answers with its IR, a Go source with its facts and build predicates.
//! That is the whole of what the two genuinely disagree on, so that is all each
//! one keeps.

use std::sync::Arc;

use pedant_types::SourceRecord;

/// One source a snapshot reached, read and inventoried exactly once.
///
/// The inventory is shared rather than owned, because the read that produced it
/// belongs to the provider and may be older than this snapshot: a file two
/// project slices reach is one read, and both slices instantiate the same facts.
#[derive(Debug)]
pub(crate) struct SnapshotRecordOf<Inventory> {
    path: Arc<str>,
    text: Arc<str>,
    digest: [u8; 32],
    inventory: Arc<Inventory>,
}

impl<Inventory> SnapshotRecordOf<Inventory> {
    /// Instantiate one provider record at the path this snapshot reached it by.
    ///
    /// The path is the snapshot's; the text, digest, and inventory are shared
    /// from the provider record.
    pub(crate) fn of_record(path: &Arc<str>, record: &SourceRecord<Inventory>) -> Self {
        Self {
            path: Arc::clone(path),
            text: record.shared_text(),
            digest: *record.digest(),
            inventory: record.shared_facts(),
        }
    }

    /// The repository-relative, `/`-separated path.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// The same path, shared rather than copied, for the spans that name it.
    pub(crate) fn shared_path(&self) -> &Arc<str> {
        &self.path
    }

    /// The exact UTF-8 text this snapshot read.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// SHA-256 of the exact bytes behind [`Self::text`].
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Everything the provider extracted from this source, shared.
    pub(crate) fn inventory(&self) -> &Inventory {
        &self.inventory
    }
}
