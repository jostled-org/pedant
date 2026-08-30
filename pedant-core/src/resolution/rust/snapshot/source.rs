//! The source view: one snapshotted Rust file, its exact bytes, and its IR.

use std::sync::Arc;

use pedant_types::SourceRecord;

use crate::ir::FileIr;
use crate::resolution::line_index::SnapshotSource;
use crate::resolution::rust::inventory::RustFileInventory;
use crate::resolution::snapshot_record::SnapshotRecordOf;

/// One Rust source a snapshot reached, read and parsed exactly once.
///
/// The path, bytes, digest, and shared inventory are the record every language
/// keeps, so they are kept once, by the owner both languages read them through.
/// What this type adds is the Rust projection of that inventory: the one-pass
/// IR and the editions the tree is valid under.
#[derive(Debug)]
pub struct RustSource {
    record: SnapshotRecordOf<RustFileInventory>,
}

impl RustSource {
    /// Instantiate one provider record at the path this snapshot reached it by.
    pub(super) fn of_record(path: &Arc<str>, record: &SourceRecord<RustFileInventory>) -> Self {
        Self {
            record: SnapshotRecordOf::of_record(path, record),
        }
    }

    /// The repository-relative, `/`-separated path.
    pub fn path(&self) -> &str {
        self.record.path()
    }

    /// The same path, shared rather than copied, for the spans that name it.
    pub(in crate::resolution::rust) fn shared_path(&self) -> &Arc<str> {
        self.record.shared_path()
    }

    /// The exact UTF-8 text this snapshot read.
    pub fn text(&self) -> &str {
        self.record.text()
    }

    /// SHA-256 of the exact bytes behind [`Self::text`].
    pub fn digest(&self) -> &[u8; 32] {
        self.record.digest()
    }

    /// The one-pass IR extracted while the source was snapshotted.
    pub fn ir(&self) -> &FileIr {
        self.record.inventory().ir()
    }

    /// The strict-edition parse error this source only avoids under a pre-2021
    /// edition, absent when every edition parses it.
    pub(super) fn legacy_callable_trait_error(&self) -> Option<&str> {
        self.record.inventory().legacy_callable_trait_error()
    }
}

/// Delegated to the shared record, which is where both answers already live.
impl SnapshotSource for RustSource {
    fn path(&self) -> &str {
        self.record.path()
    }

    fn text(&self) -> &str {
        self.record.text()
    }
}
