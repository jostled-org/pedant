//! The source view: one snapshotted Go file, its exact bytes, its retained
//! predicates, and its fact inventory.

use std::sync::Arc;

use pedant_types::SourceRecord;

use crate::resolution::line_index::SnapshotSource;
use crate::resolution::snapshot_record::SnapshotRecordOf;

use super::condition::GoBuildCondition;
use super::facts::GoSourceFacts;
use super::inventory::GoFileInventory;

/// One Go source a snapshot reached, read, parsed, and walked exactly once.
///
/// The path, bytes, digest, and shared inventory are the record every language
/// keeps, so they are kept once, by the owner both languages read them through.
/// What this type adds is the Go projection of that inventory: the grammar
/// facts and the build predicates the source carries unevaluated.
#[derive(Debug)]
pub struct GoSource {
    record: SnapshotRecordOf<GoFileInventory>,
}

impl GoSource {
    /// Take one provider record at the path this snapshot reached it by.
    pub(super) fn of_record(path: &Arc<str>, record: &SourceRecord<GoFileInventory>) -> Self {
        Self {
            record: SnapshotRecordOf::of_record(path, record),
        }
    }

    /// The repository-relative, `/`-separated path.
    pub fn path(&self) -> &str {
        self.record.path()
    }

    /// The exact UTF-8 text this snapshot read.
    pub fn text(&self) -> &str {
        self.record.text()
    }

    /// SHA-256 of the exact bytes behind [`Self::text`].
    pub fn digest(&self) -> &[u8; 32] {
        self.record.digest()
    }

    /// Every unevaluated build predicate this source carries.
    ///
    /// Empty for a source every build compiles. A non-empty list is evidence a
    /// consumer states as possible, never a decision this tier made.
    pub fn conditions(&self) -> &[GoBuildCondition] {
        self.record.inventory().conditions()
    }

    /// The structured grammar facts extracted while this source was
    /// snapshotted.
    pub fn facts(&self) -> &GoSourceFacts {
        self.record.inventory().facts()
    }
}

/// Delegated to the shared record, which is where both answers already live.
impl SnapshotSource for GoSource {
    fn path(&self) -> &str {
        self.record.path()
    }

    fn text(&self) -> &str {
        self.record.text()
    }
}
