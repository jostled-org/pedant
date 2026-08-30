//! Every report about one path, reduced to one row.
//!
//! Two bits rather than a sequence of kinds, because that is what the kinds
//! carry: a create says the path was absent, a remove says it is absent now,
//! and a modify says neither. Every ordering of any number of reports about one
//! path therefore folds to one row without a table of pairs to keep exhaustive.

use std::sync::Arc;

use super::change::{ChangeKind, ChangeRole, SourceChange};

/// Whether one path was there when a batch opened, and whether it is there now.
pub(super) struct Folded {
    role: ChangeRole,
    existed: bool,
    exists: bool,
}

impl Folded {
    /// What the first report about one path establishes.
    pub(super) fn opened(role: ChangeRole, kind: ChangeKind) -> Self {
        Self {
            role,
            existed: !matches!(kind, ChangeKind::Created),
            exists: !matches!(kind, ChangeKind::Removed),
        }
    }

    /// What a later report about the same path establishes.
    pub(super) fn observe(&mut self, kind: ChangeKind) {
        self.exists = !matches!(kind, ChangeKind::Removed);
    }

    /// The one row every report about this path adds up to.
    ///
    /// A path created and then removed inside one batch is stated as removed:
    /// what the batch leaves behind is a path that is not there, and calling it
    /// a creation would name a file no rebuild can find.
    pub(super) fn stated(self, path: Arc<str>) -> SourceChange {
        let kind = match (self.existed, self.exists) {
            (false, true) => ChangeKind::Created,
            (true, true) => ChangeKind::Modified,
            _ => ChangeKind::Removed,
        };
        SourceChange::stated(self.role, path, kind)
    }
}
