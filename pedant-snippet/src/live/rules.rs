//! The corpus walk's ignore rules, held open across batches and reopened when a
//! batch changes them.
//!
//! A matcher compiles and caches one matcher per directory it is asked about,
//! so held across batches it reads each `.gitignore` once for the life of the
//! index instead of once per report — and normalization asks it about every
//! source a host writes.
//!
//! Held open is what makes reopening necessary. A matcher answers from the
//! ignore files as they stood when it first reached each directory, so a rule
//! that stopped ignoring a tree would otherwise keep that tree out of every
//! later batch — a live index quietly no longer following its repository, which
//! is worse than the rebuild the rules exist to save.

use std::path::Path;
use std::sync::Mutex;

use ignore::IncrementalIgnore;

use crate::index::{CanonicalRoot, ignore_matcher};

use super::batch::EventBatch;
use super::change::ObservedChange;

/// The rules a live index keys its batches against.
pub(super) struct LiveRules {
    opened: Mutex<Option<IncrementalIgnore>>,
}

impl LiveRules {
    /// Open the rules for one repository root.
    pub(super) fn opened(root: &Path) -> Self {
        Self {
            opened: Mutex::new(ignore_matcher(root)),
        }
    }

    /// The batch one sequence of reported changes normalizes to.
    ///
    /// A refused lock is not a refusal a caller could act on: a live index
    /// whose rules were poisoned still keys every path the same way, and the
    /// only cost of normalizing without them is a rebuild that publishes what
    /// it already had. So the lock's own state is what is passed, and a
    /// poisoned one normalizes as a build with no rules does.
    pub(super) fn normalized(
        &self,
        root: &CanonicalRoot,
        observed: &[ObservedChange],
    ) -> EventBatch {
        let mut opened = self.opened.lock().unwrap_or_else(|held| held.into_inner());
        EventBatch::normalized(root, &mut opened, observed)
    }

    /// Open the rules again where the transaction that just ran changed them.
    ///
    /// Called under the indexer's lock, so the rules a batch keyed on the
    /// applying thread's own path are never older than the index it is keyed
    /// for.
    pub(super) fn reloaded(&self, root: &Path, reload: bool) {
        match reload {
            false => (),
            true => {
                let mut opened = self.opened.lock().unwrap_or_else(|held| held.into_inner());
                *opened = ignore_matcher(root);
            }
        }
    }
}
