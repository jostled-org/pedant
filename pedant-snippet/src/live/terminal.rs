//! The refusal a live index answers with once its applying thread has stopped.
//!
//! The applying thread has nobody to return to. It receives, settles, applies,
//! and on a refusal it reports to stderr and returns — and a thread that
//! returned is a thread nothing joins until shutdown, which may be hours later
//! or never. So the refusal is recorded here, and every later query, ledger
//! read, and shutdown states it.
//!
//! Its own owner rather than a field of the index it reports on, because the
//! owners it reports about are exactly the ones a refusal says are unusable: a
//! record kept behind the indexer's lock would be unreadable in the one case it
//! exists for.

use std::sync::Mutex;

use super::error::LiveIndexError;

/// Why the applying thread stopped, once it has.
#[derive(Default)]
pub(super) struct Terminal {
    stated: Mutex<Option<LiveIndexError>>,
}

impl Terminal {
    /// The refusal every later answer states, if there is one.
    ///
    /// Permanent once present. What the thread refused was an owner a panic
    /// left unusable, so nothing advances the index afterwards and every answer
    /// from it would be a claim about a repository this process stopped
    /// following.
    ///
    /// A poisoned lock here is recovered rather than reported. This is the one
    /// owner whose whole job is stating a refusal, and refusing to read it
    /// would swallow the refusal it holds.
    pub(super) fn stated(&self) -> Option<LiveIndexError> {
        self.stated
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .clone()
    }

    /// Record why the applying thread stopped.
    ///
    /// Called once. The applying thread returns on its first refusal, so there
    /// is never a second one to choose between.
    pub(super) fn record(&self, reason: LiveIndexError) {
        *self.stated.lock().unwrap_or_else(|held| held.into_inner()) = Some(reason);
    }
}
