//! The live index a server holds: one published state, and the transactions
//! that replace it.

use std::path::Path;
use std::sync::Arc;

use crate::index::{CodeIntelligenceLimits, CodeIntelligenceState, ProjectAuthority};

use super::batch::EventBatch;
use super::change::ObservedChange;
use super::core::LiveCore;
use super::error::LiveIndexError;
use super::transaction::{LiveLedger, LiveTransaction};
use super::watcher::RootWatcher;

/// One repository, indexed once and kept current.
///
/// The immutable index is what makes this shape work. Every question is
/// answered from one cloned [`CodeIntelligenceState`], taken under a read lock
/// that is released before the answer is computed, so a rebuild running beside
/// it changes what the *next* question is answered from and never what this one
/// is part-way through.
///
/// Nothing here writes repository data or retains anything across a process.
/// The index is built from the tree each time; there is no persistent cache to
/// invalidate, and no file this crate would have to own the removal of.
pub struct LiveCodeIntelligenceIndex {
    core: Arc<LiveCore>,
}

impl LiveCodeIntelligenceIndex {
    /// Index the repository beneath `root` and hold the result live.
    ///
    /// No watcher starts here. A caller that wants one asks for it, because the
    /// CLI builds one state and answers from it while the server watches, and
    /// starting a thread for the one that does not want it would be a
    /// capability nobody asked for.
    ///
    /// # Errors
    ///
    /// Every fatal classification the first build states: an unusable root, a
    /// path that escapes it, an explicit authority that does not load, and any
    /// repository-wide ceiling the admitted corpus passes.
    pub fn open(
        root: &Path,
        authorities: &[ProjectAuthority],
        limits: CodeIntelligenceLimits,
    ) -> Result<Self, LiveIndexError> {
        Ok(Self {
            core: Arc::new(LiveCore::opened(root, authorities, limits)?),
        })
    }

    /// The state every question asked now is answered from.
    ///
    /// # Errors
    ///
    /// A panic in another thread that held the live state, and the refusal the
    /// applying thread ended on. The second outlives the call that met it: an
    /// index nothing advances is answering about a repository this process
    /// stopped following, which no state it holds can say for itself.
    pub fn state(&self) -> Result<Arc<CodeIntelligenceState>, LiveIndexError> {
        self.core.state()
    }

    /// The batch one sequence of reported changes normalizes to.
    ///
    /// Published beside [`apply`](Self::apply) because the watcher is one
    /// source of reported changes and not the only possible one: a host that
    /// learns about changes another way states them here and gets the same
    /// transaction the watcher would have produced.
    ///
    /// A caller that normalizes here and applies afterwards owns the gap
    /// between the two calls. A transaction landing in between may reopen the
    /// corpus walk's ignore rules, leaving this batch keyed against rules one
    /// reload old; the watcher's own path has no such gap, because it keys and
    /// applies under one hold of the same lock.
    pub fn normalized(&self, observed: &[ObservedChange]) -> EventBatch {
        self.core.normalized(observed)
    }

    /// Apply one normalized batch as a single transaction.
    ///
    /// One batch is one publish. A rebuild that refuses keeps the last good
    /// index and publishes a state carrying the refusal, so the failure reaches
    /// every later response rather than only this caller.
    ///
    /// The batch is taken by value: it is moved into the transaction and from
    /// there into the ledger, and the transaction handed back is the one copy
    /// this call makes, for the caller that reads it. The watcher applies
    /// through a path that makes none.
    ///
    /// # Errors
    ///
    /// A panic in another thread that held the live state.
    pub fn apply(&self, batch: EventBatch) -> Result<LiveTransaction, LiveIndexError> {
        self.core.applied(batch)
    }

    /// Observe the repository root and apply every batch it reports.
    ///
    /// The returned owner is the watcher's whole lifetime: dropping it stops
    /// observing and joins the applying thread, and
    /// [`shutdown`](RootWatcher::shutdown) does the same and says whether the
    /// thread ended cleanly.
    ///
    /// The applying thread's first transaction is a rebuild nothing reported.
    /// The observation registers after [`open`](Self::open) has already built an
    /// index, and on a large tree that build is seconds long — every change made
    /// inside it raised no event this process will ever see, and no later report
    /// names those files again. One rebuild started after the observation is
    /// registered reaches all of them.
    ///
    /// # Errors
    ///
    /// A host notification layer that will not observe the root, and a host
    /// that will not start the applying thread.
    pub fn watch(&self) -> Result<RootWatcher, LiveIndexError> {
        RootWatcher::started(&self.core)
    }

    /// What this live index has applied since it opened.
    ///
    /// # Errors
    ///
    /// A panic in another thread that held the live state, and the refusal the
    /// applying thread ended on. This is the more misleading of the two to
    /// swallow: the ledger is what an operator reads to tell "nothing changed"
    /// from "every rebuild failed", and counters frozen where the thread died
    /// read as the first.
    pub fn ledger(&self) -> Result<LiveLedger, LiveIndexError> {
        self.core.ledger()
    }
}
