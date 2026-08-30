//! The shared owner behind a live index: one state, one indexer, one ledger.
//!
//! A query clones the published `Arc` while holding the read lock, releases the
//! lock, and computes from the clone. That is the whole concurrency story, and
//! it works because the value it cloned is immutable: no caller can observe a
//! half-rebuilt tree, because there is no such value to observe. An update
//! builds a whole new state and swaps it in one assignment.
//!
//! Updates are serialized by the indexer's own lock rather than by the state's.
//! Two reasons, and both are correctness rather than economy. The indexer holds
//! the bounded graph store, which one revision at a time may write. And a
//! transaction is the keying of a batch, a rebuild, the publish that follows
//! it, the reopening of the rules the next batch is keyed against, *and* the
//! record that follows all of it — so releasing between any two of them would
//! let two updates finish in one order and land in the other, leaving the newer
//! tree behind the older one, or the ledger naming a transaction older than the
//! state a caller can already read.
//!
//! Nothing on that path copies a batch. The batch is moved from the caller into
//! the transaction and from the transaction into the ledger, so the only copy
//! anything pays for is the one a caller reading the transaction back asked
//! for.
//!
//! One refusal outlives the call that met it. The applying thread has nobody to
//! return to, so a transaction it could not finish is recorded on the
//! [`Terminal`] and every later answer states it. Without that a poisoned
//! indexer or ledger — neither of which a query reads — left the published
//! state answering `Ok` forever from an index nothing would ever advance again.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use crate::index::{
    CanonicalRoot, CodeIntelligenceIndexer, CodeIntelligenceLimits, CodeIntelligenceState,
    ProjectAuthority, stalled,
};

use super::batch::EventBatch;
use super::change::ObservedChange;
use super::error::{LiveIndexError, PoisonedOwner};
use super::rules::LiveRules;
use super::terminal::Terminal;
use super::transaction::{LiveLedger, LiveTransaction, TransactionOutcome};

/// Why one transaction is running.
///
/// Both of the questions a transaction asks about its own batch are answered
/// from this rather than from the batch alone: whether a batch that selects
/// nothing rebuilds, and whether the corpus walk's ignore rules are reopened
/// afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionCause {
    /// A batch of changes something reported.
    Reported,
    /// The observation of the root has just been registered.
    Registered,
}

impl TransactionCause {
    /// Whether this transaction rebuilds the index at all.
    ///
    /// A reported batch that selects nothing rebuilds nothing: normalization
    /// already established that no path in it is one this index admits, and
    /// rebuilding to reach the same corpus would publish a revision equal to
    /// the one already published.
    ///
    /// A registration always rebuilds, and its batch is empty for the same
    /// reason it must. What it covers is every change made while the first
    /// index was building, which raised no event this process will ever see and
    /// which no later report names.
    fn rebuilds(self, batch: &EventBatch) -> bool {
        match self {
            Self::Reported => !batch.is_empty(),
            Self::Registered => true,
        }
    }

    /// Whether it leaves the corpus walk's ignore rules to reopen.
    ///
    /// A batch that changed one of those files does, for the reason
    /// [`LiveRules`] states. A registration does too, whatever its batch says:
    /// the rules were opened beside the first index, and one changed between
    /// that build and the observation was reported to nobody.
    fn reloads(self, batch: &EventBatch) -> bool {
        match self {
            Self::Reported => batch.restates_rules(),
            Self::Registered => true,
        }
    }
}

/// Everything a live index and the thread that feeds it share.
pub(super) struct LiveCore {
    root: CanonicalRoot,
    authorities: Box<[ProjectAuthority]>,
    state: RwLock<Arc<CodeIntelligenceState>>,
    indexer: Mutex<CodeIntelligenceIndexer>,
    ledger: Mutex<LiveLedger>,
    rules: LiveRules,
    terminal: Terminal,
}

impl LiveCore {
    /// Build the first index and hold it live.
    pub(super) fn opened(
        root: &Path,
        authorities: &[ProjectAuthority],
        limits: CodeIntelligenceLimits,
    ) -> Result<Self, LiveIndexError> {
        let root = CanonicalRoot::open(root)?;
        let mut indexer = CodeIntelligenceIndexer::new(limits);
        let first = indexer.index(root.as_path(), authorities)?;
        let rules = LiveRules::opened(root.as_path());
        Ok(Self {
            root,
            authorities: authorities.to_vec().into_boxed_slice(),
            state: RwLock::new(Arc::new(first)),
            indexer: Mutex::new(indexer),
            ledger: Mutex::new(LiveLedger::default()),
            rules,
            terminal: Terminal::default(),
        })
    }

    /// The canonical root every reported path is keyed against.
    pub(super) fn root(&self) -> &CanonicalRoot {
        &self.root
    }

    /// The refusal the applying thread ended on, and where one is recorded.
    ///
    /// Published as the owner rather than as a reader and a writer, because the
    /// applying thread records and the shutdown path reads, and neither is more
    /// this core's business than the other.
    pub(super) fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    /// The published state, cloned and handed over with no lock held.
    ///
    /// Refuses outright once the applying thread has stopped. The held state is
    /// still whole and still readable, and answering from it would be the one
    /// failure a live index cannot report any other way: an index nothing will
    /// ever advance, answering as though it were current.
    pub(super) fn state(&self) -> Result<Arc<CodeIntelligenceState>, LiveIndexError> {
        match self.terminal.stated() {
            Some(reason) => Err(reason),
            None => self.published(),
        }
    }

    /// What this live index has applied.
    ///
    /// Refuses on a terminal core for the same reason [`state`](Self::state)
    /// does, and it is the more misleading of the two: an operator reads the
    /// ledger precisely to tell "nothing changed" from "every rebuild failed",
    /// and counters frozen at the moment the thread died read as the first.
    pub(super) fn ledger(&self) -> Result<LiveLedger, LiveIndexError> {
        match self.terminal.stated() {
            Some(reason) => Err(reason),
            None => Ok(self
                .ledger
                .lock()
                .map_err(|_| LiveIndexError::Poisoned {
                    owner: PoisonedOwner::Ledger,
                })?
                .clone()),
        }
    }

    /// The batch one sequence of reported changes normalizes to.
    ///
    /// The rules this keys against are whichever ones are open when it runs. A
    /// caller that normalizes and applies as two calls owns the gap between
    /// them — a transaction landing in between may reopen the rules, leaving
    /// the batch keyed against rules one reload old. The applying thread has no
    /// such gap: [`applied_reports`](Self::applied_reports) does both halves
    /// under one hold of the indexer's lock.
    pub(super) fn normalized(&self, observed: &[ObservedChange]) -> EventBatch {
        self.rules.normalized(&self.root, observed)
    }

    /// Normalize one sequence of reported changes and apply what it comes to.
    ///
    /// The applying thread's whole path, and one hold of the indexer's lock
    /// covers both halves. That is what makes [`LiveRules`]'s claim true here
    /// rather than merely likely: no other transaction can reopen the rules
    /// between the keying of this batch and the rebuild it is keyed for.
    ///
    /// Nothing is handed back. This thread reads no transaction, and a return
    /// value would copy one batch per host event for a value dropped on the
    /// next line.
    pub(super) fn applied_reports(
        &self,
        observed: &[ObservedChange],
    ) -> Result<(), LiveIndexError> {
        let mut indexer = self.locked()?;
        let batch = self.normalized(observed);
        self.committed(&mut indexer, batch, TransactionCause::Reported, |_| ())
    }

    /// Apply one already-normalized batch, handing back what it recorded.
    ///
    /// The entry point for a host that learns about changes some way other than
    /// this crate's watcher: it normalizes and applies as two published calls
    /// and reads the transaction back.
    pub(super) fn applied(&self, batch: EventBatch) -> Result<LiveTransaction, LiveIndexError> {
        let mut indexer = self.locked()?;
        self.committed(
            &mut indexer,
            batch,
            TransactionCause::Reported,
            LiveTransaction::clone,
        )
    }

    /// Rebuild once against the tree as it stands, and reopen the rules.
    ///
    /// The observation of the root registers after the first index has been
    /// built, and on a large tree that build is seconds long: every change made
    /// inside it raised no event this process will ever see, and no later report
    /// names those files again. One rebuild started after the observation is
    /// registered covers all of them, because it reads the tree as it stands
    /// while everything after it arrives as a report.
    ///
    /// Its batch names nothing, because nothing reported it. The ledger counts
    /// it as the published transaction it is, which is what tells an operator
    /// the watch resynchronized rather than that a file changed.
    pub(super) fn resynchronized(&self) -> Result<(), LiveIndexError> {
        let mut indexer = self.locked()?;
        self.committed(
            &mut indexer,
            EventBatch::unreported(),
            TransactionCause::Registered,
            |_| (),
        )
    }

    /// The published state, whatever the applying thread has done.
    ///
    /// The reading a transaction takes. A rebuild that refuses needs the last
    /// good index to stall over, and the caller of a transaction is one this
    /// call returns to — so it is told by the refusal it gets back rather than
    /// by a record written for the callers that are not.
    fn published(&self) -> Result<Arc<CodeIntelligenceState>, LiveIndexError> {
        let held = self.state.read().map_err(|_| LiveIndexError::Poisoned {
            owner: PoisonedOwner::StateRead,
        })?;
        let state = Arc::clone(&held);
        drop(held);
        Ok(state)
    }

    /// Take the indexer, which every transaction is serialized by.
    fn locked(&self) -> Result<MutexGuard<'_, CodeIntelligenceIndexer>, LiveIndexError> {
        self.indexer.lock().map_err(|_| LiveIndexError::Poisoned {
            owner: PoisonedOwner::Indexer,
        })
    }

    /// Rebuild, publish, reopen the rules, record, and hand back the reading.
    ///
    /// The caller's guard covers all of it. It is taken before the batch is
    /// read and released after the ledger has counted what the batch did, so
    /// two producers cannot publish in one order and record in the other —
    /// which would leave [`LiveLedger::last`] naming a transaction older than
    /// the state every reader can already see.
    ///
    /// The caller's reading is taken before the ledger takes the transaction,
    /// which is what lets the ledger take it by value. It also makes the value
    /// handed back this call's own transaction rather than whatever the ledger
    /// happens to hold afterwards — two producers cannot swap answers.
    ///
    /// The rules are reopened before the ledger is taken, and that order is the
    /// point rather than an accident. The ledger is the one step here that may
    /// legitimately refuse, and reopening after it left a refusal returning
    /// from a rebuild that had already consumed a `.gitignore` change while the
    /// pre-change rules stayed open for good.
    fn committed<Read>(
        &self,
        indexer: &mut CodeIntelligenceIndexer,
        batch: EventBatch,
        cause: TransactionCause,
        taken: impl FnOnce(&LiveTransaction) -> Read,
    ) -> Result<Read, LiveIndexError> {
        let transaction = self.transacted(indexer, batch, cause)?;
        let read = taken(&transaction);
        self.rules
            .reloaded(self.root.as_path(), cause.reloads(transaction.batch()));
        self.ledger
            .lock()
            .map_err(|_| LiveIndexError::Poisoned {
                owner: PoisonedOwner::Ledger,
            })?
            .record(transaction);
        Ok(read)
    }

    /// One transaction: the rebuild this cause calls for, or none at all.
    ///
    /// The transaction that rebuilds nothing still runs under the caller's
    /// guard, so the revision it reports is one nobody is swapping while it
    /// reads it.
    fn transacted(
        &self,
        indexer: &mut CodeIntelligenceIndexer,
        batch: EventBatch,
        cause: TransactionCause,
    ) -> Result<LiveTransaction, LiveIndexError> {
        match cause.rebuilds(&batch) {
            false => {
                let held = self.published()?;
                Ok(LiveTransaction::of(
                    batch,
                    TransactionOutcome::Ignored,
                    &held,
                ))
            }
            true => self.rebuilt(indexer, batch),
        }
    }

    /// Rebuild, validate, and publish, or keep the last good index.
    fn rebuilt(
        &self,
        indexer: &mut CodeIntelligenceIndexer,
        batch: EventBatch,
    ) -> Result<LiveTransaction, LiveIndexError> {
        let rebuilt = indexer.index(self.root.as_path(), &self.authorities);
        let (state, outcome) = match rebuilt {
            Ok(published) => (published, TransactionOutcome::Published),
            Err(refused) => {
                let held = self.published()?;
                (stalled(&held, &refused), TransactionOutcome::Retained)
            }
        };
        let published = Arc::new(state);
        let transaction = LiveTransaction::of(batch, outcome, &published);
        *self.state.write().map_err(|_| LiveIndexError::Poisoned {
            owner: PoisonedOwner::StateWrite,
        })? = published;
        Ok(transaction)
    }
}
