//! What one live update did, and what a live index has done since it opened.
//!
//! Cost, never an answer. No revision claim reads anything here, so a live
//! index that has applied a thousand transactions and one that has applied none
//! publish the same bytes for the same tree. What it buys is that an operator
//! watching a repository can tell "nothing changed" from "every rebuild
//! failed", which the published state alone cannot say.

use crate::index::{CodeIntelligenceState, IndexRevision, StateRevision};

use super::batch::EventBatch;

/// What one transaction did with the batch it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionOutcome {
    /// The batch selected nothing this index answers for, so nothing was built
    /// and nothing was published.
    Ignored,
    /// The rebuild succeeded and its state is now the published one.
    Published,
    /// The rebuild refused. The last good index is kept, and the state
    /// published over it carries the refusal.
    Retained,
}

impl TransactionOutcome {
    /// The stable token this outcome is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Ignored => "ignored",
            Self::Published => "published",
            Self::Retained => "retained",
        }
    }
}

/// One applied batch, and the state a caller sees after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveTransaction {
    batch: EventBatch,
    outcome: TransactionOutcome,
    index: IndexRevision,
    state: StateRevision,
}

impl LiveTransaction {
    /// Record one applied batch against the state it left published.
    pub(super) fn of(
        batch: EventBatch,
        outcome: TransactionOutcome,
        published: &CodeIntelligenceState,
    ) -> Self {
        Self {
            batch,
            outcome,
            index: published.index().revision(),
            state: published.revision(),
        }
    }

    /// The normalized batch this transaction applied.
    pub fn batch(&self) -> &EventBatch {
        &self.batch
    }

    /// What it did with it.
    pub fn outcome(&self) -> TransactionOutcome {
        self.outcome
    }

    /// The index a caller reaches after it.
    pub fn index_revision(&self) -> IndexRevision {
        self.index
    }

    /// The state a caller reaches after it.
    pub fn state_revision(&self) -> StateRevision {
        self.state
    }
}

/// What one live index has applied since it opened.
///
/// Bounded by design: four counters and the last transaction. A log that grew
/// with the repository's edit history would be a second retained collection
/// with no ceiling of its own, which is exactly the shape every limit in this
/// crate exists to refuse.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveLedger {
    applied: u64,
    ignored: u64,
    published: u64,
    retained: u64,
    last: Option<LiveTransaction>,
}

impl LiveLedger {
    /// Count one transaction and keep it as the most recent.
    ///
    /// Taken by value, because keeping it is what this does. A borrow left the
    /// ledger cloning the batch of every transaction ever applied, and the one
    /// caller drops what it hands over on the next line.
    pub(super) fn record(&mut self, transaction: LiveTransaction) {
        self.applied = self.applied.saturating_add(1);
        let counted = match transaction.outcome() {
            TransactionOutcome::Ignored => &mut self.ignored,
            TransactionOutcome::Published => &mut self.published,
            TransactionOutcome::Retained => &mut self.retained,
        };
        *counted = counted.saturating_add(1);
        self.last = Some(transaction);
    }

    /// How many batches this index has applied.
    pub fn applied(&self) -> u64 {
        self.applied
    }

    /// How many of them selected nothing.
    pub fn ignored(&self) -> u64 {
        self.ignored
    }

    /// How many of them published a rebuilt index.
    pub fn published(&self) -> u64 {
        self.published
    }

    /// How many of them kept the last good index instead.
    pub fn retained(&self) -> u64 {
        self.retained
    }

    /// The most recent transaction, absent before the first one.
    pub fn last(&self) -> Option<&LiveTransaction> {
        self.last.as_ref()
    }
}
