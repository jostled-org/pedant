//! Why a live index states no answer.

use crate::index::CodeIntelligenceError;

/// Which owner of a live index a panic left unusable.
///
/// A live index is four owners behind three locks, and a poisoned one names
/// which. Without it every refusal read the same, so a caller could not tell an
/// indexer that died mid-rebuild from a ledger that died mid-record — and the
/// applying thread, which reports the refusal it ended on and returns, had
/// nothing to report but the word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PoisonedOwner {
    /// The published state, taken to answer a question from.
    StateRead,
    /// The published state, taken to publish a rebuild over.
    StateWrite,
    /// The indexer every transaction is serialized by.
    Indexer,
    /// The ledger every transaction is counted in.
    Ledger,
}

impl PoisonedOwner {
    /// The stable token this owner is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::StateRead => "state_read",
            Self::StateWrite => "state_write",
            Self::Indexer => "indexer",
            Self::Ledger => "ledger",
        }
    }
}

impl std::fmt::Display for PoisonedOwner {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.token())
    }
}

/// Why one live-index operation states no answer.
///
/// Four refusals, and each operation states a subset. Opening states only
/// [`Build`](Self::Build), because the first index either builds or there is no
/// live index to hold. Watching states only [`Watch`](Self::Watch), because the
/// index is already built by then. Every operation on a live index states
/// [`Poisoned`](Self::Poisoned), which is the one failure that is about the
/// live index rather than about a repository. Stopping a watcher also states
/// [`WorkerPanicked`](Self::WorkerPanicked), which is the only refusal a join
/// can see and the applying thread cannot record.
///
/// A failed *rebuild* is not here. It is published: the last good index is
/// kept, a new state carries the refusal as a stale issue, and every response
/// says so until recovery. Returning it to the applying thread instead would
/// leave the caller who asked the next question with no way to learn it
/// happened.
///
/// A failed *transaction* is both. The applying thread reports it, records it
/// on the live index, and returns; every later query, ledger read, and shutdown
/// then states it, because an index nothing advances is answering from a tree
/// that has moved on without it.
#[derive(Clone, Debug, thiserror::Error)]
pub enum LiveIndexError {
    /// The first index did not build.
    #[error(transparent)]
    Build(#[from] CodeIntelligenceError),
    /// The host's notification layer will not observe the repository root.
    #[error("the repository root cannot be watched: {reason}")]
    Watch {
        /// What the host said about it.
        reason: Box<str>,
    },
    /// A thread panicked while holding one of the live index's owners.
    ///
    /// Terminal: what the panicking thread was part-way through is unknown, so
    /// every later answer would be a guess about a value nobody finished
    /// writing.
    #[error("the live index is poisoned by a panic in a thread holding its {owner}")]
    Poisoned {
        /// Which owner that thread held.
        owner: PoisonedOwner,
    },
    /// The applying thread ended by panicking.
    ///
    /// Terminal, and distinct from a poisoned owner because it is the one
    /// refusal the thread cannot state for itself: a thread that unwinds
    /// records nothing, so the join is the whole report.
    #[error("the live index's applying thread ended by panicking")]
    WorkerPanicked,
}
