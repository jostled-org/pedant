//! One repository index, kept current: what changed, what that made of it, and
//! what a caller reaches afterwards.
//!
//! An index is immutable, so keeping one current is publishing a new one rather
//! than editing the held one. That is the whole shape of this module. A batch
//! of reported changes becomes one transaction, one transaction publishes one
//! state, and a query reads whichever state is published when it asks.
//!
//! A failed rebuild publishes too. It keeps the last good index, states the
//! refusal as a stale issue over it, and moves the state identity — so every
//! later response says the tree moved on without it, and every page cursor
//! minted before it stops continuing. Answering from a partial rebuild would be
//! worse than answering late: the response would look complete and name fewer
//! symbols than the repository holds.
//!
//! A failed *transaction* refuses instead, and it refuses for good. The
//! applying thread stops on one, because what a transaction refuses is an owner
//! a panic left unusable, and every query, ledger read, and shutdown afterwards
//! states the same refusal. The alternative was the worst answer a live index
//! can give: a published state answering `Ok` from an index nothing would ever
//! advance again.

mod batch;
mod change;
mod core;
mod error;
mod fold;
mod index;
mod key;
mod rules;
mod terminal;
mod transaction;
mod watcher;

pub use batch::EventBatch;
pub use change::{ChangeKind, ChangeRole, ObservedChange, SourceChange};
pub use error::{LiveIndexError, PoisonedOwner};
pub use index::LiveCodeIntelligenceIndex;
pub use transaction::{LiveLedger, LiveTransaction, TransactionOutcome};
pub use watcher::RootWatcher;
#[cfg(feature = "test-support")]
pub use watcher::requires_rescan;
