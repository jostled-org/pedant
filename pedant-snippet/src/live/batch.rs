//! One normalized batch: everything a live update treats as a single change.
//!
//! Normalization answers three questions before a rebuild is worth starting.
//! Which reported paths are this repository's at all — that question belongs to
//! [`keyed`](super::key::keyed). What each of them is to the corpus. And what
//! one path's several reports add up to, because a single editor save arrives
//! as a create and two modifies on some hosts and as one modify on others, and
//! a repository does not change three times because of it.
//!
//! A name the index cannot key at all is neither admitted nor discarded. It is
//! counted, and the count alone is enough to make the batch select something:
//! there is no row to carry a name with no repository spelling, and the rebuild
//! the count forces is what records the refusal, under the classification the
//! corpus walk already owns.

use std::collections::BTreeMap;
use std::sync::Arc;

use ignore::IncrementalIgnore;

use crate::index::CanonicalRoot;

use super::change::{ChangeKind, ChangeRole, ObservedChange, SourceChange};
use super::fold::Folded;
use super::key::{Keyed, keyed};

/// Everything one live update treats as a single change.
///
/// The rows are shared rather than owned outright, because a batch is read by
/// copying it. The ledger keeps the last transaction and hands back a clone of
/// the whole ledger on every read, and the published `apply` clones the
/// transaction it records — so an owned slice copied every row of a
/// checkout-sized batch on each of those, for rows nothing writes to once
/// normalization has returned them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventBatch {
    changes: Arc<[SourceChange]>,
    unkeyable: u32,
}

impl EventBatch {
    /// The batch one sequence of reported changes normalizes to.
    ///
    /// The ignore matcher is borrowed mutably because it caches a compiled
    /// matcher per directory it reaches. The first batch naming a directory
    /// reads the ignore files above it; every later batch naming the same
    /// directory reads nothing.
    pub(super) fn normalized(
        root: &CanonicalRoot,
        ignored: &mut Option<IncrementalIgnore>,
        observed: &[ObservedChange],
    ) -> Self {
        let mut folded: BTreeMap<Arc<str>, Folded> = BTreeMap::new();
        let mut unkeyable = 0_u32;
        for change in observed {
            match keyed(root, ignored, change.path()) {
                Keyed::Discarded => (),
                Keyed::Unkeyable => unkeyable = unkeyable.saturating_add(1),
                Keyed::Admitted { relative, role } => {
                    admit(&mut folded, &relative, role, change.settled());
                }
            }
        }
        let mut changes: Vec<SourceChange> = folded
            .into_iter()
            .map(|(path, folded)| folded.stated(path))
            .collect();
        changes.sort();
        Self {
            changes: Arc::from(changes),
            unkeyable,
        }
    }

    /// The batch a transaction nothing reported applies.
    ///
    /// For the rebuild that follows registering an observation. It names
    /// nothing because nothing reported it, and the rebuild it carries is what
    /// reaches the changes no report ever will.
    pub(super) fn unreported() -> Self {
        Self {
            changes: Arc::default(),
            unkeyable: 0,
        }
    }

    /// Every normalized row, in role then path then kind order.
    pub fn changes(&self) -> &[SourceChange] {
        &self.changes
    }

    /// How many reported names beneath the root this index cannot key.
    ///
    /// A count rather than rows, because a row is keyed by the repository path
    /// these names do not have. What states them is the rebuild the count
    /// forces: the corpus walk reaches the same names and records each one as
    /// an issue, under the classification that walk already owns.
    pub fn unkeyable(&self) -> u32 {
        self.unkeyable
    }

    /// Whether this batch selects nothing this index answers for.
    ///
    /// A batch holding only unkeyable names selects something. The names have
    /// no repository spelling, so no row can carry them, and calling the batch
    /// empty would discard the one refusal a live update has no other way to
    /// state.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.unkeyable == 0
    }

    /// Whether this batch changes a file the corpus walk reads its rules from.
    ///
    /// A matcher answers from the ignore files as they were when it first
    /// reached each directory, so the one change that can make its answers
    /// wrong is a change to those files. Reported here rather than inspected by
    /// the caller, because the caller would be reading the role vocabulary this
    /// module owns to ask a question this module can answer.
    pub(super) fn restates_rules(&self) -> bool {
        self.changes
            .iter()
            .any(|change| change.role() == ChangeRole::Ignore)
    }
}

/// Fold one admitted report into the row its path already holds, or open one.
///
/// The key is probed borrowed and copied only where the map does not hold it. A
/// `cargo build` or a checkout puts thousands of reports through here per batch
/// and most of them name a path the batch already holds, so an entry keyed by
/// an owned share copied every one of those names to reach a row already there.
fn admit(
    folded: &mut BTreeMap<Arc<str>, Folded>,
    relative: &str,
    role: ChangeRole,
    kind: ChangeKind,
) {
    match folded.get_mut(relative) {
        Some(held) => held.observe(kind),
        None => {
            folded.insert(Arc::from(relative), Folded::opened(role, kind));
        }
    }
}
