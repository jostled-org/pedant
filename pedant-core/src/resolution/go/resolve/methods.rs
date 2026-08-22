//! The members one concrete named type answers to, including the ones it
//! promotes from the types it embeds.
//!
//! Go gives a struct the exported and unexported members of every type it
//! embeds, at one level deeper each time, and the shallowest depth that answers
//! wins. An embedded chain that leaves the snapshot stops there: a promoted
//! member whose owner is not in the corpus is a member the corpus cannot name.

use std::collections::BTreeSet;

use super::index::{EmbeddedType, Index};
use super::types::Receiver;

/// Every definition one concrete receiver answers to under `member`.
///
/// The search widens one embedding level at a time and stops at the first level
/// that answers, which is Go's depth rule. Two answers at one depth are two
/// candidates rather than a choice: an ambiguous selector is a real Go program
/// error, and a resolver that picked one would hide it.
pub(super) fn members(index: &Index, receiver: Receiver, member: &str) -> Box<[usize]> {
    let mut visited: BTreeSet<EmbeddedType> = BTreeSet::new();
    let mut level: Vec<EmbeddedType> = owner(index, receiver).into_iter().collect();
    while !level.is_empty() {
        let found = at_depth(index, &level, member);
        if !found.is_empty() {
            return found;
        }
        let next = deeper(index, &level, &visited);
        visited.extend(level.drain(..));
        level = next;
    }
    Box::from([])
}

/// The name the receiver's own type is declared under.
fn owner(index: &Index, receiver: Receiver) -> Option<EmbeddedType> {
    index.slot(receiver.slot).map(|slot| EmbeddedType {
        unit: slot.unit,
        name: slot.name.clone(),
    })
}

/// Every definition the named types at one embedding depth answer with.
fn at_depth(index: &Index, level: &[EmbeddedType], member: &str) -> Box<[usize]> {
    let mut found: Vec<usize> = level
        .iter()
        .flat_map(|embedded| {
            index
                .unit(embedded.unit)
                .into_iter()
                .flat_map(|tables| tables.member(&embedded.name, member).iter().copied())
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found.into_boxed_slice()
}

/// The types embedded one level beneath the current one, less those already
/// walked.
fn deeper(
    index: &Index,
    level: &[EmbeddedType],
    visited: &BTreeSet<EmbeddedType>,
) -> Vec<EmbeddedType> {
    let mut next: Vec<EmbeddedType> = level
        .iter()
        .flat_map(|embedded| {
            index
                .unit(embedded.unit)
                .into_iter()
                .flat_map(|tables| tables.embedded(&embedded.name).iter().cloned())
        })
        .filter(|embedded| {
            !visited.contains(embedded) && !level.iter().any(|open| open == embedded)
        })
        .collect();
    next.sort_unstable();
    next.dedup();
    next
}
