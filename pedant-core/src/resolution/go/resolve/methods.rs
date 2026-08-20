//! The members one concrete named type answers to, including the ones it
//! promotes from the types it embeds.
//!
//! Go gives a struct the exported and unexported members of every type it
//! embeds, at one level deeper each time, and the shallowest depth that answers
//! wins. An embedded chain that leaves the snapshot stops there: a promoted
//! member whose owner is not in the corpus is a member the corpus cannot name.

use std::collections::BTreeSet;

use super::index::Index;
use super::types::Receiver;

/// Every definition one concrete receiver answers to under `member`.
///
/// The search widens one embedding level at a time and stops at the first level
/// that answers, which is Go's depth rule. Two answers at one depth are two
/// candidates rather than a choice: an ambiguous selector is a real Go program
/// error, and a resolver that picked one would hide it.
pub(super) fn members(index: &Index, receiver: Receiver, member: &str) -> Box<[usize]> {
    let mut visited: BTreeSet<Box<str>> = BTreeSet::new();
    let mut level: Vec<Box<str>> = owner(index, receiver).into_iter().collect();
    while !level.is_empty() {
        let found = at_depth(index, receiver.unit, &level, member);
        if !found.is_empty() {
            return found;
        }
        let next = deeper(index, receiver.unit, &level, &visited);
        visited.extend(level.drain(..));
        level = next;
    }
    Box::from([])
}

/// The name the receiver's own type is declared under.
fn owner(index: &Index, receiver: Receiver) -> Option<Box<str>> {
    index.slot(receiver.slot).map(|slot| slot.name.clone())
}

/// Every definition the named types at one embedding depth answer with.
fn at_depth(index: &Index, unit: usize, level: &[Box<str>], member: &str) -> Box<[usize]> {
    let Some(tables) = index.unit(unit) else {
        return Box::from([]);
    };
    let mut found: Vec<usize> = level
        .iter()
        .flat_map(|name| tables.member(name, member).iter().copied())
        .collect();
    found.sort_unstable();
    found.dedup();
    found.into_boxed_slice()
}

/// The types embedded one level beneath the current one, less those already
/// walked.
fn deeper(
    index: &Index,
    unit: usize,
    level: &[Box<str>],
    visited: &BTreeSet<Box<str>>,
) -> Vec<Box<str>> {
    let Some(tables) = index.unit(unit) else {
        return Vec::new();
    };
    let mut next: Vec<Box<str>> = level
        .iter()
        .flat_map(|name| tables.embedded(name).iter().cloned())
        .filter(|name| !visited.contains(name) && !level.iter().any(|open| open == name))
        .collect();
    next.sort_unstable();
    next.dedup();
    next
}
