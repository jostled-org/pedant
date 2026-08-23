//! The members one concrete named type answers to, including the ones it
//! promotes from the types it embeds.
//!
//! Go gives a struct the exported and unexported members of every type it
//! embeds, at one level deeper each time, and the shallowest depth that answers
//! wins. An embedded chain that leaves the snapshot stops there: a promoted
//! member whose owner is not in the corpus is a member the corpus cannot name.

use std::collections::BTreeSet;

use super::index::{EmbeddedType, Embedding, Index};
use super::types::Receiver;

/// One type reached while widening a search, and how it was reached.
///
/// A type reached through an embedded pointer already carries an address, so
/// the methods it receives by pointer belong to the embedding type's own value.
/// One reached through a value embedding does not, and those methods belong to
/// the pointer form alone.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Reached {
    embedded: EmbeddedType,
    through_pointer: bool,
}

/// One member a search answered with, and whether an embedded pointer carried
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Member {
    pub(super) slot: usize,
    pub(super) through_pointer: bool,
}

/// Every definition one concrete receiver answers to under `member`.
///
/// A call site asks only which definitions answer, because Go's method-call
/// rules reach a pointer receiver from an addressable value and a value
/// receiver through a pointer, so both forms select one method set there.
pub(super) fn members(index: &Index, receiver: Receiver, member: &str) -> Box<[usize]> {
    promoted(index, receiver, member)
        .iter()
        .map(|found| found.slot)
        .collect()
}

/// Every definition one concrete receiver answers to under `member`, with the
/// embedding form that carried each.
///
/// The search widens one embedding level at a time and stops at the first level
/// that answers, which is Go's depth rule. Two answers at one depth are two
/// candidates rather than a choice: an ambiguous selector is a real Go program
/// error, and a resolver that picked one would hide it.
pub(super) fn promoted(index: &Index, receiver: Receiver, member: &str) -> Box<[Member]> {
    let mut visited: BTreeSet<EmbeddedType> = BTreeSet::new();
    let mut level: Vec<Reached> = owner(index, receiver).into_iter().collect();
    while !level.is_empty() {
        let found = at_depth(index, &level, member);
        if !found.is_empty() {
            return found;
        }
        let next = deeper(index, &level, &visited);
        visited.extend(level.drain(..).map(|reached| reached.embedded));
        level = next;
    }
    Box::from([])
}

/// The name the receiver's own type is declared under.
fn owner(index: &Index, receiver: Receiver) -> Option<Reached> {
    index.slot(receiver.slot).map(|slot| Reached {
        embedded: EmbeddedType {
            unit: slot.unit,
            name: slot.name.clone(),
        },
        through_pointer: false,
    })
}

/// Every definition the named types at one embedding depth answer with.
fn at_depth(index: &Index, level: &[Reached], member: &str) -> Box<[Member]> {
    let mut found: Vec<Member> = level
        .iter()
        .flat_map(|reached| {
            index
                .unit(reached.embedded.unit)
                .into_iter()
                .flat_map(move |tables| {
                    tables
                        .member(&reached.embedded.name, member)
                        .iter()
                        .map(move |slot| Member {
                            slot: *slot,
                            through_pointer: reached.through_pointer,
                        })
                })
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found.into_boxed_slice()
}

/// The types embedded one level beneath the current one, less those already
/// walked.
fn deeper(index: &Index, level: &[Reached], visited: &BTreeSet<EmbeddedType>) -> Vec<Reached> {
    let mut next: Vec<Reached> = level
        .iter()
        .flat_map(|reached| {
            index
                .unit(reached.embedded.unit)
                .into_iter()
                .flat_map(move |tables| {
                    tables
                        .embedded(&reached.embedded.name)
                        .iter()
                        .map(move |embedding| carried(reached, embedding))
                })
        })
        .filter(|reached| {
            !visited.contains(&reached.embedded)
                && !level.iter().any(|open| open.embedded == reached.embedded)
        })
        .collect();
    next.sort_unstable();
    next.dedup();
    next
}

/// What one embedding promotes into the type that wrote it.
fn carried(holder: &Reached, embedding: &Embedding) -> Reached {
    Reached {
        embedded: embedding.embedded.clone(),
        through_pointer: holder.through_pointer || embedding.pointer,
    }
}
