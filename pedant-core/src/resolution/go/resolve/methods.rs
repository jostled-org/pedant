//! The members one concrete named type answers to, including the ones it
//! promotes from the types it embeds.
//!
//! Go gives a struct the exported and unexported members of every type it
//! embeds, at one level deeper each time, and the shallowest depth that answers
//! wins. An embedded chain that leaves the snapshot stops there: a promoted
//! member whose owner is not in the corpus is a member the corpus cannot name.
//!
//! The rule counts embedding paths rather than the types they arrive at. Two
//! embeddings reaching one type at one depth make every member that type
//! answers with an ambiguous selector, which is a Go program error rather than
//! one answer stated twice.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
    /// Whether several embedding paths arrive at this type at this depth.
    multiples: bool,
}

/// One member a search answered with, and whether an embedded pointer carried
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Member {
    pub(super) slot: usize,
    pub(super) through_pointer: bool,
    /// Whether the type carrying it is one several embedding paths reach at one
    /// depth, which makes selecting it ambiguous however few definitions answer.
    pub(super) multiples: bool,
}

/// Every member one concrete receiver answers to, at the shallowest embedding
/// depth that answers each name.
///
/// One walk per receiver rather than one per name. A structural comparison asks
/// the same receiver for every method every interface in the corpus requires,
/// and a walk per requirement pays the whole embedding graph again for a table
/// the first walk already filled.
pub(super) struct MethodSet {
    answered: BTreeMap<Arc<str>, Box<[Member]>>,
}

impl MethodSet {
    /// Every member `receiver` answers to, walked once.
    ///
    /// The search widens one embedding level at a time and keeps the first
    /// level that answers each name, which is Go's depth rule. Two answers at
    /// one depth are two candidates rather than a choice: an ambiguous selector
    /// is a real Go program error, and a resolver that picked one would hide it.
    pub(super) fn of(index: &Index, receiver: Receiver) -> Self {
        let mut answered: BTreeMap<Arc<str>, Vec<Member>> = BTreeMap::new();
        let mut visited: BTreeSet<EmbeddedType> = BTreeSet::new();
        let mut level: Vec<Reached> = owner(index, receiver).into_iter().collect();
        while !level.is_empty() {
            let next = deeper(index, &level, &visited);
            record_level(index, &level, &mut answered);
            visited.extend(level.drain(..).map(|reached| reached.embedded));
            level = next;
        }
        Self {
            answered: answered
                .into_iter()
                .map(|(name, found)| (name, found.into_boxed_slice()))
                .collect(),
        }
    }

    /// Every member one name answers with, at the depth that answered it.
    pub(super) fn named(&self, member: &str) -> &[Member] {
        self.answered
            .get(member)
            .map(|found| &**found)
            .unwrap_or_default()
    }
}

/// Every definition one concrete receiver answers to under `member`.
///
/// A call site asks only which definitions answer, because Go's method-call
/// rules reach a pointer receiver from an addressable value and a value
/// receiver through a pointer, so both forms select one method set there.
pub(super) fn promoted(index: &Index, receiver: Receiver, member: &str) -> Box<[Member]> {
    let found = MethodSet::of(index, receiver);
    Box::from(found.named(member))
}

/// The name the receiver's own type is declared under.
fn owner(index: &Index, receiver: Receiver) -> Option<Reached> {
    index.slot(receiver.slot).map(|slot| Reached {
        embedded: EmbeddedType {
            unit: slot.unit,
            name: Arc::clone(&slot.name),
        },
        through_pointer: false,
        multiples: false,
    })
}

/// Record every member the named types at one depth answer with, keeping the
/// shallowest depth that answered each name.
fn record_level(index: &Index, level: &[Reached], answered: &mut BTreeMap<Arc<str>, Vec<Member>>) {
    let mut depth: BTreeMap<Arc<str>, Vec<Member>> = BTreeMap::new();
    for (name, member) in at_depth(index, level) {
        depth.entry(name).or_default().push(member);
    }
    for (name, found) in depth {
        answered.entry(name).or_insert_with(|| sorted(found));
    }
}

/// One level's answers under one name, in a stable order and stated once each.
fn sorted(mut found: Vec<Member>) -> Vec<Member> {
    found.sort_unstable();
    found.dedup();
    found
}

/// Every member the named types at one depth declare, with the name each is
/// declared under.
fn at_depth<'a>(
    index: &'a Index,
    level: &'a [Reached],
) -> impl Iterator<Item = (Arc<str>, Member)> + 'a {
    level
        .iter()
        .flat_map(move |reached| declared(index, reached))
}

/// Every member one reached type declares directly.
fn declared<'a>(
    index: &'a Index,
    reached: &'a Reached,
) -> impl Iterator<Item = (Arc<str>, Member)> + 'a {
    index
        .unit(reached.embedded.unit)
        .into_iter()
        .flat_map(move |tables| tables.held(&reached.embedded.name))
        .filter_map(move |slot| index.slot(*slot).map(|found| (found, *slot)))
        .map(move |(found, slot)| {
            (
                Arc::clone(&found.name),
                Member {
                    slot,
                    through_pointer: reached.through_pointer,
                    multiples: reached.multiples,
                },
            )
        })
}

/// The types embedded one level beneath the current one, less those already
/// walked, with the ones several paths reach at this depth marked.
fn deeper(index: &Index, level: &[Reached], visited: &BTreeSet<EmbeddedType>) -> Vec<Reached> {
    let mut next: Vec<Reached> = carried(index, level)
        .filter(|reached| unwalked(reached, level, visited))
        .collect();
    next.sort_unstable();
    consolidated(next)
}

/// Every type the embeddings written at one depth promote.
fn carried<'a>(index: &'a Index, level: &'a [Reached]) -> impl Iterator<Item = Reached> + 'a {
    level
        .iter()
        .flat_map(move |reached| embedded(index, reached))
}

/// Every type one reached type embeds, as the promotion it makes.
fn embedded<'a>(index: &'a Index, holder: &'a Reached) -> impl Iterator<Item = Reached> + 'a {
    index
        .unit(holder.embedded.unit)
        .into_iter()
        .flat_map(move |tables| tables.embedded(&holder.embedded.name))
        .map(move |embedding| promotes(holder, embedding))
}

/// What one embedding promotes into the type that wrote it.
fn promotes(holder: &Reached, embedding: &Embedding) -> Reached {
    Reached {
        embedded: embedding.embedded.clone(),
        through_pointer: holder.through_pointer || embedding.pointer,
        multiples: false,
    }
}

/// Whether one promoted type is new to this walk.
fn unwalked(reached: &Reached, level: &[Reached], visited: &BTreeSet<EmbeddedType>) -> bool {
    !visited.contains(&reached.embedded)
        && !level.iter().any(|open| open.embedded == reached.embedded)
}

/// One entry per type reached, with the ones several embedding paths reach
/// marked ambiguous.
///
/// Go's rule is the path rather than the type: a type two embeddings arrive at
/// is seen twice at one level, and every member it answers with is an ambiguous
/// selector. Collapsing the run without recording that it was a run is what
/// turns a program `go build` rejects into a resolved answer.
fn consolidated(sorted: Vec<Reached>) -> Vec<Reached> {
    let mut held: Vec<Reached> = Vec::new();
    for reached in sorted {
        match held.last_mut() {
            Some(last) if last.embedded == reached.embedded => last.multiples = true,
            _ => held.push(reached),
        }
    }
    held
}
