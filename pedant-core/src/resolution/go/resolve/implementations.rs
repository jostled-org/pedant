//! Which concrete named types structurally implement which interfaces.
//!
//! Go has no declaration of intent: a type implements an interface exactly when
//! its method set answers every method the interface requires, with the same
//! canonical signature. So every concrete type in the corpus is compared
//! against every interface in it, and the comparisons are counted against their
//! own ceiling — an overrunning corpus refuses rather than states some of the
//! relations it holds.
//!
//! A comparison proves a relation only from complete evidence. An incomplete
//! requirement list, a method whose signature the corpus cannot name, and an
//! ambiguous selector each leave the relation possible with the gap that says
//! why; a method the type answers with a different signature is no relation at
//! all.

use std::collections::BTreeMap;

use pedant_types::ResolutionGap;

use crate::resolution::go::limits::GoResolutionLimits;

use super::corpus::Corpus;
use super::error::GoResolutionError;
use super::index::{Index, Slot};
use super::interfaces::{self, Expansion, Requirement};
use super::methods::{self, Member};
use super::signatures::Signatures;
use super::types::Receiver;

/// One structural relation between a concrete type and an interface.
pub(super) struct Relation {
    /// The concrete type that answers the interface.
    pub(super) concrete: usize,
    /// The interface it answers.
    pub(super) interface: usize,
    /// Whether the pointer form is the one carrying every required method.
    pub(super) pointer: bool,
    /// Why the relation is not proved, absent when it is.
    pub(super) gap: Option<ResolutionGap>,
}

/// What one comparison found.
#[derive(Clone, Copy)]
struct Match {
    pointer: bool,
    gap: Option<ResolutionGap>,
}

/// Every structural relation the corpus states, and the types each interface
/// may dispatch to.
///
/// Sealed on construction: the comparison fills a draft, and what a reader
/// holds is the whole answer rather than a list a later stage could still push
/// an unchecked relation onto.
pub(super) struct Implementations {
    relations: Box<[Relation]>,
    implementors: BTreeMap<usize, Box<[usize]>>,
}

impl Implementations {
    /// Compare every concrete type in the corpus against every interface in it.
    pub(super) fn of(
        index: &Index,
        corpus: &Corpus<'_>,
        limits: GoResolutionLimits,
    ) -> Result<Self, GoResolutionError> {
        let signatures = Signatures::of(index, corpus);
        let expansions = expansions(index, &signatures);
        let mut draft = Draft::default();
        let mut spent = 0_u64;
        for concrete in concrete_types(index).iter() {
            draft.compare_type(
                (index, &signatures),
                (*concrete, &expansions),
                (&mut spent, limits),
            )?;
        }
        Ok(draft.seal())
    }

    /// Every relation the corpus states, in comparison order.
    pub(super) fn relations(&self) -> &[Relation] {
        &self.relations
    }

    /// Every concrete type one interface may dispatch to.
    pub(super) fn implementors(&self, interface: usize) -> &[usize] {
        self.implementors
            .get(&interface)
            .map(|found| &**found)
            .unwrap_or_default()
    }
}

/// The relations one comparison run has stated so far.
#[derive(Default)]
struct Draft {
    relations: Vec<Relation>,
    implementors: BTreeMap<usize, Vec<usize>>,
}

impl Draft {
    /// Compare one concrete type against every interface.
    fn compare_type(
        &mut self,
        read: (&Index, &Signatures),
        against: (usize, &BTreeMap<usize, Expansion>),
        budget: (&mut u64, GoResolutionLimits),
    ) -> Result<(), GoResolutionError> {
        let (concrete, expansions) = against;
        let (spent, limits) = budget;
        for (interface, expansion) in expansions.iter() {
            self.compare_pair(read, (concrete, (*interface, expansion)), (spent, limits))?;
        }
        Ok(())
    }

    /// Compare one concrete type against one interface.
    ///
    /// The ceiling is checked before the comparison runs, so a corpus whose
    /// comparisons overrun refuses the whole resolution rather than retaining
    /// the relations it happened to reach first.
    fn compare_pair(
        &mut self,
        read: (&Index, &Signatures),
        pair: (usize, (usize, &Expansion)),
        budget: (&mut u64, GoResolutionLimits),
    ) -> Result<(), GoResolutionError> {
        let (spent, limits) = budget;
        check_comparison_capacity(*spent, limits)?;
        *spent += 1;
        let (index, signatures) = read;
        let (concrete, (interface, expansion)) = pair;
        let found = matched(index, signatures, (concrete, expansion));
        self.retain_relation((concrete, interface), found);
        Ok(())
    }

    /// Retain one comparison that found a relation.
    fn retain_relation(&mut self, pair: (usize, usize), found: Option<Match>) {
        let Some(found) = found else {
            return;
        };
        let (concrete, interface) = pair;
        self.relations.push(Relation {
            concrete,
            interface,
            pointer: found.pointer,
            gap: found.gap,
        });
        self.implementors
            .entry(interface)
            .or_default()
            .push(concrete);
    }

    /// Seal every stated relation into the answer a reader holds.
    fn seal(self) -> Implementations {
        Implementations {
            relations: self.relations.into_boxed_slice(),
            implementors: self
                .implementors
                .into_iter()
                .map(|(interface, concrete)| (interface, concrete.into_boxed_slice()))
                .collect(),
        }
    }
}

/// Comparisons are never truncated: a corpus overrunning the ceiling refuses
/// the whole resolution instead of stating the relations it reached first.
fn check_comparison_capacity(
    spent: u64,
    limits: GoResolutionLimits,
) -> Result<(), GoResolutionError> {
    let ceiling = limits.max_interface_comparisons;
    match spent < u64::from(ceiling) {
        true => Ok(()),
        false => Err(GoResolutionError::InterfaceComparisonLimitExceeded { limit: ceiling }),
    }
}

/// Every interface the corpus declares, with the methods it requires.
fn expansions(index: &Index, signatures: &Signatures) -> BTreeMap<usize, Expansion> {
    index
        .stated()
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_interface())
        .map(|(slot, _)| (slot, interfaces::expand(index, signatures, slot)))
        .collect()
}

/// Every concrete named type the corpus declares, in the order it stated them.
fn concrete_types(index: &Index) -> Box<[usize]> {
    index
        .stated()
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_concrete_type())
        .map(|(slot, _)| slot)
        .collect()
}

/// What one concrete type answers one interface's requirements with.
///
/// An interface requiring nothing states nothing about any type: every type in
/// every corpus answers it, so a relation would carry no evidence.
fn matched(index: &Index, signatures: &Signatures, asked: (usize, &Expansion)) -> Option<Match> {
    let (concrete, expansion) = asked;
    if expansion.required().is_empty() {
        return None;
    }
    let mut answer = Match {
        pointer: false,
        gap: expansion.gap(),
    };
    for requirement in expansion.required() {
        answer = answered(index, signatures, (concrete, requirement), answer)?;
    }
    Some(answer)
}

/// What one concrete type answers one required method with.
///
/// A name the type answers with a field rather than a method is not an answer:
/// Go's selector reaches the shallowest member of that name, and a field there
/// is what the type has under it.
fn answered(
    index: &Index,
    signatures: &Signatures,
    asked: (usize, &Requirement),
    answer: Match,
) -> Option<Match> {
    let (concrete, requirement) = asked;
    let found: Box<[Member]> =
        methods::promoted(index, Receiver { slot: concrete }, requirement.name())
            .iter()
            .copied()
            .filter(|member| {
                index
                    .slot(member.slot)
                    .is_some_and(Slot::is_concrete_method)
            })
            .collect();
    match *found {
        [only] => compared(index, signatures, (requirement, only), answer),
        [] => None,
        _ => Some(Match {
            gap: answer.gap.or(Some(ResolutionGap::Ambiguous)),
            ..answer
        }),
    }
}

/// What one answering method states against the signature required of it.
fn compared(
    index: &Index,
    signatures: &Signatures,
    found: (&Requirement, Member),
    answer: Match,
) -> Option<Match> {
    let (requirement, member) = found;
    let pointer = answer.pointer || needs_address(index, member);
    match (requirement.signature(), signatures.of_slot(member.slot)) {
        (Some(required), Some(stated)) => {
            (required == stated).then_some(Match { pointer, ..answer })
        }
        _ => Some(Match {
            pointer,
            gap: answer.gap.or(Some(ResolutionGap::UnsupportedSyntax)),
        }),
    }
}

/// Whether one answering method belongs to the pointer form alone.
///
/// A method receiving its type by pointer is in the value form's method set
/// only when an embedded pointer already carried the address.
fn needs_address(index: &Index, member: Member) -> bool {
    index
        .slot(member.slot)
        .is_some_and(|slot| slot.pointer_receiver)
        && !member.through_pointer
}
