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
use super::methods::{Member, MethodSet};
use super::signatures::Signatures;
use super::types::Receiver;

/// One concrete named type, as the definition position that declares it.
///
/// Named apart from the interface it is compared against, because the two
/// travel together through every stage below: as bare positions, transposing
/// them compiles and inverts every relation the corpus states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ConcreteSlot(usize);

impl ConcreteSlot {
    /// The definition position this type is recorded at.
    pub(super) fn slot(self) -> usize {
        self.0
    }
}

/// One interface, as the definition position that declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct InterfaceSlot(usize);

impl InterfaceSlot {
    /// One interface named by the position its definition took.
    pub(super) fn new(slot: usize) -> Self {
        Self(slot)
    }

    /// The definition position this interface is recorded at.
    pub(super) fn slot(self) -> usize {
        self.0
    }
}

/// One structural relation between a concrete type and an interface.
pub(super) struct Relation {
    /// The concrete type that answers the interface.
    pub(super) concrete: ConcreteSlot,
    /// The interface it answers.
    pub(super) interface: InterfaceSlot,
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

/// Every structural relation the corpus states, the types each interface may
/// dispatch to, and the method set each concrete type answers with.
///
/// Sealed on construction: the comparison fills a draft, and what a reader
/// holds is the whole answer rather than a list a later stage could still push
/// an unchecked relation onto.
pub(super) struct Implementations {
    relations: Box<[Relation]>,
    implementors: BTreeMap<InterfaceSlot, Box<[ConcreteSlot]>>,
    /// Every relation each package context declares, by the unit of its
    /// concrete type. Partitioned once, because a relation belongs to exactly
    /// one context and a scan per context reads the whole corpus each time.
    declared: BTreeMap<usize, Box<[usize]>>,
    /// The method set each concrete type answers with, walked once per type
    /// rather than once per comparison.
    sets: BTreeMap<ConcreteSlot, MethodSet>,
}

impl Implementations {
    /// Compare every concrete type in the corpus against every interface in it.
    pub(super) fn of(
        index: &Index,
        corpus: &Corpus<'_>,
        limits: GoResolutionLimits,
    ) -> Result<Self, GoResolutionError> {
        let signatures = Signatures::of(index, corpus)?;
        let expansions = expansions(index, &signatures);
        let sets = method_sets(index);
        let mut draft = Draft::default();
        let mut spent = 0_u64;
        for (concrete, set) in sets.iter() {
            draft.compare_type(
                (index, &signatures),
                ((*concrete, set), &expansions),
                (&mut spent, limits),
            )?;
        }
        Ok(draft.seal(index, sets))
    }

    /// Every relation one package context declares, in comparison order.
    pub(super) fn of_unit(&self, unit: usize) -> impl Iterator<Item = &Relation> {
        self.declared
            .get(&unit)
            .map(|held| &**held)
            .unwrap_or_default()
            .iter()
            .filter_map(|at| self.relations.get(*at))
    }

    /// Every concrete type one interface may dispatch to.
    pub(super) fn implementors(&self, interface: InterfaceSlot) -> &[ConcreteSlot] {
        self.implementors
            .get(&interface)
            .map(|found| &**found)
            .unwrap_or_default()
    }

    /// Every member one concrete type answers under a name, read from the table
    /// the comparison already walked.
    pub(super) fn answering(&self, concrete: ConcreteSlot, member: &str) -> &[Member] {
        self.sets
            .get(&concrete)
            .map(|set| set.named(member))
            .unwrap_or_default()
    }
}

/// The relations one comparison run has stated so far.
#[derive(Default)]
struct Draft {
    relations: Vec<Relation>,
    implementors: BTreeMap<InterfaceSlot, Vec<ConcreteSlot>>,
}

impl Draft {
    /// Compare one concrete type against every interface.
    fn compare_type(
        &mut self,
        read: (&Index, &Signatures),
        against: (
            (ConcreteSlot, &MethodSet),
            &BTreeMap<InterfaceSlot, Expansion>,
        ),
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
        pair: ((ConcreteSlot, &MethodSet), (InterfaceSlot, &Expansion)),
        budget: (&mut u64, GoResolutionLimits),
    ) -> Result<(), GoResolutionError> {
        let (spent, limits) = budget;
        check_comparison_capacity(*spent, limits)?;
        *spent += 1;
        let (index, signatures) = read;
        let ((concrete, set), (interface, expansion)) = pair;
        let found = matched(index, signatures, (set, expansion));
        self.retain_relation((concrete, interface), found);
        Ok(())
    }

    /// Retain one comparison that found a relation.
    fn retain_relation(&mut self, pair: (ConcreteSlot, InterfaceSlot), found: Option<Match>) {
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
    fn seal(self, index: &Index, sets: BTreeMap<ConcreteSlot, MethodSet>) -> Implementations {
        let declared = declared_by_unit(index, &self.relations);
        Implementations {
            relations: self.relations.into_boxed_slice(),
            implementors: self
                .implementors
                .into_iter()
                .map(|(interface, concrete)| (interface, concrete.into_boxed_slice()))
                .collect(),
            declared,
            sets,
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
fn expansions(index: &Index, signatures: &Signatures) -> BTreeMap<InterfaceSlot, Expansion> {
    index
        .stated()
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_interface())
        .map(|(slot, _)| {
            (
                InterfaceSlot(slot),
                interfaces::expand(index, signatures, slot),
            )
        })
        .collect()
}

/// One method-set table per concrete named type the corpus declares, in the
/// order it stated them.
///
/// The embedding graph is walked once per type here rather than once per
/// requirement inside the comparison. Every interface asks the same receiver
/// the same question, so a walk per requirement pays the whole graph again for
/// a table the first walk already filled.
fn method_sets(index: &Index) -> BTreeMap<ConcreteSlot, MethodSet> {
    index
        .stated()
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_concrete_type())
        .map(|(slot, _)| (ConcreteSlot(slot), MethodSet::of(index, Receiver { slot })))
        .collect()
}

/// Every relation each package context declares, by the unit of its concrete
/// type.
fn declared_by_unit(index: &Index, relations: &[Relation]) -> BTreeMap<usize, Box<[usize]>> {
    let mut declared: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let stated = relations
        .iter()
        .enumerate()
        .filter_map(|(at, relation)| declaring_unit(index, relation).map(|unit| (unit, at)));
    for (unit, at) in stated {
        declared.entry(unit).or_default().push(at);
    }
    declared
        .into_iter()
        .map(|(unit, held)| (unit, held.into_boxed_slice()))
        .collect()
}

/// The package context declaring one relation's concrete type.
fn declaring_unit(index: &Index, relation: &Relation) -> Option<usize> {
    index.slot(relation.concrete.slot()).map(|slot| slot.unit)
}

/// What one concrete type answers one interface's requirements with.
///
/// An interface requiring nothing states nothing about any type: every type in
/// every corpus answers it, so a relation would carry no evidence.
fn matched(
    index: &Index,
    signatures: &Signatures,
    asked: (&MethodSet, &Expansion),
) -> Option<Match> {
    let (set, expansion) = asked;
    if expansion.required().is_empty() {
        return None;
    }
    let mut answer = Match {
        pointer: false,
        gap: expansion.gap(),
    };
    for requirement in expansion.required() {
        answer = answered(index, signatures, (set, requirement), answer)?;
    }
    Some(answer)
}

/// What one concrete type answers one required method with.
///
/// A name the type answers with a field rather than a method is not an answer:
/// Go's selector reaches the shallowest member of that name, and a field there
/// is what the type has under it. A member several embedding paths reach at one
/// depth is not one either: the selector is ambiguous, so the relation stays
/// possible with the gap that says so.
fn answered(
    index: &Index,
    signatures: &Signatures,
    asked: (&MethodSet, &Requirement),
    answer: Match,
) -> Option<Match> {
    let (set, requirement) = asked;
    let found: Box<[Member]> = set
        .named(requirement.name())
        .iter()
        .copied()
        .filter(|member| index.slot(member.slot).is_some_and(answers))
        .collect();
    match *found {
        [only] if !only.multiples => compared(index, signatures, (requirement, only), answer),
        [] => None,
        _ => Some(Match {
            gap: answer.gap.or(Some(ResolutionGap::Ambiguous)),
            ..answer
        }),
    }
}

/// Whether one member of a method set is a method that can answer a
/// requirement.
///
/// An interface's own method counts. A struct embedding an interface promotes
/// that interface's methods into its method set — legal Go, and the type does
/// implement the interface — and the only member answering there is the
/// interface's declaration. Its canonical signature is stated exactly as a
/// receiver's is and it belongs to the value form, so the comparison reads it
/// the same way. Admitting only a receiver's methods states nothing about such
/// a type at all: not proved, not possible, and no gap saying why.
fn answers(slot: &Slot) -> bool {
    slot.is_concrete_method() || slot.is_interface_method()
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
