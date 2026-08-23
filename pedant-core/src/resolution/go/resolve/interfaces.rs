//! Every method one Go interface requires, expanded through the interfaces it
//! embeds.
//!
//! Go states an interface's method set structurally: the methods it writes plus
//! the methods of every interface it embeds, at any depth. So the requirement
//! list a concrete type is compared against is this expansion rather than the
//! elements one declaration happens to write.
//!
//! An expansion that leaves the snapshot, reaches an element that is not an
//! interface, or reaches a method the corpus cannot name a signature for is
//! incomplete, and says so. An incomplete requirement list can never prove an
//! implementation; it can only leave one possible.

use std::collections::BTreeSet;

use pedant_types::ResolutionGap;

use super::index::{EmbeddedType, Index, Slot};
use super::signatures::Signatures;

/// One method an interface requires.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Requirement {
    name: Box<str>,
    /// The canonical signature the requirement states, absent when the corpus
    /// cannot name one of its terms.
    signature: Option<Box<str>>,
}

impl Requirement {
    /// The method name a concrete type must answer.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// The canonical signature the answering method must state.
    pub(super) fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }
}

/// Every method one interface requires, and why that list may be incomplete.
pub(super) struct Expansion {
    required: Box<[Requirement]>,
    gap: Option<ResolutionGap>,
}

impl Expansion {
    /// Every method the interface requires, one entry per name.
    pub(super) fn required(&self) -> &[Requirement] {
        &self.required
    }

    /// Why the requirement list is not the whole method set, absent when it is.
    pub(super) fn gap(&self) -> Option<ResolutionGap> {
        self.gap
    }
}

/// One expansion in progress: the interfaces still to read, the ones already
/// read, and what has been required so far.
#[derive(Default)]
struct Walk {
    open: Vec<usize>,
    visited: BTreeSet<usize>,
    required: Vec<Requirement>,
    gap: Option<ResolutionGap>,
}

impl Walk {
    /// A walk that has read nothing and opens with one interface.
    fn opening(interface: usize) -> Self {
        Self {
            open: vec![interface],
            ..Self::default()
        }
    }

    /// The next interface to read, skipping every one already read.
    ///
    /// Cycles are a Go program error rather than a shape to follow, so an
    /// interface reached twice is read once.
    fn next_open(&mut self) -> Option<usize> {
        while let Some(slot) = self.open.pop() {
            if self.visited.insert(slot) {
                return Some(slot);
            }
        }
        None
    }

    /// Read one more interface into this expansion.
    fn open(&mut self, interface: usize) {
        self.open.push(interface);
    }

    /// Require one method.
    fn require(&mut self, required: Requirement) {
        if required.signature.is_none() {
            self.refuse(ResolutionGap::UnsupportedSyntax);
        }
        self.required.push(required);
    }

    /// State why this expansion is incomplete, keeping the first reason.
    fn refuse(&mut self, gap: ResolutionGap) {
        self.gap = self.gap.or(Some(gap));
    }

    /// Seal the walk into one requirement per method name.
    ///
    /// Two embedded interfaces may require one name, which Go admits when both
    /// state one signature. Two signatures under one name is a requirement this
    /// tier cannot compare against, so the name survives with no signature and
    /// the expansion says why.
    fn seal(self) -> Expansion {
        let mut sorted = self.required;
        sorted.sort();
        sorted.dedup();
        let mut gap = self.gap;
        let mut merged: Vec<Requirement> = Vec::new();
        for entry in sorted {
            match merged.last_mut() {
                Some(last) if last.name == entry.name => {
                    last.signature = None;
                    gap = gap.or(Some(ResolutionGap::Ambiguous));
                }
                _ => merged.push(entry),
            }
        }
        Expansion {
            required: merged.into_boxed_slice(),
            gap,
        }
    }
}

/// Every method one interface requires, read through every interface it embeds.
pub(super) fn expand(index: &Index, signatures: &Signatures, interface: usize) -> Expansion {
    let mut walk = Walk::opening(interface);
    while let Some(slot) = walk.next_open() {
        read_interface(index, signatures, slot, &mut walk);
    }
    walk.seal()
}

/// Read every element one interface declares.
fn read_interface(index: &Index, signatures: &Signatures, interface: usize, walk: &mut Walk) {
    let Some(found) = index.slot(interface) else {
        return;
    };
    if found.general_terms {
        walk.refuse(ResolutionGap::UnsupportedSyntax);
    }
    let members = index
        .unit(found.unit)
        .map(|tables| tables.held(&found.name))
        .unwrap_or_default();
    for member in members {
        read_element(index, signatures, (found, *member), walk);
    }
}

/// Read one element an interface declares: a method it requires, or an
/// interface it embeds.
fn read_element(index: &Index, signatures: &Signatures, stated: (&Slot, usize), walk: &mut Walk) {
    let (owner, member) = stated;
    let Some(held) = index.slot(member) else {
        return;
    };
    match (held.is_interface_method(), held.is_embedded_field()) {
        (true, _) => walk.require(Requirement {
            name: Box::from(&*held.name),
            signature: signatures.of_slot(member).map(Box::from),
        }),
        (_, true) => open_embedded(index, (owner, held), walk),
        _ => {}
    }
}

/// Open the interface one embedded element names.
fn open_embedded(index: &Index, stated: (&Slot, &Slot), walk: &mut Walk) {
    let (owner, held) = stated;
    let Some(embedded) = embedded_type(index, owner, &held.name) else {
        walk.refuse(ResolutionGap::ExternalDefinition);
        return;
    };
    let named = declared_types(index, embedded);
    if named.is_empty() {
        walk.refuse(ResolutionGap::ExternalDefinition);
    }
    for slot in named.iter() {
        open_interface(index, *slot, walk);
    }
}

/// Open one named type, which an interface may embed only if it is one.
fn open_interface(index: &Index, slot: usize, walk: &mut Walk) {
    match index.slot(slot).is_some_and(Slot::is_interface) {
        true => walk.open(slot),
        false => walk.refuse(ResolutionGap::UnsupportedSyntax),
    }
}

/// The in-snapshot type one embedded element of an interface names.
fn embedded_type<'a>(index: &'a Index, owner: &Slot, written: &str) -> Option<&'a EmbeddedType> {
    index
        .unit(owner.unit)?
        .embedded(&owner.name)
        .iter()
        .find(|embedding| &*embedding.embedded.name == written)
        .map(|embedding| &embedding.embedded)
}

/// Every definition one embedded type identity names that is a type.
fn declared_types(index: &Index, embedded: &EmbeddedType) -> Box<[usize]> {
    index
        .unit(embedded.unit)
        .map(|tables| tables.named(&embedded.name))
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|slot| index.slot(*slot).is_some_and(Slot::is_type))
        .collect()
}
