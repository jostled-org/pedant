//! What a selected member states when an interface is the one declaring it.
//!
//! A method an interface declares is never the target of the call selecting it.
//! The value behind the interface decides at run time, so the answer names the
//! concrete method every implementor would supply, and every candidate stays
//! possible however few there are.

use pedant_types::ReferenceKind;

use super::denotation::Answer;
use super::implementations::Implementations;
use super::index::{Index, Slot};
use super::methods;
use super::types::Receiver;

/// What one selected member states: an interface dispatch, or a static answer.
pub(super) fn selected(
    index: &Index,
    implementations: &Implementations,
    asked: (ReferenceKind, &str),
    found: Box<[usize]>,
) -> Answer {
    let (default, name) = asked;
    let dispatched = found
        .iter()
        .any(|slot| index.slot(*slot).is_some_and(Slot::is_interface_method));
    match dispatched {
        true => Answer::dispatched(default, targets(index, implementations, name, &found)),
        false => Answer::found(default, found, None),
    }
}

/// Every definition one interface dispatch could reach: the interface methods
/// the selector named, and the concrete method each implementor answers with.
fn targets(
    index: &Index,
    implementations: &Implementations,
    name: &str,
    found: &[usize],
) -> Box<[usize]> {
    let mut reached: Vec<usize> = found.to_vec();
    for slot in found.iter() {
        reached.extend(implementing_methods(index, implementations, name, *slot));
    }
    reached.sort_unstable();
    reached.dedup();
    reached.into_boxed_slice()
}

/// The concrete method every implementor of one interface method's interface
/// answers under that name.
fn implementing_methods(
    index: &Index,
    implementations: &Implementations,
    name: &str,
    method: usize,
) -> Vec<usize> {
    let interface = index.slot(method).and_then(|slot| slot.holder);
    interface
        .into_iter()
        .flat_map(|holder| implementations.implementors(holder).iter())
        .flat_map(|concrete| methods::members(index, Receiver { slot: *concrete }, name).into_vec())
        .filter(|slot| index.slot(*slot).is_some_and(Slot::is_concrete_method))
        .collect()
}
