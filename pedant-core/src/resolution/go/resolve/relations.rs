//! The structural relations one package context's own types hold, as sites.
//!
//! Go writes no syntax for implementing an interface: the relation is the whole
//! method set. So these sites are written at the concrete type's own name
//! rather than at an occurrence, which is the one place the source states the
//! type the relation belongs to.

use std::sync::Arc;

use pedant_types::ReferenceKind;

use super::denotation::Denotation;
use super::implementations::{Implementations, Relation};
use super::index::Index;

/// Every structural relation the concrete types of one package context hold.
///
/// One site per proved or possible pair, written at the concrete type's own
/// name and naming the interface it answers. The comparison already partitioned
/// its relations by the context declaring each concrete type, so this reads one
/// bucket rather than rescanning every relation the corpus states.
pub(super) fn of_unit(
    index: &Index,
    implementations: &Implementations,
    unit: usize,
) -> Vec<Denotation> {
    implementations
        .of_unit(unit)
        .filter_map(|relation| implementation(index, relation))
        .collect()
}

/// One structural relation, as the site its concrete type is named at.
///
/// A relation the comparison could not finish stays possible however complete
/// its one candidate looks: the gap says which part of the method set the
/// corpus could not read, and an answer resolved beside that gap would claim
/// the comparison proved what it explicitly did not.
fn implementation(index: &Index, relation: &Relation) -> Option<Denotation> {
    let concrete = index.slot(relation.concrete.slot())?;
    Some(Denotation {
        kind: ReferenceKind::Implementation,
        text: implementing_form(&concrete.name, relation.pointer),
        span: concrete.site.clone(),
        enclosing: Some(relation.concrete.slot()),
        candidates: Box::from([relation.interface.slot()]),
        gap: relation.gap,
        conditional: concrete.conditional,
        possible_only: relation.gap.is_some(),
    })
}

/// The form of a concrete type that carries an interface's whole method set.
///
/// A type whose answering methods all receive a value implements as itself; one
/// answering with a method that receives a pointer implements only as `*T`, and
/// the site says so rather than claiming the value form does. The value form
/// shares the name the slot already holds rather than copying it.
fn implementing_form(name: &Arc<str>, pointer: bool) -> Arc<str> {
    match pointer {
        true => Arc::from(format!("*{name}")),
        false => Arc::clone(name),
    }
}
