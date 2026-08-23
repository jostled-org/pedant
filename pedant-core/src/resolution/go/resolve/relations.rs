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
/// name and naming the interface it answers.
pub(super) fn of_unit(
    index: &Index,
    implementations: &Implementations,
    unit: usize,
) -> Vec<Denotation> {
    implementations
        .relations()
        .iter()
        .filter(|relation| declares(index, relation, unit))
        .filter_map(|relation| implementation(index, relation))
        .collect()
}

/// Whether one package context declares the concrete type of one relation.
fn declares(index: &Index, relation: &Relation, unit: usize) -> bool {
    index
        .slot(relation.concrete)
        .is_some_and(|slot| slot.unit == unit)
}

/// One structural relation, as the site its concrete type is named at.
///
/// A relation the comparison could not finish stays possible however complete
/// its one candidate looks: the gap says which part of the method set the
/// corpus could not read, and an answer resolved beside that gap would claim
/// the comparison proved what it explicitly did not.
fn implementation(index: &Index, relation: &Relation) -> Option<Denotation> {
    let concrete = index.slot(relation.concrete)?;
    Some(Denotation {
        kind: ReferenceKind::Implementation,
        text: Arc::from(implementing_form(&concrete.name, relation.pointer)),
        span: concrete.site.clone(),
        enclosing: Some(relation.concrete),
        candidates: Box::from([relation.interface]),
        gap: relation.gap,
        conditional: concrete.conditional,
        possible_only: relation.gap.is_some(),
    })
}

/// The form of a concrete type that carries an interface's whole method set.
///
/// A type whose answering methods all receive a value implements as itself; one
/// answering with a method that receives a pointer implements only as `*T`, and
/// the site says so rather than claiming the value form does.
fn implementing_form(name: &str, pointer: bool) -> Box<str> {
    match pointer {
        true => format!("*{name}").into_boxed_str(),
        false => Box::from(name),
    }
}
