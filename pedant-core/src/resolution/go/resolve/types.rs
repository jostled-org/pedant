//! What concrete named type a receiver expression has, when the snapshot states
//! enough to say.
//!
//! The evidence is the binding the receiver name sees: the type its declaration
//! writes, the type its composite literal names, or the type the callable it
//! calls returns. A receiver reached through any other expression states no
//! named type here, and the caller reports that rather than guessing one.

use pedant_syntax::go::GoInitializerForm;

use crate::resolution::go::binding_fact::GoBindingRecord;
use crate::resolution::go::facts::GoSourceFacts;

use super::imports::FileImports;
use super::index::{Index, Slot, TypeName};
use super::lookup::{self, Outcome};
use super::scopes;

/// One statically known concrete receiver.
///
/// The pointer form is not carried: Go's method-call rules reach a pointer
/// receiver from an addressable value and a value receiver through a pointer,
/// and a local, a parameter, and a composite literal are all addressable, so
/// both forms select the same method set at a call site. The pointer form is
/// what an interface's method set turns on, and that is the structural
/// resolver's question rather than this one.
#[derive(Clone, Copy)]
pub(super) struct Receiver {
    pub(super) unit: usize,
    pub(super) slot: usize,
}

/// Where one receiver expression is written.
#[derive(Clone, Copy)]
pub(super) struct Site<'a> {
    pub(super) unit: usize,
    pub(super) facts: &'a GoSourceFacts,
    pub(super) imports: &'a FileImports<'a>,
    pub(super) scope: u32,
    pub(super) offset: usize,
}

/// The concrete type one receiver expression has, when its evidence is
/// complete.
pub(super) fn concrete(index: &Index, site: Site<'_>, qualifier: &str) -> Option<Receiver> {
    let base = plain_name(qualifier)?;
    let bound = scopes::binding(site.facts, (site.scope, site.offset), base)?;
    from_binding(index, site, bound)
}

/// The receiver name one expression reads, or nothing when the expression is
/// not a name an address or a dereference is taken of.
///
/// A field selection, an index, and a call all state receivers this tier cannot
/// complete, so they answer with no name rather than with the text they were
/// written as.
fn plain_name(qualifier: &str) -> Option<&str> {
    let base = qualifier.trim_start_matches(['&', '*']);
    let named = !base.is_empty()
        && base
            .chars()
            .all(|letter| letter.is_alphanumeric() || letter == '_');
    named.then_some(base)
}

/// The type one binding's own evidence names.
fn from_binding(index: &Index, site: Site<'_>, bound: &GoBindingRecord) -> Option<Receiver> {
    match bound.type_name() {
        Some(name) => named(index, site, (bound.type_qualifier(), name)),
        None => from_initializer(index, site, bound),
    }
}

/// The type one short variable declaration's initializer names.
fn from_initializer(index: &Index, site: Site<'_>, bound: &GoBindingRecord) -> Option<Receiver> {
    let stated = bound.initializer()?;
    let written = (stated.qualifier(), stated.name());
    match stated.form() {
        GoInitializerForm::CompositeLiteral | GoInitializerForm::CompositeLiteralAddress => {
            named(index, site, written)
        }
        GoInitializerForm::Call => called(index, site, written),
    }
}

/// The type a call's value has: the type it converts to, or the single result
/// the callable it names declares.
fn called(index: &Index, site: Site<'_>, written: (Option<&str>, &str)) -> Option<Receiver> {
    let found = candidates(index, site, written);
    let converted = found
        .iter()
        .find(|slot| index.slot(**slot).is_some_and(Slot::is_type));
    match converted {
        Some(slot) => Some(receiver(index, *slot)?),
        None => returned(index, &found),
    }
}

/// The type the single callable a name selects declares as its one result.
fn returned(index: &Index, found: &[usize]) -> Option<Receiver> {
    let [only] = found else {
        return None;
    };
    let callable = index.slot(*only)?;
    let result = callable.result.as_ref()?;
    result_type(index, callable.unit, result)
}

/// The named type one declared result states, read in the package that declared
/// it.
///
/// A qualified result names a package through the imports of the file that
/// wrote it, which is not the file asking, so it states no type here.
fn result_type(index: &Index, unit: usize, result: &TypeName) -> Option<Receiver> {
    match result.qualifier {
        Some(_) => None,
        None => first_type(index, lookup::declared(index, unit, &result.name)),
    }
}

/// The type one written name selects, in the file that wrote it.
fn named(index: &Index, site: Site<'_>, written: (Option<&str>, &str)) -> Option<Receiver> {
    first_type(index, &candidates(index, site, written))
}

/// Every definition one written name selects, bare or package-qualified.
fn candidates(index: &Index, site: Site<'_>, written: (Option<&str>, &str)) -> Box<[usize]> {
    let (qualifier, name) = written;
    let target = qualifier.map(|package| site.imports.named(package));
    let outcome = match target {
        None => lookup::bare(index, (site.unit, site.imports), name),
        Some(None) => Outcome::Missing,
        Some(Some(package)) => lookup::qualified(index, package, name),
    };
    match outcome {
        Outcome::Found(found) => found,
        Outcome::External | Outcome::Missing => Box::from([]),
    }
}

/// The one type among the found definitions, when exactly one is a type.
///
/// Several would be an ambiguous receiver, and a receiver this tier cannot
/// name uniquely is receiver evidence it does not have.
fn first_type(index: &Index, found: &[usize]) -> Option<Receiver> {
    let types: Box<[usize]> = found
        .iter()
        .copied()
        .filter(|slot| index.slot(*slot).is_some_and(Slot::is_type))
        .collect();
    match *types {
        [only] => receiver(index, only),
        _ => None,
    }
}

/// One found type slot, with the unit that declares it.
fn receiver(index: &Index, slot: usize) -> Option<Receiver> {
    index.slot(slot).map(|found| Receiver {
        unit: found.unit,
        slot,
    })
}
