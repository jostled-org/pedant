//! What concrete named type a receiver expression has, when the snapshot states
//! enough to say.
//!
//! The evidence is the binding the receiver name sees: the type its declaration
//! writes, the type its composite literal names, or the type the callable it
//! calls returns. A receiver reached through any other expression states no
//! named type here, and the caller reports that rather than guessing one.

use pedant_syntax::go::GoInitializerForm;

use crate::resolution::go::binding_fact::GoBindingRecord;

use super::imports::FileImports;
use super::index::{Index, Slot, TypeName};
use super::lookup::{self, Outcome};

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
    pub(super) slot: usize,
}

/// Where one receiver expression is written.
#[derive(Clone, Copy)]
pub(super) struct Site<'a> {
    pub(super) unit: usize,
    pub(super) imports: &'a FileImports<'a>,
}

/// The receiver name one expression reads, or nothing when the expression is
/// not a name an address or a dereference is taken of.
///
/// A field selection, an index, and a call all state receivers this tier cannot
/// complete, so they answer with no name rather than with the text they were
/// written as.
pub(super) fn plain_name(qualifier: &str) -> Option<&str> {
    let base = held(qualifier).trim_start_matches(['&', '*']);
    let named = !base.is_empty()
        && base
            .chars()
            .all(|letter| letter.is_alphanumeric() || letter == '_');
    named.then_some(base)
}

/// The expression one parenthesized receiver holds.
///
/// Go binds a selector tighter than an address or a dereference, so `*p.M()`
/// dereferences what the call returns and `&n.M()` takes the address of it. A
/// receiver dereferenced or addressed before its member is selected is written
/// `(*p).M()` and `(&n).M()`, so the parentheses are part of the text every such
/// receiver arrives as.
///
/// Peeled with a loop rather than by recursion. The text is a raw source slice,
/// so its nesting is whatever the repository wrote: a recursive peel spends one
/// stack frame per parenthesis, and the only thing standing between that and a
/// blown stack is a caller-raisable syntax ceiling.
fn held(qualifier: &str) -> &str {
    let mut current = qualifier;
    while let Some(inner) = current
        .strip_prefix('(')
        .and_then(|open| open.strip_suffix(')'))
    {
        current = inner;
    }
    current
}

/// The type one binding's own evidence names.
pub(super) fn from_binding(
    index: &Index,
    site: Site<'_>,
    bound: &GoBindingRecord,
) -> Option<Receiver> {
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
///
/// The conversion is read through the same "exactly one type" rule every other
/// receiver claim is. Picking the first type among several would state a
/// receiver for `T(x)` where two packages answer `T`, which is an ambiguous
/// conversion rather than a choice, and the answer would then feed a resolved
/// method call.
fn called(index: &Index, site: Site<'_>, written: (Option<&str>, &str)) -> Option<Receiver> {
    let found = candidates(index, site, written);
    match first_type(index, &found) {
        Some(receiver) => Some(receiver),
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
fn first_type(index: &Index, found: &[usize]) -> Option<Receiver> {
    unique_type(index, found, |slot, _| slot).map(|slot| Receiver { slot })
}

/// The one key every type among the found definitions shares, when they share
/// exactly one.
///
/// Three stages ask this question of the same candidate list, and each cares
/// about a different notion of "one type": a receiver needs one definition, a
/// canonical signature needs one declaring package, and an embedding needs one
/// type identity. Keyed rather than copied, because three copies of the rule
/// are three answers one input can get — a name twin declarations state twice
/// is one type to a signature and two candidates to a receiver only when one
/// owner says so.
///
/// Several keys is a Go program error rather than a choice, so the answer is
/// nothing at all.
pub(super) fn unique_type<Key: Ord>(
    index: &Index,
    found: &[usize],
    key: impl Fn(usize, &Slot) -> Key,
) -> Option<Key> {
    let mut keys: Vec<Key> = found
        .iter()
        .filter_map(|slot| index.slot(*slot).map(|found| (*slot, found)))
        .filter(|(_, found)| found.is_type())
        .map(|(slot, found)| key(slot, found))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    match keys.len() {
        1 => keys.pop(),
        _ => None,
    }
}
