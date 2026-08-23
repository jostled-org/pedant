//! Which binding one occurrence sees, read from the lexical scopes its source
//! states.
//!
//! Go resolves a name in the innermost scope that binds it, and only from the
//! point the binding is written. Both rules are read here from the fact
//! inventory alone: a scope names its parent, a binding names its scope, and
//! every span indexes the one source they were all extracted from.

use pedant_syntax::go::GoScopeFact;

use crate::resolution::go::binding_fact::GoBindingRecord;
use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::identity::index_of;

/// The scopes holding one position, innermost first, closing with the file
/// scope.
///
/// A cycle cannot occur in a tree the walk built parent-first, but the chain is
/// still bounded by the scope count so a malformed inventory cannot spin here.
fn chain(facts: &GoSourceFacts, scope: u32) -> Box<[u32]> {
    let mut held = Vec::new();
    let mut current = Some(scope);
    while let Some(index) = current.filter(|_| held.len() < facts.scopes().len()) {
        held.push(index);
        current = facts
            .scopes()
            .get(index_of(index))
            .and_then(GoScopeFact::parent);
    }
    held.into_boxed_slice()
}

/// The binding `name` sees at one position, when a scope holding that position
/// binds it.
///
/// The innermost binding wins, and a binding written after the occurrence does
/// not cover it: a package-level name read above the local that shadows it is
/// still the package's. A binding whose name is written before the occurrence
/// but whose own initializer reads the outer name is the one imprecision this
/// rule accepts, and it withholds a claim rather than inventing one.
pub(super) fn binding<'a>(
    facts: &'a GoSourceFacts,
    at: (u32, usize),
    name: &str,
) -> Option<&'a GoBindingRecord> {
    let (scope, offset) = at;
    let held = chain(facts, scope);
    facts
        .bindings()
        .iter()
        .filter(|bound| bound.name() == name && bound.span().start_byte() < offset)
        .filter_map(|bound| depth(&held, bound.scope()).map(|depth| (depth, bound)))
        .min_by_key(|(depth, _)| *depth)
        .map(|(_, bound)| bound)
}

/// How far out one scope sits in a chain, or nothing when it is not on it.
fn depth(held: &[u32], scope: u32) -> Option<usize> {
    held.iter().position(|open| *open == scope)
}
