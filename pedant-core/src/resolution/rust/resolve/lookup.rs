//! Rust path resolution over the snapshot's definition index.
//!
//! A path starts at the crate root, at the module it is written in, at that
//! module's parent, or at a dependency unit's root, and then walks module
//! members, imported names, glob-imported members, and associated items. No
//! feature or platform universe is chosen here: a conditional definition stays
//! in the corpus and its certainty is decided when the record is written.

use super::bindings::Bindings;
use super::corpus::Corpus;

/// One thing a path segment may select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Target {
    /// A definition slot in the report under construction.
    Definition(usize),
    /// A module instance of some unit.
    Module(usize),
}

/// What one path resolved to.
pub(super) enum Outcome {
    /// The path selects these targets.
    Found(Box<[Target]>),
    /// The path leaves the indexed corpus.
    External,
    /// Nothing in the corpus matches the path.
    Missing,
    /// The path form is not one this tier resolves.
    Unsupported,
}

/// Where a path's first segment lands.
enum Start {
    Targets(Box<[Target]>),
    Refused(Outcome),
}

/// Resolve one path, written inside `from`, against the corpus.
pub(super) fn resolve_path(
    corpus: &Corpus<'_>,
    bindings: &Bindings,
    from: usize,
    segments: &[Box<str>],
) -> Outcome {
    let Some((first, rest)) = segments.split_first() else {
        return Outcome::Unsupported;
    };
    let mut current = match start(corpus, bindings, from, first) {
        Start::Targets(targets) => targets,
        Start::Refused(outcome) => return outcome,
    };
    for segment in rest {
        current = descend(corpus, bindings, &current, segment);
        if current.is_empty() {
            return Outcome::Missing;
        }
    }
    Outcome::Found(current)
}

/// Every member of one module that `name` selects, glob imports included.
pub(super) fn members(
    corpus: &Corpus<'_>,
    bindings: &Bindings,
    node: usize,
    name: &str,
) -> Box<[Target]> {
    let mut targets = direct_members(corpus, bindings, node, name);
    if targets.is_empty() {
        targets.extend(glob_members(corpus, bindings, node, name));
    }
    sorted(targets)
}

fn start(corpus: &Corpus<'_>, bindings: &Bindings, from: usize, first: &str) -> Start {
    match first {
        "crate" => at_root(corpus, corpus.unit_of(from)),
        "self" => Start::Targets(Box::from([Target::Module(from)])),
        "super" => at_module(corpus.parent_of(from)),
        "$crate" => Start::Refused(Outcome::External),
        name => named_start(corpus, bindings, from, name),
    }
}

fn named_start(corpus: &Corpus<'_>, bindings: &Bindings, from: usize, name: &str) -> Start {
    let lexical = lexical_lookup(corpus, bindings, from, name);
    if !lexical.is_empty() {
        return Start::Targets(lexical);
    }
    let unit = corpus
        .unit_of(from)
        .and_then(|unit| corpus.units.named(unit, name));
    match unit {
        Some(found) => at_root(corpus, Some(found)),
        None => Start::Refused(Outcome::External),
    }
}

fn at_root(corpus: &Corpus<'_>, unit: Option<usize>) -> Start {
    at_module(unit.and_then(|unit| corpus.root_of(unit)))
}

fn at_module(node: Option<usize>) -> Start {
    match node {
        Some(found) => Start::Targets(Box::from([Target::Module(found)])),
        None => Start::Refused(Outcome::External),
    }
}

/// Look one name up in the module it is written in, then in each module above.
fn lexical_lookup(
    corpus: &Corpus<'_>,
    bindings: &Bindings,
    from: usize,
    name: &str,
) -> Box<[Target]> {
    let mut current = Some(from);
    while let Some(node) = current {
        let found = members(corpus, bindings, node, name);
        if !found.is_empty() {
            return found;
        }
        current = corpus.parent_of(node);
    }
    Box::from([])
}

fn descend(
    corpus: &Corpus<'_>,
    bindings: &Bindings,
    targets: &[Target],
    name: &str,
) -> Box<[Target]> {
    let mut next: Vec<Target> = Vec::new();
    for target in targets {
        match target {
            Target::Module(node) => next.extend(members(corpus, bindings, *node, name)),
            Target::Definition(slot) => next.extend(associated(corpus, *slot, name)),
        }
    }
    sorted(next)
}

/// The associated items one type, trait, or module definition exposes, inside
/// the unit that holds the owner.
///
/// The index keys associated items by owner name alone, so a source two units
/// share offers each of its owners twice. A path descends into the owner it
/// already resolved, which fixes the unit the members must come from.
fn associated(corpus: &Corpus<'_>, slot: usize, name: &str) -> Box<[Target]> {
    let Some(owner) = corpus.index.slot(slot) else {
        return Box::from([]);
    };
    corpus
        .index
        .associated(&owner.name, name)
        .iter()
        .filter(|found| corpus.holds(owner.node, **found))
        .map(|found| Target::Definition(*found))
        .collect()
}

fn glob_members(corpus: &Corpus<'_>, bindings: &Bindings, node: usize, name: &str) -> Vec<Target> {
    bindings
        .globs(node)
        .iter()
        .flat_map(|module| direct_members(corpus, bindings, *module, name))
        .collect()
}

/// The members one module states directly, without following its own globs.
fn direct_members(
    corpus: &Corpus<'_>,
    bindings: &Bindings,
    node: usize,
    name: &str,
) -> Vec<Target> {
    let mut targets: Vec<Target> = corpus
        .index
        .names_in(node, name)
        .iter()
        .map(|slot| Target::Definition(*slot))
        .collect();
    targets.extend(
        corpus
            .index
            .modules_in(node, name)
            .iter()
            .map(|child| Target::Module(*child)),
    );
    targets.extend(bindings.named(node, name).iter().copied());
    targets
}

fn sorted(mut targets: Vec<Target>) -> Box<[Target]> {
    targets.sort_unstable();
    targets.dedup();
    targets.into_boxed_slice()
}
