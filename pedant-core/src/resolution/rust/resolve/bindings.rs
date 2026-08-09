//! The names imports bring into a module instance.
//!
//! Imports may name other imports, so bindings are filled to a fixed point
//! before any other reference is resolved. Each round only adds, so the loop
//! terminates on the round that adds nothing.

use std::collections::BTreeMap;

use super::lookup::Target;

/// The answer a lookup with no entry returns.
const NO_TARGETS: &[Target] = &[];

/// The answer a glob lookup with no entry returns.
const NO_MODULES: &[usize] = &[];

/// What `use` items bound inside each module instance.
#[derive(Default)]
pub(super) struct Bindings {
    named: BTreeMap<usize, BTreeMap<Box<str>, Box<[Target]>>>,
    globs: BTreeMap<usize, Box<[usize]>>,
}

impl Bindings {
    /// The targets one imported name selects inside `node`.
    pub(super) fn named(&self, node: usize, name: &str) -> &[Target] {
        self.named
            .get(&node)
            .and_then(|scope| scope.get(name))
            .map_or(NO_TARGETS, |found| found)
    }

    /// The modules every name of which one glob import brought into `node`.
    pub(super) fn globs(&self, node: usize) -> &[usize] {
        self.globs.get(&node).map_or(NO_MODULES, |found| found)
    }

    /// Bind `name` inside `node`, reporting whether the binding grew.
    ///
    /// Binding only ever adds. Two `use` items may bind one name — this tier
    /// evaluates no `cfg`, so a name that a platform-gated pair of imports
    /// both bind carries both candidates — and a later round may resolve a
    /// path an earlier one could not. Replacing would drop whichever answer
    /// came second in source order and leave the fixed point non-monotone,
    /// so the loop would run every round on any module that states such a
    /// pair.
    pub(super) fn bind(&mut self, node: usize, name: &str, targets: &[Target]) -> bool {
        let scope = self.named.entry(node).or_default();
        let bound = scope
            .get(name)
            .map(|existing| (covers(existing, targets), existing));
        let merged = match bound {
            Some((true, _)) => return false,
            Some((false, existing)) => union(existing, targets),
            None => Box::from(targets),
        };
        scope.insert(Box::from(name), merged);
        true
    }

    /// Bring every name of `module` into `node`, reporting whether it is new.
    pub(super) fn bind_glob(&mut self, node: usize, module: usize) -> bool {
        let entry = self.globs.entry(node).or_default();
        match entry.contains(&module) {
            true => false,
            false => {
                *entry = entry.iter().copied().chain([module]).collect();
                true
            }
        }
    }
}

/// Whether `existing` already states every target of this round.
fn covers(existing: &[Target], targets: &[Target]) -> bool {
    targets.iter().all(|target| existing.contains(target))
}

/// Every target of both sides, sorted and deduplicated.
fn union(existing: &[Target], targets: &[Target]) -> Box<[Target]> {
    let mut merged: Vec<Target> = existing.iter().chain(targets).copied().collect();
    merged.sort_unstable();
    merged.dedup();
    merged.into_boxed_slice()
}
