//! Filling the names `use` items bind, to a fixed point.
//!
//! One import may name another, so a single pass would depend on source order.
//! Each round resolves every import against the bindings the previous rounds
//! produced and only ever adds, so the first round that adds nothing is the
//! answer.
//!
//! That round's outcomes were computed against the bindings it left unchanged,
//! which are the final ones, so they are kept and the record each import
//! writes for itself reads them rather than resolving the same path a ninth
//! time.

use crate::ir::sites::{ReferenceOrigin, ReferenceSite};
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use super::bindings::Bindings;
use super::corpus::Corpus;
use super::error::RustResolutionError;
use super::lookup::{Outcome, Target, resolve_path};
use super::references::ReferenceEntry;

/// How many times imports may be re-resolved before the chain is taken as
/// pathological. Each round strictly adds, so a chain of re-exports shallower
/// than this always settles first.
const MAX_ROUNDS: u32 = 8;

/// What the fixed point produced.
pub(super) struct Imports {
    bindings: Bindings,
    /// What each entry's import path resolved to under the final bindings,
    /// indexed parallel to the entries. `None` marks an entry that is not an
    /// import site.
    outcomes: Box<[Option<Outcome>]>,
}

impl Imports {
    /// The names every module instance's imports bound.
    pub(super) fn bindings(&self) -> &Bindings {
        &self.bindings
    }

    /// What the import at `entry` resolved to, when that entry is one.
    pub(super) fn outcome(&self, entry: usize) -> Option<&Outcome> {
        self.outcomes.get(entry).and_then(Option::as_ref)
    }
}

/// What one import site binds locally.
enum Binding {
    /// The import binds this one local name.
    Named(Box<str>),
    /// The import brings in every name of the module it names.
    Glob,
    /// The import states no name this tier can bind.
    Absent,
}

/// One import site's answer under one round's bindings.
struct Resolved {
    node: usize,
    binding: Binding,
    outcome: Outcome,
}

/// Resolve every import until the bound name set stops growing.
///
/// Non-convergence is refused rather than truncated: a chain deeper than
/// [`MAX_ROUNDS`] would leave its tail bindings unfilled, and every reference
/// through them would be written as a missing definition — indistinguishable
/// from a name that genuinely does not exist.
pub(super) fn bind(
    corpus: &Corpus<'_>,
    snapshot: &RustResolutionSnapshot,
    entries: &[ReferenceEntry],
) -> Result<Imports, RustResolutionError> {
    let mut bindings = Bindings::default();
    for _ in 0..MAX_ROUNDS {
        let round: Box<[Option<Resolved>]> = entries
            .iter()
            .map(|entry| resolve_entry(corpus, &bindings, snapshot, entry))
            .collect();
        if !apply(&mut bindings, &round) {
            return Ok(Imports {
                bindings,
                outcomes: outcomes(round),
            });
        }
    }
    Err(RustResolutionError::ImportsNotConverged { rounds: MAX_ROUNDS })
}

fn apply(bindings: &mut Bindings, round: &[Option<Resolved>]) -> bool {
    round.iter().flatten().fold(false, |changed, resolved| {
        changed | record(bindings, resolved)
    })
}

fn record(bindings: &mut Bindings, resolved: &Resolved) -> bool {
    match (&resolved.outcome, &resolved.binding) {
        (Outcome::Found(targets), Binding::Named(name)) => {
            bindings.bind(resolved.node, name, targets)
        }
        (Outcome::Found(targets), Binding::Glob) => glob(bindings, resolved.node, targets),
        _ => false,
    }
}

fn glob(bindings: &mut Bindings, node: usize, targets: &[Target]) -> bool {
    modules_of(targets).iter().fold(false, |changed, module| {
        changed | bindings.bind_glob(node, *module)
    })
}

fn outcomes(round: Box<[Option<Resolved>]>) -> Box<[Option<Outcome>]> {
    round
        .into_vec()
        .into_iter()
        .map(|found| found.map(|resolved| resolved.outcome))
        .collect()
}

fn resolve_entry(
    corpus: &Corpus<'_>,
    bindings: &Bindings,
    snapshot: &RustResolutionSnapshot,
    entry: &ReferenceEntry,
) -> Option<Resolved> {
    let site = import_site(corpus, snapshot, entry)?;
    Some(Resolved {
        node: entry.node,
        binding: binding_of(site),
        outcome: resolve_path(corpus, bindings, entry.node, site.segments()),
    })
}

fn binding_of(site: &ReferenceSite) -> Binding {
    match (site.is_glob(), bound_name(site)) {
        (true, _) => Binding::Glob,
        (false, Some(name)) => Binding::Named(name),
        (false, None) => Binding::Absent,
    }
}

fn import_site<'a>(
    corpus: &Corpus<'_>,
    snapshot: &'a RustResolutionSnapshot,
    entry: &ReferenceEntry,
) -> Option<&'a ReferenceSite> {
    let site = corpus
        .graph
        .file_ir(snapshot, entry.node)?
        .reference_sites
        .get(entry.site)?;
    (site.origin() == ReferenceOrigin::Import).then_some(site)
}

/// The local name an import binds: its alias, or its last path segment.
fn bound_name(site: &ReferenceSite) -> Option<Box<str>> {
    match site.alias() {
        Some(alias) => Some(Box::from(alias)),
        None => site.segments().last().cloned(),
    }
}

fn modules_of(targets: &[Target]) -> Box<[usize]> {
    targets
        .iter()
        .filter_map(|target| match target {
            Target::Module(node) => Some(*node),
            Target::Definition(_) => None,
        })
        .collect()
}
