//! Reading the committed tree and holding it to [`super::authority_model`].
//!
//! Each function below answers one question the model asks. None builds,
//! spawns, or reads outside the repository, and every file it opens is
//! committed — so the proof compiles in every configuration and a reintroduced
//! identifier is a regression a normal `cargo test` catches.
//!
//! [`read_text`] states what happens when a subject is absent, and it is never
//! "pass".

use std::collections::BTreeSet;
use std::fs;
use std::sync::OnceLock;

use crate::resolution::authority_model::{
    AUTHORITIES, Authority, FIRST_PARTY_SOURCES, FORBIDDEN_IDENTIFIERS, FORBIDDEN_PATHS,
    MIGRATED_PREDICATE_SITE, MIGRATED_PREDICATES,
};
use crate::resolution::production_tree::nested_sources_from;
use crate::resolution::root_inventory::workspace_root;
use crate::resolution::tracked_script::CI_WORKFLOW;

/// The workflow key that names the trees CI scans.
const CI_SOURCE_KEY: &str = "FIRST_PARTY_SOURCES:";

/// One first-party source, read once for every question asked of it.
pub struct Source {
    /// Where the file sits, repository-relative and slash-separated.
    pub path: Box<str>,
    /// Its whole text.
    pub text: Box<str>,
}

/// Read one file, failing loudly rather than treating it as empty.
///
/// An unreadable document must not read as a satisfied clause: that is the one
/// way this proof could pass a tree it never inspected.
pub fn read_text(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Every `.rs` file beneath the eight first-party source trees, in path order.
///
/// The scan runs once per process and every caller borrows that one reading.
/// Three cases ask questions of the same hundred files, and three walks answer
/// no more than one does.
pub fn first_party_sources() -> &'static [Source] {
    static SOURCES: OnceLock<Box<[Source]>> = OnceLock::new();
    SOURCES.get_or_init(scan_first_party_sources)
}

fn scan_first_party_sources() -> Box<[Source]> {
    assert_the_scanned_trees_are_the_workflows();
    let root = workspace_root();
    let found: BTreeSet<Box<str>> = FIRST_PARTY_SOURCES
        .iter()
        .flat_map(|tree| nested_sources_from(&root, &root.join(tree)))
        .map(String::into_boxed_str)
        .collect();
    assert!(
        found.len() > 50,
        "the first-party source scan found only {} files, so it is not reading the tree",
        found.len()
    );
    found
        .into_iter()
        .map(|path| {
            let text = read_text(&path).into_boxed_str();
            Source { path, text }
        })
        .collect()
}

/// The model's trees are the trees the tracked workflow scans.
///
/// [`FIRST_PARTY_SOURCES`] was a second hand-written copy of the workflow's own
/// job-env list with nothing holding the two together. A crate added to CI and
/// not here leaves the authority and forbidden-identifier scans reading a
/// narrower surface than the job does, and every claim over them goes on
/// passing — which is the failure this whole model is written down to reject.
///
/// Asserted where the scan is built rather than beside one case, so every
/// consumer of that one reading gets it.
fn assert_the_scanned_trees_are_the_workflows() {
    let workflow = read_text(CI_WORKFLOW);
    let stated: BTreeSet<&str> = workflow
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(CI_SOURCE_KEY))
        .unwrap_or_else(|| {
            panic!("{CI_WORKFLOW} must state {CI_SOURCE_KEY}, or nothing binds this scan to it")
        })
        .split_whitespace()
        .collect();
    assert!(
        !stated.is_empty(),
        "{CI_WORKFLOW} states {CI_SOURCE_KEY} with no tree, so the job scans nothing"
    );
    let modelled: BTreeSet<&str> = FIRST_PARTY_SOURCES.iter().copied().collect();
    assert_eq!(
        stated, modelled,
        "{CI_WORKFLOW}'s {CI_SOURCE_KEY} and the authority model must name the same trees"
    );
}

/// Every first-party source that names `needle`, in path order.
///
/// Settled the moment the filter is over; both callers read it and neither
/// appends to it.
fn sources_naming<'a>(sources: &'a [Source], needle: &str) -> Box<[&'a str]> {
    sources
        .iter()
        .filter(|source| source.text.contains(needle))
        .map(|source| &*source.path)
        .collect()
}

/// Each authority is where the model says, and nowhere else.
pub fn assert_authorities(sources: &[Source]) {
    for authority in AUTHORITIES {
        assert_authority(sources, authority);
    }
}

fn assert_authority(sources: &[Source], authority: &Authority) {
    let found = sources_naming(sources, authority.marker);
    assert_eq!(
        &*found, authority.sites,
        "{}: {:?} must be named by exactly {:?}",
        authority.label, authority.marker, authority.sites
    );
}

/// No removed identifier survived anywhere, and no removed file came back.
pub fn assert_removed_authorities_are_absent(sources: &[Source]) {
    for identifier in FORBIDDEN_IDENTIFIERS {
        let found = sources_naming(sources, identifier);
        assert!(
            found.is_empty(),
            "{identifier} was removed in the breaking seam but is named by {found:?}"
        );
    }
    let root = workspace_root();
    for path in FORBIDDEN_PATHS {
        assert!(
            !root.join(path).exists(),
            "{path} was removed but exists again"
        );
    }
}

/// The migrated workspace-member cases run under the substrate root.
pub fn assert_migrated_predicates() {
    let source = read_text(MIGRATED_PREDICATE_SITE);
    for predicate in MIGRATED_PREDICATES {
        assert!(
            source.contains(predicate),
            "{MIGRATED_PREDICATE_SITE} must carry {predicate}"
        );
    }
    let substrate = read_text("pedant-core/tests/substrate.rs");
    assert!(
        substrate.contains("substrate_support/resolution/mod.rs"),
        "substrate.rs must declare the resolution support tree that carries them"
    );
}
