//! Reading the committed tree and holding it to [`super::authority_model`].
//!
//! Each function below answers one question the model asks. None builds,
//! spawns, or reads outside the repository, and every file it opens is
//! committed — so this half of the proof compiles in every configuration and
//! runs in the ordinary `[ci]` matrix, where a reintroduced identifier is a
//! regression a normal `cargo test` must catch. The scans that index local
//! tooling live in [`super::authority_acceptance`] and
//! [`super::authority_documents`], which carry `resolution-test-support`.
//!
//! [`read_text`] states what happens when a subject is absent, and it is never
//! "pass".

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::resolution::authority_model::{
    AUTHORITIES, Authority, FIRST_PARTY_SOURCES, FORBIDDEN_IDENTIFIERS, FORBIDDEN_PATHS,
    MIGRATED_PREDICATE_SITE, MIGRATED_PREDICATES,
};
use crate::resolution::root_inventory::workspace_root;

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

/// Every `.rs` file beneath the seven first-party source trees, in path order.
///
/// Each is read once here rather than once per question. Ten scans over the
/// same hundred files answer no more than one does.
pub fn first_party_sources() -> Box<[Source]> {
    let root = workspace_root();
    let mut found: BTreeSet<Box<str>> = BTreeSet::new();
    for tree in FIRST_PARTY_SOURCES {
        collect_rust_files(&root.join(tree), &root, &mut found);
    }
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

fn collect_rust_files(directory: &Path, root: &Path, found: &mut BTreeSet<Box<str>>) {
    let entries =
        fs::read_dir(directory).unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    for entry in entries
        .map(|entry| entry.unwrap_or_else(|error| panic!("{}: {error}", directory.display())))
    {
        let path = entry.path();
        match (path.is_dir(), path.extension().is_some_and(|it| it == "rs")) {
            (true, _) => collect_rust_files(&path, root, found),
            (false, true) => {
                found.insert(relative_text(root, &path));
            }
            (false, false) => (),
        }
    }
}

fn relative_text(root: &Path, path: &Path) -> Box<str> {
    let relative = path.strip_prefix(root).unwrap_or_else(|error| {
        panic!(
            "{} is outside scanned root {}: {error}",
            path.display(),
            root.display()
        )
    });
    relative
        .to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .replace('\\', "/")
        .into_boxed_str()
}

/// Every first-party source that names `needle`, in path order.
fn sources_naming<'a>(sources: &'a [Source], needle: &str) -> Vec<&'a str> {
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
        found, authority.sites,
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
