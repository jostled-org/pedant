//! An index published while a manifest changes names a tree that existed.
//!
//! A build reads each manifest to load its project, and the bytes it parsed are
//! the bytes its revision states. A second read of the same file for the
//! revision could see a later edit, and the index would then pair units parsed
//! from one manifest with the identity of another: a revision of a tree that
//! never existed. A live index that then refuses the next rebuild keeps that
//! revision as its last good one.
//!
//! The manifest here alternates between two complete versions, each placed by a
//! rename, so every read sees one whole version. A build may still refuse when a
//! manifest changes under it. What no build may do is publish a revision that
//! neither version's tree has.
//!
//! The two versions name different packages. Versions that differed only in
//! bytes would load the same units, and units of one version under the digest
//! of the other would be exactly the other tree's revision. One indexer builds
//! every revision, as a live index's does.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use pedant_snippet::{CodeIntelligenceIndexer, CodeIntelligenceLimits};

use crate::index::fixture::{Repository, parented};
use crate::index::harness::indexed;
use crate::index::root::TempRoot;
use crate::index::sources::CRATE_A_MANIFEST;

/// Builds attempted while the manifest alternates. Enough that an edit lands
/// between a build's reads many times over when a build makes two.
const BUILDS: usize = 300;

/// A repository, the manifest in it that alternates, and its two versions.
struct EditedRepository {
    files: &'static [(&'static str, &'static str)],
    manifest: &'static str,
    versions: [&'static str; 2],
}

/// A Cargo workspace whose one member is renamed.
const RUST_MEMBER: EditedRepository = EditedRepository {
    files: &[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crate-a\"]\nresolver = \"3\"\n",
        ),
        ("crate-a/src/lib.rs", "pub fn make() -> u32 {\n    1\n}\n"),
    ],
    manifest: "crate-a/Cargo.toml",
    versions: [
        CRATE_A_MANIFEST,
        "[package]\nname = \"crate-b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ],
};

/// A Go module whose module path is renamed.
const GO_MODULE: EditedRepository = EditedRepository {
    files: &[("main.go", "package main\n\nfunc main() {}\n")],
    manifest: "go.mod",
    versions: [
        "module example.com/first\n\ngo 1.22\n",
        "module example.com/second\n\ngo 1.22\n",
    ],
};

#[test]
fn a_rust_index_built_during_a_manifest_edit_names_a_tree_that_existed() {
    assert_every_published_tree_existed(&RUST_MEMBER);
}

#[test]
fn a_go_index_built_during_a_manifest_edit_names_a_tree_that_existed() {
    assert_every_published_tree_existed(&GO_MODULE);
}

fn assert_every_published_tree_existed(edited: &'static EditedRepository) {
    let existed = edited.versions.map(|version| {
        indexed(&edited.holding(version))
            .index()
            .revision()
            .to_string()
    });
    assert_ne!(
        existed[0], existed[1],
        "the two manifests must publish different revisions, or a torn one hides"
    );

    let repository = Arc::new(edited.holding(edited.versions[0]));
    let running = Arc::new(AtomicBool::new(true));
    let editor = {
        let repository = Arc::clone(&repository);
        let running = Arc::clone(&running);
        thread::spawn(move || edited.alternate_until_stopped(&repository, &running))
    };

    let mut indexer = CodeIntelligenceIndexer::new(CodeIntelligenceLimits::default());
    let published: Vec<String> = (0..BUILDS)
        .filter_map(|_| indexer.index(repository.root(), &[]).ok())
        .map(|state| state.index().revision().to_string())
        .collect();
    running.store(false, Ordering::Relaxed);
    editor.join().expect("the editing thread ends cleanly");

    assert!(
        !published.is_empty(),
        "no build published, so nothing here was compared"
    );
    let torn: Vec<&String> = published
        .iter()
        .filter(|revision| !existed.contains(revision))
        .collect();
    let distinct: BTreeSet<&String> = torn.iter().copied().collect();
    assert!(
        torn.is_empty(),
        "{} of {} published revisions name neither tree {existed:?}: {distinct:?}",
        torn.len(),
        published.len()
    );
}

impl EditedRepository {
    /// The repository with its manifest at one version.
    fn holding(&self, version: &str) -> Repository {
        let repository = Repository::of(self.files);
        repository.write(self.manifest, version);
        repository
    }

    /// Swap the manifest between its two versions until told to stop, each
    /// time by renaming complete bytes over it.
    fn alternate_until_stopped(&self, repository: &Repository, running: &AtomicBool) {
        let staging = TempRoot::new();
        let staged = staging.canonical().join("staged");
        let target = repository.root().join(self.manifest);
        for version in self.versions.iter().rev().cycle() {
            if !running.load(Ordering::Relaxed) {
                return;
            }
            std::fs::write(&staged, version).expect("the staged manifest is written");
            std::fs::rename(&staged, parented(&target)).expect("the staged manifest is placed");
        }
    }
}
