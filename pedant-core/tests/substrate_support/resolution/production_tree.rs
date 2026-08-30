//! One production tree, claimed whole.
//!
//! A structural claim about a crate is only as good as the set of files it
//! reads. A discovered set agrees with whatever the tree happens to hold, so it
//! cannot reject a module that arrived beside the modelled owners and was
//! registered nowhere. Every model here therefore states its modules and then
//! holds the directory to exactly that list, at every level.
//!
//! Shared rather than copied. The Go surface and the code-intelligence product
//! ask the same question of different trees, and two walks would let one of them
//! drift into reading a directory the other never saw.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::resolution::tracked_index::is_tracked;
use crate::resolution::tracked_script::tracked_path;

/// One crate's production tree, and every module it is modelled to hold.
pub(crate) struct ProductionTree {
    /// The package that publishes it.
    pub(crate) package: &'static str,
    /// The tree, relative to the workspace root.
    pub(crate) directory: &'static str,
    /// Every modelled module, relative to `directory`. Grouped because a tree
    /// whose families are already stated apart should not have to restate them
    /// as one list.
    pub(crate) families: &'static [&'static [&'static str]],
    /// The subdirectories `directory` holds whose contents this same tree
    /// claims, by `<name>/` prefix in `families`.
    pub(crate) subdirectories: &'static [&'static str],
    /// The subdirectories `directory` holds whose contents another tree claims.
    ///
    /// A directory has to be counted where it sits, or a fifth one appearing
    /// beside the four would read as an unmodelled entry that nobody notices.
    /// It must not be walked twice, though: two trees claiming one directory is
    /// two lists to keep in step, and the pair would disagree exactly when a
    /// module moved.
    pub(crate) delegated: &'static [&'static str],
}

/// Every modelled module of one production tree, in the order its families
/// state them.
///
/// The one flattening of `families`. Three claims read that list — the
/// repository-relative inventory, the top-level listing, and each
/// subdirectory's — and three private flattenings were three filters that could
/// stop agreeing about which modules a family holds.
fn modules(tree: &ProductionTree) -> impl Iterator<Item = &'static str> {
    tree.families
        .iter()
        .flat_map(|family| family.iter().copied())
}

/// Every modelled module of one production tree, as its repository-relative
/// path.
pub(crate) fn tree_modules(tree: &ProductionTree) -> Box<[String]> {
    modules(tree)
        .map(|module| format!("{}/{module}", tree.directory))
        .collect()
}

/// One production tree holds exactly its modelled modules and subdirectories,
/// at every level.
pub(crate) fn assert_tree_is_exactly_modelled(tree: &ProductionTree) {
    // Git, not the disk. "Tracked" is the claim the message makes, and a
    // generated manifest satisfies `is_file` on the machine that produced it and
    // exists in no other checkout.
    assert!(
        is_tracked(&format!("{}/Cargo.toml", tree.package)),
        "{} must be a tracked package to own a production tree",
        tree.package
    );
    let root = tracked_path(tree.directory);
    // Unsorted: the listing below compares two sets, and a sort before that
    // comparison ordered a list nothing reads in order.
    let top: Box<[&str]> = modules(tree)
        .filter(|module| !module.contains('/'))
        .chain(tree.subdirectories.iter().copied())
        .chain(tree.delegated.iter().copied())
        .collect();
    assert_directory_holds_exactly(&root, &top);
    for nested in tree.subdirectories {
        let prefix = format!("{nested}/");
        let held: Box<[&str]> = modules(tree)
            .filter_map(|module| module.strip_prefix(&prefix))
            .collect();
        assert_directory_holds_exactly(&root.join(nested), &held);
    }
}

/// Nothing sits beside the modelled owners in a directory a model claims whole.
pub(crate) fn assert_directory_holds_exactly(directory: &Path, modelled: &[&str]) {
    let found: BTreeSet<String> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| {
            entry
                .expect("a readable directory yields readable entries")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let expected: BTreeSet<String> = modelled.iter().map(|name| (*name).to_owned()).collect();
    // The set below collapses a name stated twice, and a model that lists one
    // owner twice then compares equal to a directory holding it once. That is a
    // model with a row nothing reads, which is how a module leaves a list
    // without the list noticing.
    assert_eq!(
        expected.len(),
        modelled.len(),
        "the model of {} states a name twice: {modelled:?}",
        directory.display()
    );
    assert_eq!(
        found,
        expected,
        "every entry beneath {} must be a modelled owner",
        directory.display()
    );
}

/// Every `.rs` file beneath a directory, as a path relative to it.
///
/// Recursive, because a support tree may hold one: a root that keeps its
/// ownership modules in a subdirectory would otherwise read as missing them.
pub(crate) fn nested_sources(directory: &Path) -> BTreeSet<String> {
    nested_sources_from(directory, directory)
}

/// Every `.rs` file beneath `directory`, named relative to `root`.
///
/// The form the first-party source scan needs: it walks eight trees and names
/// every file by the repository that holds them all, so the root it renders
/// against is not the directory it descends from. The scan used to carry its
/// own copy of this walk — the same `read_dir`, the same panic on an unreadable
/// entry, the same `(is_dir, ext == "rs")` match, and the same slash
/// normalization — and two walks are two chances for one to start reading a
/// directory the other never saw.
pub(crate) fn nested_sources_from(root: &Path, directory: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    collect_nested(root, directory, &mut found);
    found
}

fn collect_nested(root: &Path, directory: &Path, found: &mut BTreeSet<String>) {
    let listing =
        fs::read_dir(directory).unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    for entry in listing {
        let path = entry
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
            .path();
        match (path.is_dir(), path.extension().is_some_and(|it| it == "rs")) {
            (true, _) => collect_nested(root, &path, found),
            (false, true) => {
                found.insert(tree_relative(root, &path));
            }
            (false, false) => {}
        }
    }
}

/// One path beneath `root`, as the slash-separated text every claim names it by.
///
/// A path outside `root` stops here, and so does one no reader can spell. The
/// walks above always descend from the root they were given, and a caller that
/// resolved somewhere else — or onto bytes that are not UTF-8 — is asking a
/// question this text cannot answer.
///
/// Named for the tree it renders rather than for the normalization it performs:
/// `relative_text` is the marker the authority model gives to
/// `pedant-core/src/resolution/path_normalization.rs`, and a test helper
/// spelling its signature byte for byte is a second site for the one claim this
/// tree exists to make.
pub(crate) fn tree_relative(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or_else(|error| {
        panic!("{} is outside {}: {error}", path.display(), root.display())
    });
    relative
        .to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .replace('\\', "/")
}
