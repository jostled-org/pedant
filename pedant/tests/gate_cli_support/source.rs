//! Tracked-source reading, shared by every boundary claim beside it.
//!
//! Production source, test source, Cargo manifests, and release workflows are
//! the only inputs. No plan, specification, log, or lifecycle manifest is
//! consulted here.

use std::fs;
use std::path::{Path, PathBuf};

/// The CLI gate family, which declares and re-exports only from its root.
const GATE_TREE: &str = "src/gate";

/// The gate CLI support tree, which carries every assertion body this root
/// registers.
const SUPPORT_TREE: &str = "tests/gate_cli_support";

pub(crate) fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub(crate) fn workspace_root() -> PathBuf {
    manifest_dir()
        .parent()
        .expect("the workspace root is the package parent")
        .to_path_buf()
}

pub(crate) fn gate_tree() -> PathBuf {
    manifest_dir().join(GATE_TREE)
}

pub(crate) fn gate_module(name: &str) -> PathBuf {
    gate_tree().join(name)
}

pub(crate) fn support_tree() -> PathBuf {
    manifest_dir().join(SUPPORT_TREE)
}

pub(crate) fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is tracked: {error}", path.display()))
}

/// One text with every run of whitespace collapsed to one space.
pub(crate) fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// One tracked source in collapsed form.
///
/// A wiring claim is about which owner receives which value, not about where
/// the formatter chose to break the line, so every call-shape assertion beside
/// this one reads this form.
pub(crate) fn normalized(path: &Path) -> String {
    collapsed(&read(path))
}

/// One source line with any comment tail removed.
///
/// A claim about what the tree *does* must not be satisfiable by prose, so
/// every scan below reads this form.
#[cfg(feature = "semantic")]
fn without_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(head, _)| head)
}

/// Every `.rs` file directly beneath one tree, sorted by file name.
pub(crate) fn module_names(tree: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(tree)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", tree.display()))
        .map(|entry| entry.expect("a directory entry is readable").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| {
            path.file_name()
                .expect("a source file has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    found
}

pub(crate) fn assert_inventory(tree: &Path, declared: &[&str]) {
    assert_eq!(
        module_names(tree),
        declared,
        "the inventory of {} is exact",
        tree.display()
    );
}

/// Every `.rs` file beneath one tree, at any depth.
pub(crate) fn collect_sources(root: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", root.display()));
    for entry in entries {
        let path = entry.expect("a directory entry is readable").path();
        match (
            path.is_dir(),
            path.extension().is_some_and(|extension| extension == "rs"),
        ) {
            (true, _) => collect_sources(&path, found),
            (false, true) => found.push(path),
            (false, false) => (),
        }
    }
}

/// Every site under the gate CLI support tree that one scan names, as its
/// module and the value the scan read there, in tree order.
///
/// A support-tree claim is a claim about the whole tree rather than about the
/// modules that happened to be searched, so the scan walks the on-disk
/// inventory and the caller states the result as a whole set.
#[cfg(feature = "semantic")]
pub(crate) fn support_tree_sites(scan: impl Fn(&str) -> Vec<String>) -> Vec<String> {
    let tree = support_tree();
    let mut sites = Vec::new();
    for module in module_names(&tree) {
        for line in read(&tree.join(&module)).lines() {
            for value in scan(without_comment(line)) {
                sites.push(format!("{module} -> {value}"));
            }
        }
    }
    sites
}
