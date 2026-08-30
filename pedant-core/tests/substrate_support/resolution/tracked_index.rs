//! What this repository tracks, as Git states it.
//!
//! A proof about a *committed* file cannot read the working tree. The two
//! disagree in exactly the direction that matters: a generated file nobody
//! added is present here and absent in every other checkout, so a filesystem
//! walk answers "the generator ran on this machine once" while the claim being
//! made is "every checkout sees this". The index is where that becomes shared.
//!
//! Git is also the only authority that knows what this repository *declines* to
//! track — `docs/` and `logs/` hold ignored lifecycle files a walk would sweep
//! in.

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::OnceLock;

use crate::resolution::root_inventory::workspace_root;

/// Every tracked path under one pathspec, repository-relative, in Git's order.
///
/// The pathspec is passed after `--`, so a leading dash or a glob is a path to
/// Git rather than an option. `-z` is what makes the split total: a path
/// holding a newline would otherwise arrive as two paths, and the two halves
/// would name files that do not exist.
///
/// A pathspec that matched nothing stops here. Git exits 0 for a glob that
/// selects no row, so every caller that filters the result and asserts the
/// remainder is empty — which is how a negative claim about tracked files is
/// written — passes unchanged the moment a directory is renamed out from under
/// its pattern.
pub(crate) fn tracked_paths(pathspec: &str) -> Box<[Box<str>]> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", pathspec])
        .current_dir(workspace_root())
        .output()
        .expect("git is available");
    assert!(
        output.status.success(),
        "git ls-files {pathspec} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let paths: Box<[Box<str>]> = String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(Box::from)
        .collect();
    assert!(
        !paths.is_empty(),
        "git tracks no path matching {pathspec}, so every claim over that selection is vacuous"
    );
    paths
}

/// Whether this repository tracks one path, as Git states it.
///
/// Asked instead of `Path::is_file`, which answers for the working tree. A
/// generated or forgotten file satisfies the filesystem on the machine that
/// produced it and exists in no other checkout, so a claim written as "must be
/// a tracked package" that read the disk was making the weaker claim its own
/// message denies.
pub(crate) fn is_tracked(relative: &str) -> bool {
    tracked_index().contains(relative)
}

/// The whole tracked index, read once for the process.
///
/// One `git ls-files` rather than one per question: the answer is a property of
/// the commit, and three trees ask it of a few hundred paths between them.
fn tracked_index() -> &'static BTreeSet<Box<str>> {
    static INDEX: OnceLock<BTreeSet<Box<str>>> = OnceLock::new();
    INDEX.get_or_init(|| tracked_paths("*").into_vec().into_iter().collect())
}
