//! The whole-repository Go surface: which sources implement it, and which test
//! modules prove it.
//!
//! Three crates carry Go production code and five roots carry Go cases, so a
//! claim about "the Go surface" spans the workspace rather than this crate. The
//! set is stated, never discovered: a discovered set agrees with whatever the
//! tree happens to contain, so it could not reject an adapter that appeared
//! beside the projector or a support module nothing registered.
//!
//! Stated once because both Step 13 claims read it. The registration case asks
//! whether every Go owner is declared and every predicate registered; the
//! policy case holds production sources to the repository's structural rules.
//! Two inventories could pass one and drift on the other.
//!
//! The two claims range over different universes, so the set is stated in two
//! parts. [`production_sources`] is the Go surface, and registration is a claim
//! about it alone. [`plan_sources`] adds the production owners this plan wrote
//! or changed elsewhere, because "no body is written twice" is only decidable
//! when both copies are read and this plan wrote one half of several pairs
//! outside the Go trees.
//!
//! The test-side half of the same inventory is [`super::support_trees`], and
//! the path and directory helpers below serve both.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::resolution::go::owners::{GO_MODULES, RESOLVE_MODULES};
use crate::resolution::root_inventory::workspace_root;

/// One crate's Go production tree.
pub struct ProductionTree {
    /// The package that publishes it.
    pub package: &'static str,
    /// The tree, relative to the workspace root.
    pub directory: &'static str,
    /// Every modelled module, relative to `directory`. Grouped because the core
    /// tree's two halves are already stated apart in [`super::owners`].
    pub families: &'static [&'static [&'static str]],
    /// The subdirectories `directory` holds, so an exactness check counts them
    /// beside the files rather than reporting them as absent owners.
    pub subdirectories: &'static [&'static str],
}

/// The Go projection adapter, relative to `pedant-graph/src/go`.
pub const GRAPH_GO_MODULES: &[&str] = &[
    "entry.rs",
    "mapping.rs",
    "mod.rs",
    "placement.rs",
    "projection.rs",
    "validation.rs",
];

/// The Go grammar inventory, relative to `pedant-syntax/src/go`.
pub const SYNTAX_GO_MODULES: &[&str] = &[
    "binding.rs",
    "condition.rs",
    "context.rs",
    "declaration.rs",
    "error.rs",
    "facts.rs",
    "frame.rs",
    "import.rs",
    "limits.rs",
    "mod.rs",
    "reference.rs",
    "scope.rs",
    "signature.rs",
    "span.rs",
    "walk.rs",
    "written_type.rs",
];

/// Every Go production tree in the workspace, in dependency order.
pub const GO_PRODUCTION: &[ProductionTree] = &[
    ProductionTree {
        package: "pedant-syntax",
        directory: "pedant-syntax/src/go",
        families: &[SYNTAX_GO_MODULES],
        subdirectories: &[],
    },
    ProductionTree {
        package: "pedant-core",
        directory: "pedant-core/src/resolution/go",
        families: &[GO_MODULES, RESOLVE_MODULES],
        subdirectories: &["resolve"],
    },
    ProductionTree {
        package: "pedant-graph",
        directory: "pedant-graph/src/go",
        families: &[GRAPH_GO_MODULES],
        subdirectories: &[],
    },
];

/// The language-neutral projection this plan built the Go adapter on top of,
/// relative to `pedant-graph/src/projection`.
pub const PROJECTION_MODULES: &[&str] = &[
    "assembly.rs",
    "draft.rs",
    "forest.rs",
    "mod.rs",
    "placement.rs",
    "state.rs",
    "validation.rs",
];

/// Directories this plan created whole outside the Go trees.
///
/// One so far: Step 11 split the Rust assembler into a neutral projection both
/// languages mint through, and every module beneath it is this plan's. Modelled
/// as a tree rather than a file list for the same reason the Go trees are — a
/// module that appeared beside the assembler unregistered has to fail.
pub const PLAN_TREES: &[ProductionTree] = &[ProductionTree {
    package: "pedant-graph",
    directory: "pedant-graph/src/projection",
    families: &[PROJECTION_MODULES],
    subdirectories: &[],
}];

/// Every other production module this plan wrote or changed.
///
/// Exit Criterion 14 claims no body is written twice across the modules written
/// in this plan, and the Go trees are not those modules: the plan widened the
/// shared report vocabulary, hoisted `LineIndex` and the path helpers into
/// language-neutral owners, split the graph assembler, and changed each Rust
/// counterpart of a Go module it added. A scan that stopped at the Go trees
/// collects a body copied between a Go module and its Rust twin exactly once
/// and reports no duplicate.
///
/// Stated rather than derived, like every inventory here. Deriving it would
/// mean running version control, which this case is registered to prove without
/// a process, and a derived set agrees with whatever the tree holds instead of
/// rejecting a module nothing registered.
///
/// The eight published packages are the production surface. `test-support`
/// crates ship with no release and assert by design, so holding them to a
/// production rule would state a claim about the wrong code.
pub const PLAN_MODULES: &[&str] = &[
    "pedant-core/src/lib.rs",
    "pedant-core/src/observe/event.rs",
    "pedant-core/src/observe/probe.rs",
    "pedant-core/src/resolution/digest.rs",
    "pedant-core/src/resolution/identity.rs",
    "pedant-core/src/resolution/line_index.rs",
    "pedant-core/src/resolution/mod.rs",
    "pedant-core/src/resolution/paths.rs",
    "pedant-core/src/resolution/rust/fingerprint.rs",
    "pedant-core/src/resolution/rust/identity.rs",
    "pedant-core/src/resolution/rust/mod.rs",
    "pedant-core/src/resolution/rust/paths.rs",
    "pedant-core/src/resolution/rust/resolve/coordinates.rs",
    "pedant-core/src/resolution/rust/resolve/error.rs",
    "pedant-core/src/resolution/rust/resolve/index.rs",
    "pedant-core/src/resolution/rust/resolve/pipeline.rs",
    "pedant-core/src/resolution/rust/resolve/references.rs",
    "pedant-core/src/resolution/rust/resolve/target.rs",
    "pedant-core/src/resolution/sites.rs",
    "pedant-graph/src/edge.rs",
    "pedant-graph/src/error.rs",
    "pedant-graph/src/lib.rs",
    "pedant-graph/src/rust/cache.rs",
    "pedant-graph/src/rust/claim.rs",
    "pedant-graph/src/rust/mapping.rs",
    "pedant-graph/src/rust/mod.rs",
    "pedant-graph/src/rust/projection.rs",
    "pedant-graph/src/rust/reuse.rs",
    "pedant-graph/src/rust/source.rs",
    "pedant-graph/src/rust/validation.rs",
    "pedant-lang/src/attribution/anchors.rs",
    "pedant-lang/src/attribution/mod.rs",
    "pedant-lang/src/attribution/symbols.rs",
    "pedant-lang/src/go.rs",
    "pedant-syntax/src/extract/ts.rs",
    "pedant-syntax/src/lib.rs",
    "pedant-syntax/src/tree_sitter/session.rs",
    "pedant-types/src/resolution/definition.rs",
    "pedant-types/src/resolution/reference.rs",
    "pedant/src/supply_chain/attestation.rs",
    "pedant/src/supply_chain/receipt.rs",
];

/// A tracked path, resolved against the workspace root.
pub fn tracked_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

/// Read one tracked file, failing loudly rather than treating it as empty.
///
/// An unreadable file must not read as a satisfied clause: that is the one way
/// a structural claim could pass over a file it never inspected.
pub fn tracked_text(relative: &str) -> String {
    let path = tracked_path(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()))
}

/// Every modelled module of one production tree, as its repository-relative
/// path.
pub fn tree_modules(tree: &ProductionTree) -> Box<[String]> {
    tree.families
        .iter()
        .flat_map(|family| family.iter())
        .map(|module| format!("{}/{module}", tree.directory))
        .collect()
}

/// Every Go production source in the workspace, proved to be exactly the
/// modelled set first.
pub fn production_sources() -> Box<[String]> {
    let mut sources: Vec<String> = Vec::new();
    for tree in GO_PRODUCTION {
        assert!(
            tracked_path(&format!("{}/Cargo.toml", tree.package)).is_file(),
            "{} must be a tracked package to own a Go tree",
            tree.package
        );
        assert_tree_is_exactly_modelled(tree);
        sources.extend(tree_modules(tree));
    }
    assert!(
        sources.len() > GO_MODULES.len(),
        "the Go surface spans three crates, so it must exceed one crate's module list"
    );
    sources.into_boxed_slice()
}

/// Every production source this plan wrote or changed, in one sorted set.
///
/// [`production_sources`] answers the Go registration claim and stops at the Go
/// trees, which is the right universe for "every Go owner is registered". It is
/// the wrong universe for a claim about duplicate bodies: a duplicate is only
/// visible when both copies are read, and this plan wrote one half of several
/// pairs outside those trees.
pub fn plan_sources() -> Box<[String]> {
    let mut sources: Vec<String> = production_sources().into_vec();
    let go = sources.len();
    for tree in PLAN_TREES {
        assert!(
            tracked_path(&format!("{}/Cargo.toml", tree.package)).is_file(),
            "{} must be a tracked package to own a plan tree",
            tree.package
        );
        assert_tree_is_exactly_modelled(tree);
        sources.extend(tree_modules(tree));
    }
    sources.extend(PLAN_MODULES.iter().map(|module| (*module).to_owned()));
    assert_each_is_tracked(&sources);
    assert_each_is_stated_once(&mut sources, go);
    sources.into_boxed_slice()
}

/// No modelled owner names a file the repository does not hold.
///
/// A stated path that moved has to fail here. Reading it as absent would drop
/// the module from every claim below while leaving each one green.
fn assert_each_is_tracked(sources: &[String]) {
    let missing: Vec<&String> = sources
        .iter()
        .filter(|module| !tracked_path(module).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "every modelled production owner must be a tracked file: {missing:?}"
    );
}

/// Each owner reaches the scan once, and the plan set is wider than the Go
/// trees it contains.
///
/// A path stated twice would enter the duplicate scan as its own copy, so the
/// claim would fail on a body written once. The width guard is the other half:
/// it refuses a plan set that quietly collapsed back to the Go trees.
fn assert_each_is_stated_once(sources: &mut Vec<String>, go: usize) {
    let stated = sources.len();
    assert!(
        stated > go,
        "this plan wrote production modules outside the Go trees, so the set must exceed them"
    );
    sources.sort_unstable();
    sources.dedup();
    assert_eq!(
        sources.len(),
        stated,
        "every production owner is modelled exactly once"
    );
}

/// One production tree holds exactly its modelled modules and subdirectories,
/// at every level.
fn assert_tree_is_exactly_modelled(tree: &ProductionTree) {
    let root = tracked_path(tree.directory);
    let mut top: Vec<&str> = tree
        .families
        .iter()
        .flat_map(|family| family.iter())
        .filter(|module| !module.contains('/'))
        .copied()
        .chain(tree.subdirectories.iter().copied())
        .collect();
    top.sort_unstable();
    assert_directory_holds_exactly(&root, &top);
    for nested in tree.subdirectories {
        let prefix = format!("{nested}/");
        let held: Box<[&str]> = tree
            .families
            .iter()
            .flat_map(|family| family.iter())
            .filter_map(|module| module.strip_prefix(&prefix))
            .collect();
        assert_directory_holds_exactly(&root.join(nested), &held);
    }
}

/// Nothing sits beside the modelled owners in a directory a model claims whole.
///
/// Stated here rather than in each caller because three inventories make the
/// same claim about a directory, and a second copy of the walk could report one
/// of them against a set the others never saw.
pub fn assert_directory_holds_exactly(directory: &Path, modelled: &[&str]) {
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
    assert_eq!(
        found,
        expected,
        "every entry beneath {} must be a modelled owner",
        directory.display()
    );
}

/// Every `.rs` file beneath a directory, as a path relative to it.
///
/// Recursive, because a support tree may hold one: `enclosing_unit_support`
/// keeps its ownership modules in a subdirectory, and a flat listing would
/// report the Go module there as absent.
pub fn nested_sources(directory: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    collect_nested(directory, directory, &mut found);
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
                found.insert(relative_text(root, &path));
            }
            (false, false) => {}
        }
    }
}

fn relative_text(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or_else(|error| panic!("{} is outside {}: {error}", path.display(), root.display()))
        .to_string_lossy()
        .replace('\\', "/")
}
