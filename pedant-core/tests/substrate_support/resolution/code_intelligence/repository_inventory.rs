//! 10.T4 (Invariant 23): what this repository ships and what it links, after
//! the code-intelligence product is complete.
//!
//! Four counts and a boundary. Eight published packages, 34 integration
//! executables, no inline test inside a production module, every support module
//! declared beneath a root that already existed, every repository check tracked
//! under one directory, and no Cargo test that reads a file a clean checkout
//! does not contain.
//!
//! Each is written down rather than discovered, and each is compared with the
//! walked tree. A membership check would agree with a repository that grew a
//! thirty-fifth executable, which is the one drift this claim exists to reject:
//! the specification's budget is an executable count, and a support module that
//! became a root costs a whole compile-and-link with nothing else turning red.

use std::collections::{BTreeMap, BTreeSet};

use crate::repository_artifact_boundary::local_lifecycle_violations;
use crate::resolution::code_intelligence::hosted_filters::assert_every_workflow_exact_filter_selects_a_registered_test;
use crate::resolution::code_intelligence::product_surface::ProductSurface;
use crate::resolution::module_scan::{Block, Line, classify};
use crate::resolution::root_inventory::{
    INTEGRATION_ROOTS, assert_exact_integration_roots, workspace_members, workspace_root,
};
use crate::resolution::source_routes::{INLINE_TESTS, forbidden_routes};
use crate::resolution::test_identity::{beneath_tests, workspace_test_sources};
use crate::resolution::tracked_index::tracked_paths;

/// The eight packages this workspace publishes.
///
/// Stated in dependency order, and compared as a set. Release order is
/// `release-plz.toml`'s and is not this one — it places `pedant-lang` sixth,
/// after the snippet crate, where the dependency reading puts it third. Naming
/// this list "release order" too would be a second authority on a question the
/// manifest already answers, and the two already disagree.
///
/// A ninth member that appeared would be a ninth crates.io identity, and the
/// release graph, the packaged-workspace proof, and the archive budget all count
/// on this being the whole list.
const PUBLISHED_PACKAGES: [&str; 8] = [
    "pedant-types",
    "pedant-syntax",
    "pedant-lang",
    "pedant-core",
    "pedant-graph",
    "pedant-snippet",
    "pedant-mcp",
    "pedant",
];

/// The workspace member that ships with no release.
///
/// It is a member, so a package count taken from `[workspace] members` alone
/// would report nine. It is excluded from the root manifest's workspace and
/// carries `publish = false`, which is what makes eight the right number.
const UNPUBLISHED_MEMBER: &str = "test-support/process-guard";

/// The directory every tracked repository check sits under.
const CHECK_DIRECTORY: &str = ".github/scripts";

/// How many tracked checks that directory must hold at the least.
///
/// A floor rather than an exact count: this plan adds scripts, and a claim that
/// pinned the number would have to be rewritten by every step that adds one.
/// What the floor rejects is a directory that emptied — the state in which every
/// registration claim above it would pass over nothing.
const MINIMUM_TRACKED_CHECKS: usize = 20;

/// 10.T4 (Invariant 23): eight published packages, 34 integration executables,
/// no inline production test, every support module beneath an existing root,
/// every check tracked in one directory and reachable from a job, every exact
/// filter selecting a registered test, and no test reading local lifecycle
/// state.
#[test]
fn code_intelligence_test_and_release_inventory_is_exact() {
    assert_the_workspace_publishes_exactly_eight_packages();
    assert_exact_integration_roots();
    assert_no_product_module_declares_an_inline_test(&ProductSurface::read());
    assert_every_support_module_sits_beneath_an_existing_root();
    assert_every_repository_check_is_tracked_in_one_directory();
    assert_every_workflow_exact_filter_selects_a_registered_test();
    assert_no_cargo_test_reads_local_lifecycle_state();
}

/// The workspace declares exactly the eight published packages plus the one
/// unpublished test-support member.
fn assert_the_workspace_publishes_exactly_eight_packages() {
    let members: BTreeSet<String> = workspace_members(&workspace_root()).into_iter().collect();
    let expected: BTreeSet<String> = PUBLISHED_PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect();
    assert_eq!(
        members, expected,
        "the workspace links exactly the eight published packages"
    );
    assert!(
        workspace_root().join(UNPUBLISHED_MEMBER).is_dir(),
        "{UNPUBLISHED_MEMBER} is the excluded test-support crate, and it must stay excluded"
    );
    assert!(
        !members.contains(UNPUBLISHED_MEMBER),
        "{UNPUBLISHED_MEMBER} ships with no release, so it is not a workspace member"
    );
}

/// No module of the completed product declares an inline test.
///
/// Inline tests in production source are compiled into the library, so they
/// change what a consumer links and they are invisible to the integration-root
/// budget above. Every case this product states lives beneath one of the 34.
fn assert_no_product_module_declares_an_inline_test(surface: &ProductSurface) {
    let offenders: Box<[Box<str>]> = surface
        .modules()
        .iter()
        .flat_map(|module| {
            forbidden_routes(&module.parsed, &INLINE_TESTS)
                .into_vec()
                .into_iter()
                .map(move |route| format!("{} declares {route}", module.path).into_boxed_str())
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "production modules declare no inline test: {offenders:?}"
    );
}

/// Every support module a test root declares is explicit, and every one of them
/// resolves inside the crate's own `tests/` tree.
///
/// A support module reached by `#[path]` is linked into the declaring root's
/// executable and costs nothing extra; the same file sitting at `tests/*.rs`
/// would be a thirty-fifth executable, which the count above rejects. This is
/// that claim read from the other side. A declaration that escaped the tree with
/// `..` would be a module two crates could link, and a declaration naming a file
/// that no longer exists would be a support module silently dropped from
/// whichever root stopped compiling it.
///
/// Both the roots and the files they must resolve to come from the one
/// process-wide reading of every member's `tests/` tree. Thirty-four roots sit
/// in ten of those trees, so the walk this used to make per root read
/// `pedant-core/tests` fourteen times over for an answer that does not change.
fn assert_every_support_module_sits_beneath_an_existing_root() {
    let trees = tests_trees();
    let sources = workspace_test_sources();
    let mut offenders: Vec<String> = Vec::new();
    let mut attribute = 0;
    let mut gated = 0;
    for entry in INTEGRATION_ROOTS {
        let (member, _) = beneath_tests(entry, "an integration root");
        let held = trees
            .get(member)
            .unwrap_or_else(|| panic!("{member} holds an integration root and no test sources"));
        let text = sources
            .iter()
            .find(|source| &*source.path == *entry)
            .map(|source| &*source.text)
            .unwrap_or_else(|| panic!("{entry} is an integration root the test scan never read"));
        for (form, path) in declared_paths(text) {
            match form {
                Declaration::Attribute => attribute += 1,
                Declaration::Gated => gated += 1,
            }
            if !held.contains(&*path) {
                offenders.push(format!("{entry} declares {path}"));
            }
        }
    }
    assert!(
        attribute > INTEGRATION_ROOTS.len(),
        "the support scan found {attribute} attribute declarations, so it is not reading the roots"
    );
    assert!(
        gated > 0,
        "no root declares a support module through the gated form, so this scan would no longer \
         see one moved behind the profile gate"
    );
    assert!(
        offenders.is_empty(),
        "every support module resolves inside its own crate's tests tree: {offenders:?}"
    );
}

/// Every test source of the workspace, grouped by the member whose `tests/` tree
/// holds it, and keyed by its path inside that tree.
///
/// The key is the member rather than the root, because a `#[path]` a root writes
/// is relative to the `tests/` directory the root sits in and every root of one
/// member shares it.
fn tests_trees() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    let mut trees: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for source in workspace_test_sources() {
        let path = &source.path;
        let (member, relative) = beneath_tests(path, "a test source");
        trees.entry(member).or_default().insert(relative);
    }
    trees
}

/// The two written forms a test root declares a support module in.
///
/// Counted apart, because a floor over their sum is answered by whichever form is
/// commoner. The snippet root moved four of its support modules from the first
/// form to the second in one commit, and a repository-wide total of thirty-odd
/// declarations did not notice.
#[derive(Clone, Copy)]
enum Declaration {
    /// `#[path = "..."] mod name;`, written directly by the root.
    Attribute,
    /// `"..." => name,`, written inside `complete_profile_path_modules!`.
    Gated,
}

/// Every support-module path one test root declares, with the form it used.
///
/// Both forms name a file the same way and reach the same place: the macro
/// expands its rows to the attribute under the closed-profile feature gate. A
/// scan that read only the attribute would stop seeing a module the moment a root
/// moved it behind that gate, and the escape and dangling-file claims above would
/// pass silently over it.
///
/// The two written forms are recognized by [`classify`] and not by a second
/// reader here. This module used to restate the macro name, the block state
/// machine, and both row shapes — a second reader of the same two forms, which
/// is precisely the drift `module_scan` was split out to prevent.
fn declared_paths(text: &str) -> Box<[(Declaration, Box<str>)]> {
    let mut declarations: Vec<(Declaration, Box<str>)> = Vec::new();
    let mut block = Block::None;
    for line in text.lines().map(str::trim) {
        match (block, classify(line)) {
            (Block::None, Line::Opens(opened)) => block = opened,
            (_, Line::Closes) => block = Block::None,
            (Block::None, Line::Path(path)) => {
                declarations.push((Declaration::Attribute, path.into()));
            }
            (Block::GatedPath, Line::GatedPathRow(_, row)) => {
                declarations.extend(row.path.map(|path| (Declaration::Gated, path)));
            }
            _ => {}
        }
    }
    declarations.into_boxed_slice()
}

/// Every tracked repository check sits under one directory, and there are
/// enough of them for the registration claims above to mean something.
///
/// The stray selection is every tracked check by name, not every check already
/// sitting under a `scripts/` directory. A pathspec that required the directory
/// answered the question with its own premise: a check written at `ci/check_x.sh`
/// selected no row, and an empty selection satisfied the emptiness clause below.
fn assert_every_repository_check_is_tracked_in_one_directory() {
    let tracked = tracked_paths(&format!("{CHECK_DIRECTORY}/*.sh"));
    assert!(
        tracked.len() >= MINIMUM_TRACKED_CHECKS,
        "{CHECK_DIRECTORY} tracks {} shell files; at least {MINIMUM_TRACKED_CHECKS} are expected",
        tracked.len()
    );
    let stray = tracked_paths("*check_*.sh");
    let outside: Box<[&str]> = stray
        .iter()
        .map(|path| &**path)
        .filter(|path| !path.starts_with(CHECK_DIRECTORY))
        .collect();
    assert!(
        outside.is_empty(),
        "every repository check is tracked under {CHECK_DIRECTORY}: {outside:?}"
    );
}

/// No Cargo test names a file a clean checkout does not contain.
///
/// One implementation, two registered owners: the artifact-boundary case states
/// it for the repository, and this inventory states it as part of what the
/// completed product leaves behind. A second scan could pass one while the other
/// drifted.
fn assert_no_cargo_test_reads_local_lifecycle_state() {
    let violations = local_lifecycle_violations();
    assert!(
        violations.is_empty(),
        "Cargo tests must not name local lifecycle artifacts: {violations:?}"
    );
}
