//! Who a capacity refusal is charged to once it has crossed the project seam.
//!
//! A project loader translates a source provider's refusal into its own fault
//! vocabulary, and a graph builder translates the repository's allowance into
//! its own. Either translation can lose the owner, the collection, or the two
//! numbers while still returning a refusal, so every row here fixes all four.
//!
//! Every ceiling below is set to zero or to one, which refuses the first record
//! rather than a record deep in a walk. That fixes the observed count at a value
//! this file can write down, so a mapper that reported the retained count, or
//! that merely stringified the owner, cannot satisfy the assertion.
//!
//! Apart from [`accounting`](super::accounting) because these are the rows about
//! the seam rather than about the repository: none of them reads the mixed
//! repository, and each builds the smallest tree that states one authority.

use pedant_snippet::{CapacityCollection, CapacityOwner};

use super::accounting::{Observed, assert_capacity};
use super::fixture::Repository;
use super::harness::{adjusted, built, go_module, lowered, rust_manifest};
use super::sources::GO_MAIN_MODULE;

/// The smallest Cargo package that resolves: one manifest, one source, one
/// call.
const BOUNDED_PACKAGE: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"bounded\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "src/lib.rs",
        "pub fn bounded() { target(); }\nfn target() {}\n",
    ),
];

/// The same package with a path dependency beneath it.
///
/// A second manifest and a second unit, which is what a ceiling of one manifest
/// or zero units needs something to refuse.
const DEPENDENT_PACKAGE: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"bounded\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         [dependencies]\ndep = { path = \"dep\" }\n",
    ),
    (
        "src/lib.rs",
        "pub fn bounded() { target(); }\nfn target() {}\n",
    ),
    (
        "dep/Cargo.toml",
        "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("dep/src/lib.rs", "pub fn dependency() {}\n"),
];

/// A project loader cannot erase the owner or numbers of a capacity refusal
/// when it translates the source provider into its own fault vocabulary.
pub(super) fn project_loader_ceilings_remain_typed_and_fatal() {
    let rust = Repository::of(BOUNDED_PACKAGE);
    let rust_required = [rust_manifest("Cargo.toml")];

    let bytes = built(
        &rust,
        &rust_required,
        lowered(|limits| limits.max_source_file_bytes = 4),
    )
    .expect_err("a shared repository byte ceiling is fatal through a project loader");
    assert_capacity(
        &bytes,
        CapacityOwner::Repository,
        CapacityCollection::FileBytes,
        Observed::Exactly(5),
        4,
    );

    let structures = built(
        &rust,
        &rust_required,
        lowered(|limits| limits.max_structures = 0),
    )
    .expect_err("a shared repository structure ceiling is checked before retention");
    assert_capacity(
        &structures,
        CapacityOwner::Repository,
        CapacityCollection::Structure,
        Observed::Exactly(2),
        0,
    );

    let rust_depth = built(
        &rust,
        &rust_required,
        adjusted(|limits| limits.rust.max_syntax_depth = 0),
    )
    .expect_err("the Rust provider's syntax ceiling remains typed");
    assert_capacity(
        &rust_depth,
        CapacityOwner::Rust,
        CapacityCollection::SyntaxDepth,
        Observed::Exactly(1),
        0,
    );

    let go = Repository::of(GO_MAIN_MODULE);
    let go_depth = built(
        &go,
        &[go_module("go.mod")],
        adjusted(|limits| limits.go.max_syntax_depth = 0),
    )
    .expect_err("the Go provider's syntax ceiling remains typed");
    assert_capacity(
        &go_depth,
        CapacityOwner::Go,
        CapacityCollection::SyntaxDepth,
        Observed::Exactly(1),
        0,
    );
}

/// Language and graph owners keep their identities across the project seam.
///
/// The two repositories are written once and lent to the three blocks below.
/// Each of them refuses at a ceiling rather than at anything the tree holds, so
/// a rewrite per row was an unread tree write.
pub(super) fn language_and_graph_capacity_owners_remain_typed() {
    let rust = Repository::of(DEPENDENT_PACKAGE);
    let go = Repository::of(GO_MAIN_MODULE);

    the_rust_owner_keeps_its_own_refusals(&rust);
    the_go_owner_keeps_its_own_refusals(&go);
    the_repository_and_graph_builder_are_told_apart(&rust);
}

/// The Rust owner's manifest, unit, and candidate ceilings each name Rust.
fn the_rust_owner_keeps_its_own_refusals(rust: &Repository) {
    let required = [rust_manifest("Cargo.toml")];

    let manifest = built(
        rust,
        &required,
        adjusted(|limits| limits.rust.max_manifests = 1),
    )
    .expect_err("the Rust project manifest ceiling is fatal");
    assert_capacity(
        &manifest,
        CapacityOwner::Rust,
        CapacityCollection::Manifest,
        Observed::Exactly(2),
        1,
    );

    let units = built(
        rust,
        &required,
        adjusted(|limits| limits.rust.max_units = 0),
    )
    .expect_err("the Rust snapshot unit ceiling is fatal");
    assert_capacity(
        &units,
        CapacityOwner::Rust,
        CapacityCollection::Unit,
        Observed::Exactly(1),
        0,
    );

    let candidates = built(
        rust,
        &required,
        adjusted(|limits| limits.rust.max_candidates_per_reference = 0),
    )
    .expect_err("the Rust resolver candidate ceiling is fatal");
    assert_capacity(
        &candidates,
        CapacityOwner::Rust,
        CapacityCollection::Candidate,
        Observed::Exactly(1),
        0,
    );
}

/// The Go owner's manifest and fact ceilings each name Go.
fn the_go_owner_keeps_its_own_refusals(go: &Repository) {
    let required = [go_module("go.mod")];

    let manifest = built(
        go,
        &required,
        adjusted(|limits| limits.go.max_module_manifests = 0),
    )
    .expect_err("the Go project manifest ceiling is fatal");
    assert_capacity(
        &manifest,
        CapacityOwner::Go,
        CapacityCollection::Manifest,
        Observed::Exactly(1),
        0,
    );

    let facts = built(
        go,
        &required,
        adjusted(|limits| limits.go.max_facts_per_source = 0),
    )
    .expect_err("the Go fact extractor ceiling is fatal");
    assert_capacity(
        &facts,
        CapacityOwner::Go,
        CapacityCollection::Fact,
        Observed::Exactly(1),
        0,
    );
}

/// The repository's graph allowance and the builder's own are two owners.
///
/// The middle row is the one that decides between them: with both ceilings at
/// zero the refusal could honestly carry either owner, and the repository is
/// the one that must win, because its allowance is clamped into the
/// construction the builder then performs.
fn the_repository_and_graph_builder_are_told_apart(rust: &Repository) {
    let required = [rust_manifest("Cargo.toml")];

    let repository = built(
        rust,
        &required,
        adjusted(|limits| limits.repository.max_graph_nodes = 0),
    )
    .expect_err("the repository graph-node allowance is fatal");
    assert_capacity(
        &repository,
        CapacityOwner::Repository,
        CapacityCollection::GraphNode,
        Observed::Exactly(1),
        0,
    );

    let equal = built(
        rust,
        &required,
        adjusted(|limits| {
            limits.repository.max_graph_nodes = 0;
            limits.graph_build = pedant_graph::GraphLimits::new(0, u32::MAX, u32::MAX);
        }),
    )
    .expect_err("the repository owns equal graph ceilings");
    assert_capacity(
        &equal,
        CapacityOwner::Repository,
        CapacityCollection::GraphNode,
        Observed::Exactly(1),
        0,
    );

    let builder = built(
        rust,
        &required,
        adjusted(|limits| {
            limits.graph_build = pedant_graph::GraphLimits::new(0, u32::MAX, u32::MAX);
        }),
    )
    .expect_err("the graph node ceiling is fatal");
    assert_capacity(
        &builder,
        CapacityOwner::GraphBuild,
        CapacityCollection::GraphNode,
        Observed::Exactly(1),
        0,
    );
}
