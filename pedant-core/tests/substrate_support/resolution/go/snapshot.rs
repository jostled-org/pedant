//! One package directory's three compilation contexts, and the single store
//! entry a file shared by two of them keeps.
//!
//! Go compiles a directory's non-test files, its same-package `_test.go` files
//! together with those non-test files, and its `_test.go` files declaring the
//! external test package, as three separate contexts. The snapshot states all
//! three, and the file two of them instantiate is still read, parsed, and
//! stored once.

use crate::resolution::go::fixture::snapshot_default;
use crate::resolution::go::snapshot_fixtures::{PACKAGE_CONTEXTS, REPLACED_MODULE};
use crate::resolution::go::snapshot_views::{edges, modules, source_facts, source_paths, units};
use crate::resolution::go::views::borrowed;

/// Every package unit [`PACKAGE_CONTEXTS`] states.
const CONTEXT_UNITS: &[&str] = &[
    "example.com/app|production|example.com/app|app||app.go",
    "example.com/app|internal_test|example.com/app|app||app.go,app_test.go",
    "example.com/app|external_test|example.com/app|app_test||api_test.go",
    "example.com/app|production|example.com/app/util|util|util|util/util.go",
];

/// Every distinct source [`PACKAGE_CONTEXTS`] stores, in snapshot order.
const CONTEXT_SOURCES: &[&str] = &["api_test.go", "app.go", "app_test.go", "util/util.go"];

/// The fact inventory each stored source retains.
const CONTEXT_FACTS: &[&str] = &[
    "api_test.go|app_test|Function:drive|example.com/app",
    "app.go|app|Function:Run|",
    "app_test.go|app|Function:probe|",
    "util/util.go|util|Function:Name|",
];

/// Every module, unit, edge, and source [`REPLACED_MODULE`] states.
const REPLACED_MODULES: &[&str] = &[
    "example.com/root||go.mod|0",
    "example.com/lib|local/lib|local/lib/go.mod|1",
];
const REPLACED_UNITS: &[&str] = &[
    "example.com/root|production|example.com/root|root||root.go",
    "example.com/lib|production|example.com/lib|lib|local/lib|local/lib/lib.go",
];
const REPLACED_EDGES: &[&str] = &["example.com/root|example.com/lib|example.com/lib|v1.0.0"];

/// 4.T2 (Invariant 11): a file shared by two package contexts keeps one store
/// entry and one fact inventory while both contexts instantiate it.
#[test]
fn go_shared_source_has_one_store_entry_and_two_unit_instances() {
    let (tree, snapshot) = snapshot_default(PACKAGE_CONTEXTS);

    assert_eq!(
        &*borrowed(&units(&snapshot)),
        CONTEXT_UNITS,
        "one directory states its production, internal-test, and external-test contexts"
    );
    assert_eq!(
        &*borrowed(&source_paths(&snapshot)),
        CONTEXT_SOURCES,
        "the shared source has exactly one store entry"
    );
    assert_eq!(
        &*borrowed(&source_facts(&snapshot)),
        CONTEXT_FACTS,
        "every stored source retains its own fact inventory"
    );

    let shared = snapshot
        .source("app.go")
        .expect("the shared source is stored under its repository-relative path");
    assert_eq!(
        shared.facts().package_name(),
        Some("app"),
        "the stored inventory is the shared source's own"
    );

    let instances: Box<[&str]> = snapshot
        .units()
        .iter()
        .filter(|unit| unit.sources().iter().any(|path| &**path == "app.go"))
        .map(|unit| unit.context().token())
        .collect();
    assert_eq!(
        &*instances,
        ["production", "internal_test"],
        "two distinct units instantiate the one stored source"
    );

    let identities: Box<[_]> = snapshot.units().iter().map(|unit| unit.id()).collect();
    let mut distinct = identities.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        identities.len(),
        "every package context has its own unit identity"
    );
    for id in identities.iter() {
        assert!(
            snapshot.unit(*id).is_some(),
            "a snapshot answers for every identity it issued"
        );
    }

    drop(tree);
}

/// 4.T2 (Invariant 11): an admitted local replacement is a second snapshot
/// module whose packages and dependency edge are stated beside the main
/// module's.
#[test]
fn go_snapshot_states_admitted_modules_units_and_local_edges() {
    let (tree, snapshot) = snapshot_default(REPLACED_MODULE);

    assert_eq!(&*borrowed(&modules(&snapshot)), REPLACED_MODULES);
    assert_eq!(&*borrowed(&units(&snapshot)), REPLACED_UNITS);
    assert_eq!(&*borrowed(&edges(&snapshot)), REPLACED_EDGES);
    assert_eq!(
        snapshot
            .module(snapshot.root_module())
            .expect("the snapshot answers for its own root module")
            .path(),
        "example.com/root",
        "the main module is the snapshot's root module"
    );

    let root = snapshot.root().to_path_buf();
    drop(snapshot);
    drop(tree);
    assert!(
        !root.exists(),
        "the fixture is released with the temporary directory"
    );
}
