//! What a Go snapshot actually opens, parses, and walks.
//!
//! Counting stored sources cannot tell a file read once from a file read twice
//! and stored under one key, so the production loader's own events are read
//! instead. Every admitted source appears exactly once in each of the three
//! streams, including the file two package contexts instantiate.

use pedant_core::resolution::ResolutionProbe;
use pedant_core::resolution::go::{GoProject, GoResolutionLimits};

use crate::resolution::fixture::{build_repository, repository_root};
use crate::resolution::go::snapshot_fixtures::{PACKAGE_CONTEXTS, REPLACED_MODULE};
use crate::resolution::go::snapshot_views::source_paths;
use crate::resolution::go::views::borrowed;

/// Every source a [`PACKAGE_CONTEXTS`] snapshot opens, in read order.
const CONTEXT_READS: &[&str] = &["api_test.go", "app.go", "app_test.go", "util/util.go"];

/// Every source a [`REPLACED_MODULE`] snapshot opens, in read order. The main
/// module's own tree comes first, then the module its replacement admitted.
const REPLACED_READS: &[&str] = &["root.go", "local/lib/lib.go"];

/// 4.T1 (Invariants 2, 6): every admitted Go source is read once, parsed once,
/// and walked for facts once, whatever number of package contexts hold it.
#[test]
fn go_snapshot_stores_each_source_and_fact_inventory_once() {
    assert_reads_parses_and_walks(PACKAGE_CONTEXTS, CONTEXT_READS, CONTEXT_READS);
    assert_reads_parses_and_walks(REPLACED_MODULE, REPLACED_READS, REPLACED_READS);
}

/// Snapshot one fixture beneath an installed probe and compare all three
/// streams, then release the tree the snapshot no longer needs.
fn assert_reads_parses_and_walks(
    files: &[crate::resolution::fixture::FixtureFile],
    reads: &[&str],
    stored: &[&str],
) {
    let tree = build_repository(files, false);
    let probe = ResolutionProbe::install();
    let project = GoProject::load(&repository_root(&tree), GoResolutionLimits::default())
        .expect("the fixture should load");
    let snapshot = project
        .snapshot_resolution()
        .expect("the fixture should snapshot");
    drop(project);
    drop(tree);

    assert_eq!(
        &*borrowed(&probe.source_reads()),
        reads,
        "every admitted source is opened exactly once"
    );
    assert_eq!(
        &*borrowed(&probe.parses()),
        reads,
        "every admitted source is parsed exactly once"
    );
    assert_eq!(
        &*borrowed(&probe.site_visits()),
        reads,
        "every admitted source is walked for facts exactly once"
    );

    let mut expected: Vec<&str> = stored.to_vec();
    expected.sort_unstable();
    assert_eq!(
        &*borrowed(&source_paths(&snapshot)),
        &*expected,
        "the store holds exactly the sources that were read"
    );
    drop(probe);
}
