//! The published package's own boundary: what its manifest states, which
//! modules the tree holds, which predicates the root registers, and that no
//! function is written twice.
//!
//! [`super::analysis_ownership`] owns what the analysis family publishes. This
//! owns what the crate around it still is. Every input is tracked and read at
//! compile time except the two directory listings, which exist to reject a
//! source or a support module that appeared without an entry: nothing here
//! reads a plan, a lifecycle manifest, or a script.

use std::collections::{BTreeMap, BTreeSet};

use super::analysis_ownership::ANALYSIS_SOURCES;
use super::scan::{
    self, MANIFEST, SOURCES, TEST_ROOT, TEST_SUPPORT_SOURCES, discovered_sources,
    discovered_test_sources, parsed,
};
use super::surface::declared_items;

/// Every predicate the analysis family registered, each a bare wrapper at the
/// one root.
const ANALYSIS_PREDICATES: &[&str] = &[
    "graph_analysis_limit_checks_dominate_allocations",
    "graph_analysis_limits_refuse_before_work",
    "graph_analysis_public_boundary_is_exact",
    "graph_analysis_results_are_deterministic",
    "graph_analysis_selection_is_explicit_and_shared",
    "graph_analysis_source_boundary_is_exact",
    "graph_betweenness_refuses_work_before_source_state",
    "graph_components_and_condensation_are_exact",
    "graph_declared_partition_follows_nearest_container",
    "graph_degree_and_betweenness_match_directed_oracles",
    "graph_derived_consumers_reuse_analysis_results",
    "graph_divergence_and_layout_are_deterministic",
    "graph_divergence_matches_declared_partition_arithmetic",
    "graph_divergence_selection_reuses_analysis_indexes",
    "graph_layout_assist_is_complete_and_coordinate_free",
    "graph_metric_selection_reuses_analysis_indexes",
    "graph_metrics_and_components_consume_shared_indexes",
    "graph_neighbors_are_bounded_directed_and_ordered",
    "graph_path_is_shortest_directed_and_deterministic",
    "graph_subgraph_is_exact_induced_selection",
    "graph_traversal_and_components_are_iterative",
    "graph_traversal_consumes_shared_analysis_indexes",
];

/// The exact dependency edges this crate's manifest states.
const MANIFEST_DEPENDENCIES: &[&str] = &["pedant-core", "pedant-types", "serde", "thiserror"];

/// The exact dependency edges its harness adds.
const MANIFEST_DEV_DEPENDENCIES: &[&str] =
    &["pedant-core", "serde_json", "quote", "syn", "tempfile"];

/// The published package still states the same dependencies, features, modules,
/// and registered predicates it did before this family existed.
///
/// Every input is tracked and read at compile time except the two directory
/// listings, which exist to reject a source or a support module that appeared
/// without an entry. Nothing here reads a plan, a lifecycle manifest, or a
/// script.
pub fn assert_analysis_source_boundary_is_exact() {
    assert_manifest_states_no_delta();
    assert_analysis_modules_are_discovered();
    assert_every_predicate_is_registered_once();
    assert_no_test_lives_outside_the_root();
    assert_analysis_functions_are_declared_once();
}

/// The manifest adds no dependency and no feature, and keeps `pedant-core`
/// default features disabled on both edges.
fn assert_manifest_states_no_delta() {
    assert_eq!(
        manifest_table("dependencies"),
        MANIFEST_DEPENDENCIES,
        "the library closure states exactly its modelled dependencies"
    );
    assert_eq!(
        manifest_table("dev-dependencies"),
        MANIFEST_DEV_DEPENDENCIES,
        "the harness closure states exactly its modelled dependencies"
    );
    assert!(
        !MANIFEST.contains("[features]"),
        "this crate states no feature of its own"
    );
    assert_eq!(
        MANIFEST.matches("pedant-core = {").count(),
        MANIFEST.matches("default-features = false").count(),
        "every pedant-core edge disables its default features"
    );
    assert_eq!(
        MANIFEST.matches("\"resolution-test-support\"").count(),
        1,
        "the dev edge selects the one proof feature and nothing else"
    );
}

/// Every key one manifest table declares, in the order it declares them.
fn manifest_table(name: &str) -> Vec<String> {
    let header = format!("[{name}]");
    MANIFEST
        .lines()
        .skip_while(|line| line.trim() != header)
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .filter_map(declared_key)
        .collect()
}

/// The key one manifest line declares, if it declares one.
fn declared_key(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    match trimmed.starts_with('#') {
        true => None,
        false => trimmed
            .split_once('=')
            .map(|(key, _)| key.trim().to_owned()),
    }
}

/// The analysis module inventory is exactly what the tree holds beneath
/// `src/analysis`.
fn assert_analysis_modules_are_discovered() {
    let discovered: BTreeSet<String> = discovered_sources()
        .into_iter()
        .filter(|path| path.starts_with("src/analysis/"))
        .collect();
    assert_eq!(
        discovered,
        ANALYSIS_SOURCES
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<BTreeSet<String>>(),
        "every analysis module is modelled and every modelled module exists"
    );
}

/// Every modelled predicate is a bare wrapper, registered once at the root.
fn assert_every_predicate_is_registered_once() {
    for predicate in ANALYSIS_PREDICATES {
        assert_eq!(
            TEST_ROOT
                .matches(&format!("#[test]\nfn {predicate}()"))
                .count(),
            1,
            "{predicate} is registered exactly once, with its bare identity"
        );
    }
}

/// No support module registers a test, and none escapes the model.
fn assert_no_test_lives_outside_the_root() {
    let modelled: BTreeSet<String> = TEST_SUPPORT_SOURCES
        .iter()
        .map(|module| module.path.to_owned())
        .collect();
    let discovered: BTreeSet<String> = discovered_test_sources()
        .into_iter()
        .filter(|path| path != "tests/graph.rs")
        .collect();
    assert_eq!(
        discovered, modelled,
        "every support module is scanned and every scanned module exists"
    );
    for module in TEST_SUPPORT_SOURCES {
        assert!(
            !declares_a_test(module.text),
            "{}: every registered test lives at the root",
            module.path
        );
    }
    for entry in SOURCES {
        assert!(
            !declares_a_test(entry.text),
            "{}: production source states no inline test",
            entry.path
        );
    }
}

/// Whether one source declares a test or a test-only module.
///
/// Read as whole lines: a case that states the attribute inside a string, to
/// look for one, is not declaring one.
fn declares_a_test(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .any(|line| line == "#[test]" || line.starts_with("#[cfg(test)"))
}

/// No two analysis modules declare the same free function.
///
/// The sites a definition is keyed against are reported by path and by name, so
/// a failure states both copies rather than the body they share.
fn assert_analysis_functions_are_declared_once() {
    let mut declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in ANALYSIS_SOURCES {
        for (name, definition) in free_functions(path) {
            declared
                .entry(definition)
                .or_default()
                .push(format!("{path}::{name}"));
        }
    }
    let repeated: Vec<String> = declared
        .values()
        .filter(|sites| sites.len() > 1)
        .map(|sites| sites.join(" == "))
        .collect();
    assert!(
        repeated.is_empty(),
        "one function is declared once; these sites declare the same one: {repeated:?}"
    );
    assert!(
        declared.len() > 40,
        "the analysis family declares the functions this case reads: {}",
        declared.len()
    );
}

/// Every free function one source declares, as its name beside its exact
/// normalized definition.
///
/// The walk descends through inline modules, so a function moved into a `mod`
/// is still declared by the file that holds it and cannot escape this case by
/// escaping the file's top level.
fn free_functions(path: &str) -> Vec<(String, String)> {
    let file = parsed(path);
    declared_items(&file.items)
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) => Some((
                function.sig.ident.to_string(),
                normalized_definition(&function.sig, &function.block),
            )),
            _ => None,
        })
        .collect()
}

/// One function's parameters, answer, and body, with every space dropped.
///
/// The name is left out on purpose: a function copied under a second spelling
/// takes the same arguments and runs the same statements, so two definitions
/// that differ only in what they are called are one function written twice.
fn normalized_definition(signature: &syn::Signature, body: &syn::Block) -> String {
    let stated = format!(
        "{}{}{}",
        scan::token_text(&signature.inputs),
        scan::token_text(&signature.output),
        scan::token_text(body)
    );
    stated.split_whitespace().collect()
}
