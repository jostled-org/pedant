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
use super::cache_source_boundary::CACHE_PREDICATES;
use super::go_model::GO_PREDICATES;
use super::inventory::{MANIFEST, SOURCES, TEST_ROOT, TEST_SUPPORT_SOURCES};
use super::projection_ownership::PROJECTION_PREDICATES;
use super::scan::{self, discovered_sources, discovered_test_sources, parsed};
use super::surface::declared_items;

/// Every predicate the analysis family registered, each a bare wrapper at the
/// one root.
pub const ANALYSIS_PREDICATES: &[&str] = &[
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

/// Every predicate this crate registered before the analysis and cache families
/// existed, each a bare wrapper at the one root.
///
/// Written down for the same reason the two family inventories are: the three
/// lists together are the whole registered surface, so a predicate that belongs
/// to no family still has to be named by one of them.
pub const VERSION_ONE_PREDICATES: &[&str] = &[
    "graph_defensive_error_paths_are_complete_and_wired",
    "graph_defensive_malformed_inputs_return_exact_errors",
    "graph_id_capacity_uses_one_checked_insertion_owner",
    "graph_identity_checks_dominate_projection_state_construction",
    "graph_ids_languages_and_limits_are_dense_checked_and_atomic",
    "graph_projection_uses_only_supplied_resolution_facts",
    "graph_public_identity_defaults_and_schema_are_exact",
    "graph_public_lifecycle_surface_is_closed",
    "graph_public_reading_surface_is_complete",
    "rust_graph_builds_and_serializes_after_fixture_teardown",
    "rust_graph_containment_is_a_unit_local_forest",
    "rust_graph_edges_retain_candidate_certainty_and_evidence",
    "rust_graph_json_v1_covers_every_graph_owned_variant",
    "rust_graph_json_v1_is_exact_compact_and_deterministic",
    "rust_graph_maps_every_rust_reference_kind_exactly",
    "rust_graph_maps_every_rust_symbol_kind_exactly_once",
    "rust_graph_preserves_cargo_dependency_evidence",
    "rust_graph_qualifies_unit_roots_and_shared_source_files",
    "rust_graph_rejects_identity_mismatch_before_capacity_checks",
    "rust_graph_retains_enclosed_top_level_and_candidate_free_references",
    "rust_graph_separates_logical_parentage_from_source_location",
    "rust_graph_tiers_change_only_resolution_evidence",
];

/// The exact dependency edges this crate's manifest states.
const MANIFEST_DEPENDENCIES: &[&str] = &["pedant-core", "pedant-types", "serde", "thiserror"];

/// The exact feature table this crate states, and no `default` entry beside
/// them: a Go graph is opted into, never inherited.
const MANIFEST_FEATURES: &[&str] = &["go"];

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
    assert_every_registered_wrapper_is_modelled();
    assert_no_test_lives_outside_the_root();
}

/// The manifest adds no dependency and no feature, and keeps `pedant-core`
/// default features disabled on both edges.
pub fn assert_manifest_states_no_delta() {
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
    assert_eq!(
        manifest_table("features"),
        MANIFEST_FEATURES,
        "this crate states exactly its modelled features, and none by default"
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

/// Every registered wrapper is modelled, and every modelled name is registered.
///
/// Compared as whole sets rather than searched one modelled name at a time: a
/// predicate added to the root with no entry in any family's inventory is
/// invisible to every case that reasons over what the crate proves, so a
/// sixty-sixth wrapper fails here rather than passing unnamed.
pub fn assert_every_registered_wrapper_is_modelled() {
    let listed: Vec<&str> = [
        CACHE_PREDICATES,
        ANALYSIS_PREDICATES,
        GO_PREDICATES,
        PROJECTION_PREDICATES,
        VERSION_ONE_PREDICATES,
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect();
    let modelled: BTreeSet<String> = listed.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        modelled.len(),
        listed.len(),
        "no predicate is modelled by two families"
    );
    assert_eq!(
        registered_wrappers(),
        modelled,
        "the root registers exactly the predicates the family inventories name"
    );
}

/// Every test identity the one root registers.
///
/// Read as the line following each attribute, so a wrapper that took an
/// argument or stated a second attribute is refused rather than collected under
/// a name the root does not register.
fn registered_wrappers() -> BTreeSet<String> {
    TEST_ROOT
        .lines()
        .zip(TEST_ROOT.lines().skip(1))
        .filter(|(attribute, _)| attribute.trim() == "#[test]")
        .map(|(_, declaration)| registered_name(declaration))
        .collect()
}

/// The bare identity one registered declaration states.
fn registered_name(line: &str) -> String {
    let declared = line.trim();
    let named = declared
        .strip_prefix("fn ")
        .unwrap_or_else(|| panic!("{declared} follows the attribute and must declare a test"));
    named
        .split_once("() {")
        .map(|(name, _)| name.to_owned())
        .unwrap_or_else(|| panic!("{declared} must be a bare wrapper taking no argument"))
}

/// No support module registers a test, and none escapes the model.
pub fn assert_no_test_lives_outside_the_root() {
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

/// No two of `sources` declare the same function.
///
/// The sites a definition is keyed against are reported by path and by name, so
/// a failure states both copies rather than the body they share. `floor` is how
/// many distinct definitions the set must state at all, so a scan that silently
/// stopped reading fails instead of passing over nothing.
pub fn assert_functions_are_declared_once(sources: &[&str], floor: usize, subject: &str) {
    let mut declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in sources {
        for (name, definition) in declared_definitions(path) {
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
        declared.len() > floor,
        "{subject} declares the functions this case reads: {}",
        declared.len()
    );
}

/// Every function one source declares, as its reported name beside its exact
/// normalized definition.
///
/// Free functions and the methods of every inherent `impl`, each method keyed by
/// the subject it was declared on. A scan that read only a file's `fn` items
/// could not see cache code at all: the eight cache modules and the adapter's
/// cache declare two free functions between them, and every store, ceiling, and
/// classification they own is a method. A store's retention copied verbatim into
/// a second store would pass such a scan.
///
/// The walk descends through inline modules, so a function moved into a `mod`
/// is still declared by the file that holds it and cannot escape this case by
/// escaping the file's top level.
fn declared_definitions(path: &str) -> Vec<(String, String)> {
    let file = parsed(path);
    let mut declared = Vec::new();
    for item in declared_items(&file.items) {
        match item {
            syn::Item::Fn(function) => declared.push((
                function.sig.ident.to_string(),
                normalized_definition(&function.sig, &function.block),
            )),
            syn::Item::Impl(block) if block.trait_.is_none() => {
                declared.extend(impl_definitions(
                    &scan::token_text(&block.self_ty),
                    &block.items,
                ));
            }
            _ => (),
        }
    }
    declared
}

/// Every method one inherent `impl` declares that states logic, keyed by the
/// subject the block names.
fn impl_definitions(subject: &str, members: &[syn::ImplItem]) -> Vec<(String, String)> {
    members
        .iter()
        .filter_map(|member| match member {
            syn::ImplItem::Fn(method) if states_logic(&method.block) => Some((
                format!("{subject}::{}", method.sig.ident),
                normalized_definition(&method.sig, &method.block),
            )),
            _ => None,
        })
        .collect()
}

/// Whether one method body states work rather than a reading of what its type
/// already holds.
///
/// A record's accessor and a one-call delegation are the shape a record has, not
/// a function written twice: two types that each answer `&self.nodes` under the
/// name `nodes` share a spelling and no logic. A body of two statements or more
/// states something a second copy of it would have to keep in step, which is
/// exactly what this claim is about.
fn states_logic(body: &syn::Block) -> bool {
    body.stmts.len() > 1
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
