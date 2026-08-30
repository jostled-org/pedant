//! `pedant-snippet`'s product dependency and feature boundary.
//!
//! The code-intelligence product is one navigation application built from the
//! syntax substrate, the resolution substrate, and the graph projector. What it
//! must never become is a second copy of the linter: one `default-features`
//! slip on the `pedant-core` edge puts the judgment surface and the gate engine
//! — one feature further, the whole rust-analyzer tier — inside a binary whose
//! job is to answer questions about source text.
//!
//! Every claim below reads a tracked manifest and runs nothing, so it holds in
//! the profile a publication is cut from.

use std::collections::BTreeSet;

use crate::resolution::code_intelligence::dependency_model::{
    ADMITTED_DEPENDENCIES, DeclaredEdge, FIRST_PARTY_EDGES, FORBIDDEN_DEPENDENCY_FEATURES,
    FORBIDDEN_PACKAGES, FirstPartyEdge, SNIPPET_MANIFEST, TRANSPORT_DEPENDENCIES,
};
use crate::resolution::code_intelligence::feature_model::{
    FEATURE_ROWS, FORBIDDEN_FEATURE_FRAGMENTS, FeatureRow, GRAPH_FEATURES, LANGUAGE_FEATURES,
};
use crate::resolution::manifest_reader::{
    default_features, dependency_edge, dependency_features, dependency_names, feature_selection,
    feature_table, manifest_table, string_array,
};

/// 4.T1 (Invariants 16, 21): the code-intelligence dependency edges are
/// versioned, minimal, and parse-only, and the feature table is the closed set
/// a library consumer selects a smaller profile from.
#[test]
fn code_intelligence_dependency_edges_are_minimal_versioned_and_parse_only() {
    let manifest = manifest_table(SNIPPET_MANIFEST);
    let declared = declared_dependencies(manifest);
    assert_first_party_edges_are_versioned_and_narrow(manifest, &declared);
    assert_the_feature_table_is_the_closed_model(manifest);
    assert_the_binary_default_selects_every_language_and_graph(manifest);
    assert_the_third_party_closure_is_classified(manifest, &declared);
    assert_no_forbidden_package_or_feature_is_declared(manifest, &declared);
}

/// The names one manifest declares as dependencies, as a set.
///
/// Read once and lent to every claim that needs it. The source-capability owner
/// reads the same manifest for the same reason, so this is the reader both of
/// them reach `[dependencies]` through.
pub(crate) fn declared_dependencies(manifest: &toml::Table) -> BTreeSet<&str> {
    dependency_names(manifest, SNIPPET_MANIFEST)
        .iter()
        .copied()
        .collect()
}

/// A written-down row set, in the shape the manifest readings compare against.
fn modelled(rows: impl IntoIterator<Item = &'static str>) -> BTreeSet<&'static str> {
    rows.into_iter().collect()
}

/// One declared edge states the crate and the exact selection the model says.
///
/// Both kinds of edge are read here. A first-party edge and an audited
/// third-party edge answer the same two questions, and two readers would be two
/// places for "minimum selection" to come to mean different things.
fn assert_declared_edge<'manifest>(
    manifest: &'manifest toml::Table,
    edge: &DeclaredEdge,
) -> &'manifest toml::Table {
    let declared = dependency_edge(manifest, SNIPPET_MANIFEST, edge.package);
    assert_eq!(
        declared
            .get("default-features")
            .and_then(toml::Value::as_bool),
        edge.default_features,
        "{}'s edge must state the modelled default-feature answer",
        edge.package
    );
    assert_eq!(
        &*string_array(declared.get("features")),
        edge.features,
        "{}'s edge must select exactly the modelled feature list",
        edge.package
    );
    declared
}

/// Each first-party edge carries a published version beside its path, is
/// optional exactly where a feature selects it, and selects no feature of its
/// own.
fn assert_first_party_edges_are_versioned_and_narrow(
    manifest: &toml::Table,
    declared: &BTreeSet<&str>,
) {
    for edge in FIRST_PARTY_EDGES {
        assert_first_party_edge(manifest, edge);
    }
    let first_party: BTreeSet<&str> = declared
        .iter()
        .copied()
        .filter(|name| name.starts_with("pedant-"))
        .collect();
    assert_eq!(
        first_party,
        modelled(FIRST_PARTY_EDGES.iter().map(|edge| edge.edge.package)),
        "{SNIPPET_MANIFEST} must declare exactly the modelled first-party edges"
    );
}

fn assert_first_party_edge(manifest: &toml::Table, edge: &FirstPartyEdge) {
    let declared = assert_declared_edge(manifest, &edge.edge);
    let package = edge.edge.package;
    assert_eq!(
        declared.get("version").and_then(toml::Value::as_str),
        Some(edge.version),
        "{package}'s edge must carry the published version it releases against"
    );
    assert_eq!(
        declared.get("path").and_then(toml::Value::as_str),
        Some(edge.path),
        "{package}'s edge must resolve through the workspace path while unpublished"
    );
    assert_eq!(
        declared.get("optional").and_then(toml::Value::as_bool),
        edge.optional.then_some(true),
        "{package}'s edge must be optional exactly when a feature selects it"
    );
}

/// The `[features]` table holds exactly the modelled rows, each selecting
/// exactly what the model says, and none of them reaching the judgment surface,
/// the semantic tier, rust-analyzer, the proof-only probe, or ECMAScript
/// resolution.
///
/// The whole table is compared rather than each modelled row looked up: a tenth
/// feature nobody wrote down is precisely the widening this rejects, and a
/// membership check would agree with it.
///
/// Both questions are asked of one reading of each row, in the order the file's
/// own rule at [`widens_the_closure`] states: two passes over the same rows are
/// two places for one of them to stop being taken, and each pass was re-deriving
/// and re-allocating the same selection.
///
/// A forwarding entry can reach the judgment surface from either side of the
/// manifest, and only one of them is the `[features]` table. The other side —
/// what each declared edge selects — is walked once by
/// [`assert_no_forbidden_package_or_feature_is_declared`], which tests the same
/// fragments there beside the write, spawn, and socket features.
fn assert_the_feature_table_is_the_closed_model(manifest: &toml::Table) {
    let declared: BTreeSet<&str> = feature_table(manifest, SNIPPET_MANIFEST)
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        declared,
        modelled(FEATURE_ROWS.iter().map(|row| row.feature)),
        "{SNIPPET_MANIFEST} must declare exactly the modelled features"
    );
    let mut offenders: Vec<Box<str>> = Vec::new();
    for row in FEATURE_ROWS {
        offenders.extend(assert_feature_row(manifest, row));
    }
    assert!(
        offenders.is_empty(),
        "the navigation closure must select no judgment, semantic, toolchain, or ECMAScript-resolution feature: {offenders:?}"
    );
}

/// One row selects exactly its modelled set, and every forbidden surface that
/// set reaches.
fn assert_feature_row(manifest: &toml::Table, row: &FeatureRow) -> Box<[Box<str>]> {
    let selected = feature_selection(manifest, SNIPPET_MANIFEST, row.feature);
    assert_eq!(
        &*selected, row.selects,
        "the `{}` feature must select exactly the modelled set",
        row.feature
    );
    selected
        .iter()
        .filter(|entry| names_forbidden_surface(entry))
        .map(|entry| format!("feature {} selects {entry}", row.feature).into_boxed_str())
        .collect()
}

/// The installed binary answers for every supported language and both graph
/// producers, and each language row forwards to exactly one grammar.
fn assert_the_binary_default_selects_every_language_and_graph(manifest: &toml::Table) {
    let stated = default_features(manifest);
    let default: BTreeSet<&str> = stated.iter().copied().collect();
    assert_eq!(
        default,
        modelled(LANGUAGE_FEATURES.iter().chain(GRAPH_FEATURES).copied()),
        "the installed binary must select every language and both graph producers, and nothing else"
    );

    for feature in LANGUAGE_FEATURES {
        let selected = feature_selection(manifest, SNIPPET_MANIFEST, feature);
        let [grammar] = &*selected else {
            panic!("`{feature}` must forward to exactly one grammar, and it selects {selected:?}");
        };
        assert!(
            grammar.starts_with("pedant-syntax/"),
            "`{feature}` must forward to a `pedant-syntax` grammar, and it selects {grammar}"
        );
    }
}

fn names_forbidden_surface(entry: &str) -> bool {
    FORBIDDEN_FEATURE_FRAGMENTS
        .iter()
        .any(|fragment| entry.contains(fragment))
}

/// One feature an edge selects that would widen the navigation closure, whether
/// by reaching a forbidden surface or by naming a write, spawn, or socket.
///
/// Both questions are asked of the same entry in the same pass. Two passes over
/// the same edges are two places for one of them to stop being taken.
fn widens_the_closure(entry: &str) -> bool {
    names_forbidden_surface(entry) || FORBIDDEN_DEPENDENCY_FEATURES.contains(&entry)
}

/// Every third-party edge is either an audited code-intelligence dependency or
/// a written-down transport dependency, and each admitted one states the exact
/// minimum selection it was audited under.
///
/// The closure is compared as a set rather than searched row by row. A crate
/// added without a classification is the audit this step exists to run, and a
/// membership check would let it in silently.
fn assert_the_third_party_closure_is_classified(manifest: &toml::Table, declared: &BTreeSet<&str>) {
    let third_party: BTreeSet<&str> = declared
        .iter()
        .copied()
        .filter(|name| !name.starts_with("pedant-"))
        .collect();
    let classified = modelled(
        ADMITTED_DEPENDENCIES
            .iter()
            .map(|admitted| admitted.edge.package)
            .chain(TRANSPORT_DEPENDENCIES.iter().copied()),
    );
    assert_eq!(
        third_party, classified,
        "every third-party edge must be classified as an audited code-intelligence dependency or a transport dependency"
    );

    for admitted in ADMITTED_DEPENDENCIES {
        let stated = assert_declared_edge(manifest, &admitted.edge);
        assert!(
            stated
                .get("version")
                .and_then(toml::Value::as_str)
                .is_some(),
            "{}'s edge must carry a version requirement",
            admitted.edge.package
        );
    }
}

/// No declared edge names a forbidden crate, and no declared feature list names
/// a forbidden surface or a write, spawn, or socket feature.
///
/// This is the whole `[dependencies]` claim, and the source-capability owner
/// reads the manifest through it rather than deriving the table again: a
/// capability that arrives as an edge is invisible to a source scan, so both
/// proofs need this answer and neither may hold its own copy of it.
pub(crate) fn assert_no_forbidden_package_or_feature_is_declared(
    manifest: &toml::Table,
    declared: &BTreeSet<&str>,
) {
    let reached: Box<[&str]> = FORBIDDEN_PACKAGES
        .iter()
        .copied()
        .filter(|package| declared.contains(package))
        .collect();
    assert!(
        reached.is_empty(),
        "the navigation closure must declare no toolchain, network, or judgment crate: {reached:?}"
    );

    let mut widened: Vec<Box<str>> = Vec::new();
    for package in declared.iter().copied() {
        widened.extend(
            dependency_features(manifest, SNIPPET_MANIFEST, package)
                .iter()
                .filter(|feature| widens_the_closure(feature))
                .map(|feature| format!("edge {package} selects {feature}").into_boxed_str()),
        );
    }
    assert!(
        widened.is_empty(),
        "no edge may select a judgment, semantic, toolchain, ECMAScript-resolution, write, spawn, \
         or socket feature: {widened:?}"
    );
}
