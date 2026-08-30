//! 10.T2 (Invariant 16): what the completed product tree does, read from the
//! completed source.
//!
//! The tracked profile in `check_code_intelligence_capabilities.sh` is the
//! evidence producer the Step 10 route runs live: it mirrors the tree as
//! sentinels, proves the detectors still report, and then holds the real profile
//! to reads, hashing, and one exit status. What it cannot say is *which* module
//! holds each of those, because a capability profile is a list of findings and
//! not a map of owners — a reader moved into the query layer would leave the
//! profile byte-identical.
//!
//! So this owner reads the same tree the script rules on, and asks the question
//! the profile cannot: every capability sits in the one module modelled to hold
//! it, no module states a forbidden route, no navigation module parses anything,
//! and the manifest declares no edge that would carry a capability past the
//! source scan. The script stays registered and exact, because a claim about a
//! tracked owner that nothing runs is a claim about a file.

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::capability_model::{
    CAPABILITY_OWNERS, DIGEST_EVIDENCE, DIGEST_OWNERS,
};
use crate::resolution::code_intelligence::dependency_boundary::{
    assert_no_forbidden_package_or_feature_is_declared, declared_dependencies,
};
use crate::resolution::code_intelligence::dependency_capabilities::assert_profile_owner_is_non_vacuous;
use crate::resolution::code_intelligence::dependency_model::{
    CAPABILITY_CHECK, CLOSURE_CHECK, SNIPPET_MANIFEST,
};
use crate::resolution::code_intelligence::forbidden_model::{
    FORBIDDEN_ROUTES, NO_PARSE_TREE, PARSE_EVIDENCE,
};
use crate::resolution::code_intelligence::product_model::PRODUCT_TREE;
use crate::resolution::code_intelligence::product_surface::{
    ProductModule, ProductSurface, compact, compact_tokens, states,
};
use crate::resolution::manifest_reader::manifest_table;
use crate::resolution::source_routes::{PRODUCT_ROUTES, forbidden_routes};

/// 10.T2 (Invariant 16): the completed product reads sources, walks the root,
/// hashes what it read, and states one exit status — each in its one named
/// owner — and does nothing else anywhere.
#[test]
fn code_intelligence_source_capabilities_are_exact() {
    let surface = ProductSurface::read();
    assert!(
        surface.modules().len() > CAPABILITY_OWNERS.len(),
        "the product must be wider than its capability owners"
    );
    let rendered = rendered_modules(surface.modules());
    assert_each_capability_sits_in_its_named_owner(&surface);
    assert_the_route_reading_finds_a_stated_spelling();
    assert_no_module_states_a_forbidden_route(surface.modules(), &rendered);
    assert_no_navigation_module_parses_anything(&rendered);
    assert_the_manifest_declares_no_forbidden_edge();
    assert_the_tracked_profile_is_registered();
}

/// Every module's whole token stream, rendered once for both route scans.
///
/// Both scans ask what a module *names*, and both ask it of the same hundred-odd
/// token streams. Rendering per scan would render the navigation tree twice.
fn rendered_modules(modules: &[ProductModule]) -> Box<[(&str, Box<str>)]> {
    modules
        .iter()
        .map(|module| (&*module.path, compact_tokens(module)))
        .collect()
}

/// Every modelled owner states its own evidence, and no other module does.
///
/// Both directions matter. Without the first, a scan that had stopped matching
/// would report every module clean; without the second, a reader could move
/// into the query layer with the profile unchanged.
fn assert_each_capability_sits_in_its_named_owner(surface: &ProductSurface) {
    assert!(
        !CAPABILITY_OWNERS.is_empty() && !DIGEST_OWNERS.is_empty(),
        "an ownership claim over no named owner constrains nothing"
    );
    let mut offenders: Vec<String> = Vec::new();
    for owner in CAPABILITY_OWNERS {
        let held = surface.module(owner.module);
        assert!(
            !owner.evidence.is_empty(),
            "{} is modelled as the one owner of {} and states no evidence, so the exclusivity \
             scan below reads nothing",
            owner.module,
            owner.capability
        );
        for evidence in owner.evidence {
            assert!(
                states(held, evidence),
                "{} must state {evidence}; it is the one owner of {}",
                owner.module,
                owner.capability
            );
        }
        offenders.extend(surface.others_stating(&[owner.module], "states", owner.evidence));
    }
    assert!(
        offenders.is_empty(),
        "every capability belongs to its one named owner: {offenders:?}"
    );

    for owner in DIGEST_OWNERS {
        assert!(
            states(surface.module(owner), DIGEST_EVIDENCE),
            "{owner} must state {DIGEST_EVIDENCE}; it mints a revision claim"
        );
    }
    let strays = surface.others_stating(DIGEST_OWNERS, "states", &[DIGEST_EVIDENCE]);
    assert!(
        strays.is_empty(),
        "hashing belongs to the two revision owners: {strays:?}"
    );
}

/// Every spelling the two forbids below search for is one the reading behind
/// them still finds.
///
/// A forbid is an `all` over a finding set that is empty in a healthy tree, so a
/// reading that had stopped matching would report every module clean. The
/// ownership claim above answers that for the capability spellings — an owner
/// that stopped stating its evidence fails there — and nothing answers it for
/// these two tables, because no module of the product may state a forbidden
/// route or a navigation parse. There is no subject in the tree to prove the
/// reading against, so the subject is built here.
///
/// Built from the two tables rather than written beside them. A hand-copied
/// sentinel is a second list, and the row it fell behind on is exactly the row
/// whose forbid nobody would notice had gone quiet.
fn assert_the_route_reading_finds_a_stated_spelling() {
    assert!(
        !FORBIDDEN_ROUTES.is_empty() && !PARSE_EVIDENCE.is_empty(),
        "a forbid over no spelling constrains nothing"
    );
    let searched: Box<[&str]> = FORBIDDEN_ROUTES
        .iter()
        .map(|route| route.evidence)
        .chain(PARSE_EVIDENCE.iter().copied())
        .collect();
    let stated: Box<[String]> = searched
        .iter()
        .map(|evidence| format!("    {evidence:?},"))
        .collect();
    let sentinel = ProductModule::of_text(
        "route_sentinel.rs",
        &format!(
            "pub const STATED: &[&str] = &[\n{}\n];\n",
            stated.join("\n")
        ),
    );
    let tokens = compact_tokens(&sentinel);
    let missed: Box<[&str]> = searched
        .iter()
        .copied()
        .filter(|evidence| !tokens.contains(&*compact(evidence)))
        .collect();
    assert!(
        missed.is_empty(),
        "the token reading no longer finds {missed:?}, so every forbid written over it passes \
         unread"
    );
}

/// No module of the product takes a route Invariant 16 forbids, and none of
/// them aborts, prints, or hides a seam behind a trait object.
///
/// The second half is the repository's own rule rather than the invariant's,
/// and it belongs beside the first: a product that may not spawn a process may
/// certainly not end one, and an operator reading a refusal needs the typed
/// error rather than a panic message.
///
/// The route spellings are read from the rendered token stream, not line by
/// line. `compact_tokens` exists because a call written across three lines and
/// the same call written on one are the same call, and a `contains` over the
/// source text can only find the second: `std::process::\n    Command::new`
/// satisfied every per-line reading this used to make.
fn assert_no_module_states_a_forbidden_route(
    modules: &[ProductModule],
    rendered: &[(&str, Box<str>)],
) {
    let mut offenders: Vec<String> = Vec::new();
    for module in modules {
        offenders.extend(
            forbidden_routes(&module.parsed, &PRODUCT_ROUTES)
                .into_vec()
                .into_iter()
                .map(|route| format!("{} takes {route}", module.path)),
        );
    }
    for (path, tokens) in rendered {
        offenders.extend(
            FORBIDDEN_ROUTES
                .iter()
                .filter(|route| tokens.contains(&*compact(route.evidence)))
                .map(|route| format!("{path} states {} ({})", route.evidence, route.family)),
        );
    }
    assert!(
        offenders.is_empty(),
        "production code intelligence writes nothing, spawns nothing, opens no socket, \
         invokes no toolchain, and implements no graph traversal: {offenders:?}"
    );
}

/// No navigation module parses a source or walks declarations.
///
/// Read from the token stream for the reason the route scan above is: a
/// `use pedant_syntax::tree_sitter;` and a later `tree_sitter::parse` reach the
/// same parser, and a per-line `contains` finds neither.
fn assert_no_navigation_module_parses_anything(rendered: &[(&str, Box<str>)]) {
    let navigation: Box<[&(&str, Box<str>)]> = rendered
        .iter()
        .filter(|(path, _)| path.starts_with(NO_PARSE_TREE))
        .collect();
    assert!(
        navigation.len() > 20,
        "the navigation scan found {} modules, so it is not reading the tree",
        navigation.len()
    );
    let offenders: Box<[String]> = navigation
        .iter()
        .flat_map(|(path, tokens)| {
            PARSE_EVIDENCE
                .iter()
                .filter(move |evidence| tokens.contains(&*compact(evidence)))
                .map(move |evidence| format!("{path} states {evidence}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a query answers from retained records; the index parsed once and published: {offenders:?}"
    );
}

/// The product manifest declares no edge that would carry a forbidden
/// capability past the source scan.
///
/// The boundary proof owns this question and the list behind it. A second
/// reader here would be a second answer to "what may this product link", and a
/// second answer drifts in the direction that admits something.
fn assert_the_manifest_declares_no_forbidden_edge() {
    let manifest = manifest_table(SNIPPET_MANIFEST);
    let declared = declared_dependencies(manifest);
    assert_no_forbidden_package_or_feature_is_declared(manifest, &declared);
}

/// The tracked profile that rules on this tree live is still registered and
/// still ranges over it.
///
/// This owner reads the source; the script runs the detector. Neither replaces
/// the other, and a script the route stopped naming would leave the live half
/// of Invariant 16 unproven.
fn assert_the_tracked_profile_is_registered() {
    let closure = read_text(CLOSURE_CHECK);
    assert!(
        closure.contains("pedant-snippet"),
        "{CLOSURE_CHECK} must range over the completed product tree"
    );
    assert_profile_owner_is_non_vacuous(
        CAPABILITY_CHECK,
        &[PRODUCT_TREE],
        "assert_only_read_digest_exit_status_and_elapsed_under",
    );
}
