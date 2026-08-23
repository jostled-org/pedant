//! Every Go production owner is held to this repository's structural rules,
//! read from the committed source.
//!
//! The rules are enforced elsewhere too — `pedant check` runs over the eight
//! first-party trees and clippy runs over each feature configuration — but
//! neither answers the two claims this case is registered for. `pedant check`
//! reads one file at a time, so it cannot see the same body written into two
//! modules; and no lint states which typed error each seam refuses through, so
//! a variant deleted as unreachable or a seam that borrowed another's enum both
//! land green.
//!
//! Reads tracked text and runs nothing. Compiles under `go-resolution` alone.

use std::collections::BTreeMap;

use crate::resolution::go::policy_errors::error_enums;
use crate::resolution::go::policy_model::{
    DEFENSIVE_ONLY_VARIANTS, ERROR_OWNERS, ErrorOwner, FORBIDDEN_MACROS, FORBIDDEN_METHODS,
    MAX_BODY_STATEMENTS, MAX_NESTING, MIN_DUPLICATE_STATEMENTS,
};
use crate::resolution::go::policy_routes::forbidden_routes;
use crate::resolution::go::policy_scan::{Body, bodies};
use crate::resolution::go::surface::{production_sources, tracked_text};

/// 13.T5 (Exit Criteria 14 to 16): the Go production surface states unique,
/// one-job, shallow bodies; refuses through typed seam-specific errors; and
/// takes no panic, output, inline-test, or trait-object route.
#[test]
fn go_production_structure_and_error_ownership_are_exact() {
    let parsed = parsed_surface();
    assert!(
        parsed.len() > ERROR_OWNERS.len(),
        "the surface must be wider than its error owners"
    );
    assert_no_forbidden_route_is_taken(&parsed);
    assert_every_body_is_one_shallow_job(&parsed);
    assert_no_body_is_written_twice(&parsed);
    assert_every_seam_refuses_through_its_own_typed_error(&parsed);
}

/// Every Go production source, parsed once and labelled by its tracked path.
///
/// One parse, four subjects. Parsing per claim would read the same forty-odd
/// files four times and, worse, would let one claim range over a set another
/// never saw.
fn parsed_surface() -> Box<[(Box<str>, syn::File)]> {
    production_sources()
        .iter()
        .map(|path| {
            let text = tracked_text(path);
            let parsed = syn::parse_file(&text)
                .unwrap_or_else(|error| panic!("{path} should parse as Rust: {error}"));
            (path.as_str().into(), parsed)
        })
        .collect()
}

/// No Go owner panics, prints, asserts, declares an inline test, or names a
/// trait object.
fn assert_no_forbidden_route_is_taken(surface: &[(Box<str>, syn::File)]) {
    let offenders: Vec<String> = surface
        .iter()
        .flat_map(|(path, file)| {
            forbidden_routes(file, FORBIDDEN_MACROS, FORBIDDEN_METHODS)
                .into_vec()
                .into_iter()
                .map(move |route| format!("{path} takes {route}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a Go production owner refuses through its typed error and returns its output: {offenders:?}"
    );
}

/// Every body states one job's worth of statements at one readable depth.
fn assert_every_body_is_one_shallow_job(surface: &[(Box<str>, syn::File)]) {
    let mut widest = 0;
    let mut deepest = 0;
    let mut offenders: Vec<String> = Vec::new();
    for (path, body) in surface_bodies(surface).iter() {
        widest = widest.max(body.statements);
        deepest = deepest.max(body.nesting);
        if body.statements > MAX_BODY_STATEMENTS {
            offenders.push(format!(
                "{path}::{} states {} statements",
                body.name, body.statements
            ));
        }
        if body.nesting > MAX_NESTING {
            offenders.push(format!(
                "{path}::{} nests {} layers deep",
                body.name, body.nesting
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "every Go body states at most {MAX_BODY_STATEMENTS} statements and nests at most \
         {MAX_NESTING} layers: {offenders:?}"
    );
    assert!(
        widest * 2 > MAX_BODY_STATEMENTS && deepest == MAX_NESTING,
        "the widest body states {widest} statements and the deepest nests {deepest}, \
         so the ceilings are not measuring the surface they were set for"
    );
}

/// No two Go owners state the same body.
///
/// Name-independent: a copied body renamed on arrival is still one
/// implementation in two places, and it is the copy a later fix reaches only
/// one of.
fn assert_no_body_is_written_twice(surface: &[(Box<str>, syn::File)]) {
    let mut sites: BTreeMap<Box<str>, Vec<String>> = BTreeMap::new();
    let wide = surface_bodies(surface)
        .into_vec()
        .into_iter()
        .filter(|(_, body)| body.statements >= MIN_DUPLICATE_STATEMENTS);
    // The body is moved out rather than copied: its shape is the map key and its
    // name is part of the site, so nothing here needs a second owner.
    for (path, body) in wide {
        sites
            .entry(body.shape)
            .or_default()
            .push(format!("{path}::{}", body.name));
    }
    let copied: Vec<&Vec<String>> = sites.values().filter(|held| held.len() > 1).collect();
    assert!(
        copied.is_empty(),
        "one implementation belongs in one place: {copied:?}"
    );
    assert!(
        !sites.is_empty(),
        "no body reached the duplicate scan, so it constrains nothing"
    );
}

/// Every body of the surface, paired with the owner that declares it.
fn surface_bodies(surface: &[(Box<str>, syn::File)]) -> Box<[(Box<str>, Body)]> {
    surface
        .iter()
        .flat_map(|(path, file)| {
            bodies(file)
                .into_vec()
                .into_iter()
                .map(move |body| (path.clone(), body))
        })
        .collect()
}

/// Each seam publishes exactly its modelled error enum, and no Go owner
/// publishes one the model does not name.
fn assert_every_seam_refuses_through_its_own_typed_error(surface: &[(Box<str>, syn::File)]) {
    let mut published: Vec<String> = Vec::new();
    for (path, file) in surface {
        for declared in error_enums(file).iter() {
            published.push(format!("{path}:{}", declared.name));
            let owner = owner_of(&declared.name);
            assert_eq!(
                owner.source, &**path,
                "{} must be declared by its modelled owner",
                declared.name
            );
            let variants: Box<[&str]> = declared.variants.iter().map(|it| &**it).collect();
            assert_eq!(
                &*variants, owner.variants,
                "{} must state exactly its modelled variants",
                declared.name
            );
            assert!(
                declared.untyped_variants.is_empty(),
                "{} states untyped variants: {:?}",
                declared.name,
                declared.untyped_variants
            );
            assert!(
                declared.derives_thiserror
                    || tracked_text(path)
                        .contains(&format!("impl std::error::Error for {}", declared.name)),
                "{} must implement std::error::Error",
                declared.name
            );
        }
    }
    let mut modelled: Vec<String> = ERROR_OWNERS
        .iter()
        .map(|owner| format!("{}:{}", owner.source, owner.name))
        .collect();
    published.sort();
    modelled.sort();
    assert_eq!(
        published.into_boxed_slice(),
        modelled.into_boxed_slice(),
        "the Go surface publishes exactly the modelled error enums"
    );
    assert_defensive_variants_are_admitted();
}

/// The modelled owner of one declared error enum.
fn owner_of(name: &str) -> &'static ErrorOwner {
    ERROR_OWNERS
        .iter()
        .find(|owner| owner.name == name)
        .unwrap_or_else(|| panic!("{name} is an unmodelled Go error enum"))
}

/// Every variant admitted as defensive-only is a variant its enum still states.
///
/// The admission is what keeps an unreachable refusal from being deleted as
/// dead. It only means that while the variant is declared, so a stale entry
/// naming a variant that was removed has to fail rather than sit here unread.
fn assert_defensive_variants_are_admitted() {
    for (enum_name, variant) in DEFENSIVE_ONLY_VARIANTS {
        let owner = owner_of(enum_name);
        assert!(
            owner.variants.contains(variant),
            "{enum_name}::{variant} is admitted as defensive-only but is not declared"
        );
    }
}
