//! 10.T5 (Invariant 14): what the completed product's bodies look like, read
//! from the completed source.
//!
//! The other half of [`super::production_structure`], which asks who owns each
//! name. This half asks what the named owners are written as: no body written
//! twice, no body nested past two layers, and every ceiling checked before the
//! first excess is retained. Three claims over one set of bodies, and that set
//! is derived once by [`product_bodies`] rather than once per claim.
//!
//! Driven from the sibling case rather than from a `#[test]` here. Every body
//! comes out of the one [`super::product_surface::ProductSurface`] reading that
//! case makes, and a second reading would parse a hundred modules again to hand
//! this half a set the other half never saw.

use crate::resolution::body_nesting::MAX_NESTING;
use crate::resolution::body_scan::{Body, bodies_by_owner, duplicate_sites};
use crate::resolution::code_intelligence::limit_model::{
    CAPACITY_CALL, DIAGNOSTIC_RECEIVERS, RETENTION_CALLS,
};
use crate::resolution::code_intelligence::operation_model::OPERATIONS;
use crate::resolution::code_intelligence::product_surface::{ProductModule, compact};

/// Every body of the product, paired with the module that declares it.
pub(crate) fn product_bodies(modules: &[ProductModule]) -> Box<[(Box<str>, Body)]> {
    bodies_by_owner(modules.iter().map(|module| (&*module.path, &module.parsed)))
}

/// No two modules state the same body, and no body nests past two layers.
pub(crate) fn assert_no_body_is_written_twice_or_nested_past_two_layers(all: &[(Box<str>, Body)]) {
    let mut deepest = 0;
    let mut deep: Vec<String> = Vec::new();
    for (path, body) in all {
        deepest = deepest.max(body.nesting);
        if body.nesting > MAX_NESTING {
            deep.push(format!(
                "{path}::{} nests {} layers",
                body.name, body.nesting
            ));
        }
    }
    let sites = duplicate_sites(all);
    assert!(
        deep.is_empty(),
        "every body nests at most {MAX_NESTING} layers: {deep:?}"
    );
    assert_eq!(
        deepest, MAX_NESTING,
        "the deepest body nests {deepest} layers, so the ceiling is not measuring this surface"
    );
    let copied: Box<[&Vec<String>]> = sites.values().filter(|held| held.len() > 1).collect();
    assert!(
        copied.is_empty(),
        "one implementation belongs in one place: {copied:?}"
    );
    assert!(
        sites.len() > OPERATIONS.len(),
        "only {} bodies reached the duplicate scan, so it constrains nothing",
        sites.len()
    );
}

/// In every body that both refuses a ceiling and retains, the refusal is
/// source-ordered first.
///
/// The measure is the position of each call in the body's own token stream. A
/// body that checked after it retained would already hold the excess record when
/// it refused, which is exactly what Invariant 14 forbids and exactly what no
/// input small enough to test would reveal.
pub(crate) fn assert_every_ceiling_is_checked_before_retention(all: &[(Box<str>, Body)]) {
    let mut offenders: Vec<String> = Vec::new();
    let mut measured = 0;
    for (path, body) in all {
        let rendered = compact(&body.shape);
        let Some(checked) = first_ceiling_check(&rendered) else {
            continue;
        };
        let Some(retained) = RETENTION_CALLS
            .iter()
            .filter_map(|call| first_bounded_retention(&rendered, call))
            .min()
        else {
            continue;
        };
        measured += 1;
        if checked > retained {
            offenders.push(format!("{path}::{} retains before it refuses", body.name));
        }
    }
    assert!(
        measured > 0,
        "no body both refused and retained, so the ordering claim constrains nothing"
    );
    assert!(
        offenders.is_empty(),
        "a ceiling is checked before the first excess record is retained: {offenders:?}"
    );
}

/// Where a body first checks a ceiling, if it checks one.
///
/// The match has to stand where a name begins. `capacity(` is a tail of
/// `with_capacity(`, `take_capacity(`, and `language_capacity(`, and none of
/// those checks anything — so a body that reserved a vector and then pushed into
/// it read as measured and correctly ordered, and kept the non-vacuity guard
/// alive after every real refusal had gone.
fn first_ceiling_check(rendered: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(offset) = rendered[from..].find(CAPACITY_CALL) {
        let at = from + offset;
        let preceding = rendered[..at].chars().next_back();
        if !preceding.is_some_and(|it| it == '_' || it.is_alphanumeric()) {
            return Some(at);
        }
        from = at + CAPACITY_CALL.len();
    }
    None
}

/// Where a body first grows a collection a ceiling governs, if it grows one.
///
/// Every occurrence of the call is walked rather than only the first, because
/// the first may be a diagnostic receiver: a body that records why it refused
/// and then checks a ceiling before retaining anything admitted satisfies
/// Invariant 14, and a scan that stopped at the first `.push(` would report it
/// as a violation.
fn first_bounded_retention(rendered: &str, call: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(offset) = rendered[from..].find(call) {
        let at = from + offset;
        let bounded = !DIAGNOSTIC_RECEIVERS
            .iter()
            .any(|receiver| rendered[..at].ends_with(receiver));
        if bounded {
            return Some(at);
        }
        from = at + call.len();
    }
    None
}
