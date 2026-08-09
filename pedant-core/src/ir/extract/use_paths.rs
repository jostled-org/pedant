//! Projection of the authoritative reference sites into the flat qualified
//! path list capability detection consumes.
//!
//! Import trees and expression paths are walked once, by the site collector.
//! This pass only selects and deduplicates: `use` leaves are already distinct
//! and pass straight through, while expression paths repeat heavily and are
//! deduplicated against a set. Import sites keep their `use` item's start
//! coordinate, so a projected fact reports the position it always has.

use std::collections::BTreeSet;

use crate::ir::facts::UsePathFact;
use crate::ir::sites::{ReferenceOrigin, ReferenceSite};

/// The qualified paths one source's reference sites project onto.
pub(super) fn project_use_paths(references: &[ReferenceSite]) -> Box<[UsePathFact]> {
    let mut seen: BTreeSet<Box<str>> = BTreeSet::new();
    references
        .iter()
        .filter_map(|site| projected(site, &mut seen))
        .collect()
}

fn projected(site: &ReferenceSite, seen: &mut BTreeSet<Box<str>>) -> Option<UsePathFact> {
    match site.origin() {
        ReferenceOrigin::Import => Some(fact(site)),
        ReferenceOrigin::ExpressionPath => seen.insert(site.text.clone()).then(|| fact(site)),
        _ => None,
    }
}

fn fact(site: &ReferenceSite) -> UsePathFact {
    UsePathFact {
        path: site.text.clone(),
        span: site.range.start,
    }
}
