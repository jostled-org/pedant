//! Every load ceiling refuses at its own first excess and publishes no project.
//!
//! The two ceilings are lowered one at a time against one repository, so a row
//! that passed because another ceiling refused first would show up as the wrong
//! error text rather than as a pass.

use pedant_core::resolution::go::GoResolutionLimits;

use crate::resolution::go::fixture::load;
use crate::resolution::go::project_fixtures::CHAINED_MODULES;
use crate::resolution::go::views::{borrowed, modules};

/// Every module [`CHAINED_MODULES`] admits when no ceiling refuses.
const CHAIN: &[&str] = &[
    "example.com/root||go.mod|0",
    "example.com/first|local/first|local/first/go.mod|1",
    "example.com/second|local/second|local/second/go.mod|2",
];

/// 3.T3 (Invariant 5): the manifest and dependency-depth ceilings each refuse
/// at their first excess, and neither publishes a partial project.
#[test]
fn go_project_load_limits_refuse_every_first_excess() {
    for (limit, expected) in [
        (1, "project holds more than 1 module manifests"),
        (2, "project holds more than 2 module manifests"),
    ] {
        let refused = load_with(|limits| limits.max_module_manifests = limit);
        assert_eq!(
            refused, expected,
            "the manifest ceiling {limit} refuses at its first excess"
        );
    }

    for (limit, expected) in [
        (0, "dependency depth exceeds 0"),
        (1, "dependency depth exceeds 1"),
    ] {
        let refused = load_with(|limits| limits.max_dependency_depth = limit);
        assert_eq!(
            refused, expected,
            "the depth ceiling {limit} refuses at its first excess"
        );
    }

    let (tree, project) = load(CHAINED_MODULES, GoResolutionLimits::default());
    let project = project.expect("the chain loads under the documented defaults");
    assert_eq!(&*borrowed(&modules(&project)), CHAIN);
    drop(tree);

    let (tree, project) = load(CHAINED_MODULES, admitting_chain());
    let project = project.expect("the chain loads at exactly its own ceilings");
    assert_eq!(
        &*borrowed(&modules(&project)),
        CHAIN,
        "a ceiling equal to what the tree holds admits it"
    );
    drop(tree);
}

/// The lowest ceilings that still admit [`CHAINED_MODULES`], which is what makes
/// each refusal above the first excess rather than an unrelated bound.
fn admitting_chain() -> GoResolutionLimits {
    GoResolutionLimits {
        max_module_manifests: 3,
        max_dependency_depth: 2,
        ..GoResolutionLimits::default()
    }
}

/// Load the chain under one lowered ceiling and return the refusal text.
fn load_with(lower: impl FnOnce(&mut GoResolutionLimits)) -> String {
    let mut limits = admitting_chain();
    lower(&mut limits);
    let (tree, loaded) = load(CHAINED_MODULES, limits);
    let text = match loaded {
        Ok(project) => panic!("a lowered ceiling should refuse, not load: {project:?}"),
        Err(error) => error.to_string(),
    };
    drop(tree);
    text
}
