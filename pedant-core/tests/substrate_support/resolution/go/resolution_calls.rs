//! What a call denotes, and the three call shapes that denote no static target.
//!
//! A direct call and a package-qualified call resolve when the snapshot holds
//! their target. A call whose callee names a type converts rather than calls,
//! and a call through a value held by a parameter or a local is chosen at run
//! time, so neither states a resolved call target.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_fixtures::CALL_SHAPES;
use crate::resolution::go::resolution_views::unit_references;
use crate::resolution::go::views::borrowed;

/// The package unit stating every call shape.
const APP: &str = "x#production";

/// Every reference the calling package states.
const APP_REFERENCES: &[&str] = &[
    "x#production|Import|fmt|calls.go:3|-||ExternalDefinition",
    "x#production|Import|x/util|calls.go:4|resolved|x/util#production::util|",
    "x#production|Type|string|calls.go:7|-||ExternalDefinition",
    "x#production|Type|string|calls.go:9|-||ExternalDefinition",
    "x#production|Type|string|calls.go:13|-||ExternalDefinition",
    "x#production|Call|Local|calls.go:14|resolved|x#production::Local|",
    "x#production|Type|string|calls.go:17|-||ExternalDefinition",
    "x#production|Call|Name|calls.go:18|resolved|x/util#production::Name|",
    "x#production|Type|string|calls.go:21|-||ExternalDefinition",
    "x#production|Call|Sprint|calls.go:22|-||ExternalDefinition",
    "x#production|Type|string|calls.go:25|-||ExternalDefinition",
    "x#production|Type|Label|calls.go:25|resolved|x#production::Label|",
    "x#production|Type|Label|calls.go:26|resolved|x#production::Label|",
    "x#production|Type|string|calls.go:29|-||ExternalDefinition",
    "x#production|Type|string|calls.go:29|-||ExternalDefinition",
    "x#production|Call|fn|calls.go:30|-||DynamicDispatch",
    "x#production|Type|string|calls.go:33|-||ExternalDefinition",
    "x#production|Value|Local|calls.go:34|resolved|x#production::Local|",
    "x#production|Call|fn|calls.go:35|-||DynamicDispatch",
];

/// 5.T3 (Invariant 14): a direct and a package-qualified target in the snapshot
/// resolve, and an external target keeps its gap with no fabricated node.
#[test]
fn go_function_calls_resolve_only_in_snapshot_targets() {
    let (tree, snapshot, resolution) = resolve_default(CALL_SHAPES);

    assert_eq!(
        &*borrowed(&unit_references(&resolution, APP)),
        APP_REFERENCES,
        "the in-snapshot targets resolve and the external one keeps its gap"
    );

    let fabricated: Box<[&str]> = resolution
        .report()
        .definitions()
        .iter()
        .filter(|definition| definition.name() == "Sprint" || definition.name() == "fmt")
        .map(|definition| definition.name())
        .collect();
    assert!(
        fabricated.is_empty(),
        "an external target fabricates no definition: {fabricated:?}"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}

/// 5.T4 (Invariant 15): a conversion is a type reference rather than a call,
/// and a call through a function value states no resolved target.
#[test]
fn go_conversions_and_runtime_function_values_are_not_static_calls() {
    let (tree, snapshot, resolution) = resolve_default(CALL_SHAPES);

    let stated = unit_references(&resolution, APP);
    let conversions: Box<[&str]> = stated
        .iter()
        .filter(|line| line.contains("|Label|"))
        .map(|line| &**line)
        .collect();
    assert_eq!(
        &*conversions,
        [
            "x#production|Type|Label|calls.go:25|resolved|x#production::Label|",
            "x#production|Type|Label|calls.go:26|resolved|x#production::Label|",
        ],
        "a call whose callee names a type is a type reference, never a call"
    );

    let dynamic: Box<[&str]> = stated
        .iter()
        .filter(|line| line.contains("|Call|fn|"))
        .map(|line| &**line)
        .collect();
    assert_eq!(
        &*dynamic,
        [
            "x#production|Call|fn|calls.go:30|-||DynamicDispatch",
            "x#production|Call|fn|calls.go:35|-||DynamicDispatch",
        ],
        "a call through a parameter and a call through a local both stay dynamic"
    );

    let resolved_calls: Box<[&str]> = stated
        .iter()
        .filter(|line| line.contains("|Call|") && line.contains("|resolved|"))
        .map(|line| &**line)
        .collect();
    assert_eq!(
        &*resolved_calls,
        [
            "x#production|Call|Local|calls.go:14|resolved|x#production::Local|",
            "x#production|Call|Name|calls.go:18|resolved|x/util#production::Name|",
        ],
        "exactly the two static targets are resolved calls"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
