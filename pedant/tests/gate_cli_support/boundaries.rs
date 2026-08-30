//! The module, support, dependency, and release-order boundaries this design
//! states, read from tracked source and manifests only.
//!
//! Who may publish, and who may run the guards that decide it, is the release
//! authority's claim rather than this one: `pedant-core`'s
//! `code_intelligence_release_and_archive_owners_are_exact` requires each of
//! those routes to appear in exactly one tracked workflow. A weaker copy here
//! would agree with a second job that published from an ungated tree.

use std::path::PathBuf;

use crate::source::{
    assert_inventory, collect_sources, gate_tree, manifest_dir, read, support_tree, workspace_root,
};

/// Every module the gate family is required to hold, sorted.
pub(crate) const GATE_MODULES: &[&str] = &[
    "command.rs",
    "error.rs",
    "evidence.rs",
    "mod.rs",
    "project.rs",
];

/// Every gate CLI support module, sorted.
const GATE_SUPPORT_MODULES: &[&str] = &[
    "boundaries.rs",
    "budgets.rs",
    "capability_modes.rs",
    "catalog.rs",
    "ceilings.rs",
    "failures.rs",
    "fixture.rs",
    "output.rs",
    "ownership.rs",
    "project.rs",
    "release_ownership.rs",
    "semantic.rs",
    "source.rs",
    "topology.rs",
];

/// The package-shared support tree, which owns exactly one wrapper.
const PACKAGE_SUPPORT_MODULES: &[&str] = &["process_guard.rs"];

/// Policy vocabulary the topology library may not own.
const FORBIDDEN_IN_GRAPH: &[&str] = &[
    "GateVerdict",
    "GateSeverity",
    "GateConfig",
    "ModuleBoundaryConfig",
    "ModuleBoundaryInput",
    "evaluate_module_boundary_rules",
];

/// The module, support, dependency, and release boundaries this design states.
pub(crate) fn repository_boundaries_are_exact() {
    assert_inventory(&gate_tree(), GATE_MODULES);
    assert_inventory(&support_tree(), GATE_SUPPORT_MODULES);
    assert_inventory(
        &manifest_dir().join("tests/package_support"),
        PACKAGE_SUPPORT_MODULES,
    );

    production_source_holds_no_tests();
    crate::release_ownership::dependency_edge_is_versioned_and_ordered(
        &read(&manifest_dir().join("Cargo.toml")),
        &read(&workspace_root().join("pedant-graph/Cargo.toml")),
        &read(&workspace_root().join("release-plz.toml")),
    );
    graph_holds_no_policy_owner();
}

fn production_source_holds_no_tests() {
    let mut sources = Vec::new();
    collect_sources(&manifest_dir().join("src"), &mut sources);
    assert!(sources.len() > 10, "the production tree was located");
    for path in &sources {
        let source = read(path);
        assert!(
            !source.contains("#[test]") && !source.contains("mod tests"),
            "{} must hold no inline test",
            path.display()
        );
    }
}

fn graph_holds_no_policy_owner() {
    let mut sources: Vec<PathBuf> = Vec::new();
    collect_sources(&workspace_root().join("pedant-graph/src"), &mut sources);
    assert!(sources.len() > 1, "the graph production tree was located");
    for path in &sources {
        let source = read(path);
        let present: Vec<&str> = FORBIDDEN_IN_GRAPH
            .iter()
            .copied()
            .filter(|token| source.contains(token))
            .collect();
        assert!(
            present.is_empty(),
            "{} must not own {present:?}",
            path.display()
        );
    }
}
