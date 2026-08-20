//! The root manifest is the sole `replace` and `exclude` authority, and an
//! exact requirement replacement outranks a path-only one.

use pedant_core::resolution::go::GoResolutionLimits;

use crate::resolution::go::fixture::load_default;
use crate::resolution::go::project_fixtures::DIRECTIVE_AUTHORITY;
use crate::resolution::go::views::{borrowed, exclusions, modules, replacements, requirements};

/// Every module the loader may admit from [`DIRECTIVE_AUTHORITY`].
///
/// `local/outranked`, `local/unused`, and `local/exact/child-ignored` all hold
/// a readable `go.mod` and none of them appears: the first lost precedence, the
/// second is required by nobody, and the third is named only by a child
/// manifest, which has no replacement authority.
const ADMITTED_MODULES: &[&str] = &[
    "example.com/root||go.mod|0",
    "example.com/exact|local/exact|local/exact/go.mod|1",
    "example.com/wide|local/wide|local/wide/go.mod|1",
];

/// Every requirement, and what it resolved to.
///
/// `example.com/absent` is required twice at two versions and stays external
/// twice: this tier states what each manifest declared and selects no minimum
/// version.
const RESOLVED_REQUIREMENTS: &[&str] = &[
    "example.com/root|example.com/absent|v2.1.0|external",
    "example.com/root|example.com/exact|v1.0.0|local:example.com/exact",
    "example.com/root|example.com/rehomed|v1.5.0|module:example.com/elsewhere@v3.0.0",
    "example.com/root|example.com/wide|v0.3.0|local:example.com/wide",
    "example.com/exact|example.com/child|v0.1.0|external",
    "example.com/wide|example.com/absent|v1.0.0|external",
];

/// Every root replacement, and whether an admitted requirement used it.
const ROOT_REPLACEMENTS: &[&str] = &[
    "example.com/exact|*|dir:local/outranked|false",
    "example.com/exact|v1.0.0|dir:local/exact|true",
    "example.com/rehomed|v1.5.0|module:example.com/elsewhere@v3.0.0|true",
    "example.com/unused|*|dir:local/unused|false",
    "example.com/wide|*|dir:local/wide|true",
];

/// The one root exclusion, which matches nothing required.
const ROOT_EXCLUSIONS: &[&str] = &["example.com/never|v9.9.9"];

/// 3.T1 (Invariant 26): root-only directive authority, exact-over-path
/// replacement precedence, and no minimal-version selection.
#[test]
fn go_module_directive_authority_and_precedence_are_exact() {
    let (tree, project) = load_default(DIRECTIVE_AUTHORITY);

    assert_eq!(&*borrowed(&modules(&project)), ADMITTED_MODULES);
    assert_eq!(&*borrowed(&requirements(&project)), RESOLVED_REQUIREMENTS);
    assert_eq!(&*borrowed(&replacements(&project)), ROOT_REPLACEMENTS);
    assert_eq!(&*borrowed(&exclusions(&project)), ROOT_EXCLUSIONS);

    assert_eq!(
        project.root_module().path(),
        "example.com/root",
        "the root manifest names the main module"
    );
    assert_eq!(
        project.limits(),
        GoResolutionLimits::default(),
        "the project retains the limits it was loaded under"
    );
    assert_eq!(
        project.root(),
        std::fs::canonicalize(project.root()).expect("the retained root exists"),
        "the retained root is canonical"
    );

    let declared: Box<[&str]> = project
        .module_requirements(project.root_module().id())
        .map(|requirement| requirement.path())
        .collect();
    assert_eq!(
        &*declared,
        [
            "example.com/absent",
            "example.com/exact",
            "example.com/rehomed",
            "example.com/wide"
        ],
        "the root module's own requirements are selectable by identity"
    );

    drop(tree);
}
