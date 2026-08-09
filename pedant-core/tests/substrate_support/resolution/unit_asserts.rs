//! Claims about the units one resolution snapshot selects: their membership,
//! their composed activation, and the dependency shapes that cannot become a
//! unit at all.

use pedant_core::resolution::rust::{
    CargoDependencyKind, CargoTargetKind, DependencyActivation, RustProject,
    RustResolutionSnapshot, SourceClosureFailureKind,
};

use crate::resolution::fixture;
use crate::resolution::unit_fixtures::{
    ACTIVATION_COMPOSITION, DEPENDENCY_CYCLE, EXCLUDED_FROM_UNIT_SOURCES,
    EXPECTED_ACTIVATION_EDGES, EXPECTED_ACTIVATION_UNITS, EXPECTED_LIBRARY_EDGES,
    EXPECTED_LIBRARY_UNIT_MEMBERSHIP, EXPECTED_LIBRARY_UNIT_SOURCES, EXPECTED_LIBRARY_UNITS,
    EXPECTED_LIBX_MODULES, MISSING_LIBRARY, SAME_PACKAGE_TARGETS,
};
use crate::resolution::views::{
    app_library, closure_kinds, render_edges, render_modules, render_unit_sources, render_units,
    target_id, unit_of,
};

/// A library root takes its declared edges, and each unit keeps only the
/// sources and module instances its own closure reached.
pub fn assert_library_units(project: &RustProject, snapshot: &RustResolutionSnapshot) {
    assert_eq!(
        render_units(project, snapshot),
        EXPECTED_LIBRARY_UNITS,
        "a library root takes normal edges as declared and dev edges under test"
    );
    assert_eq!(
        render_edges(project, snapshot),
        EXPECTED_LIBRARY_EDGES,
        "a rename keeps its namespace-local alias on its own edge"
    );
    let paths: Vec<&str> = snapshot
        .sources()
        .iter()
        .map(|source| source.path())
        .collect();
    assert_eq!(
        paths, EXPECTED_LIBRARY_UNIT_SOURCES,
        "every unit contributes only its own module closure"
    );
    assert_eq!(
        render_unit_sources(project, snapshot),
        EXPECTED_LIBRARY_UNIT_MEMBERSHIP,
        "each source belongs to the unit whose closure reached it"
    );
    assert_eq!(
        render_modules(unit_of(project, snapshot, "libx")),
        EXPECTED_LIBX_MODULES,
        "a dependency unit carries its own module instances, not the root's"
    );
    for excluded in EXCLUDED_FROM_UNIT_SOURCES {
        assert!(
            snapshot.source(excluded).is_none(),
            "{excluded} belongs to no selected unit"
        );
    }
}

/// Effective activation is the conjunction along one path, the disjunction
/// across paths, and `Always` as soon as one path is unconditional.
pub fn assert_activation_composition() {
    let tmp = fixture::build_repository(ACTIVATION_COMPOSITION, false);
    let project = fixture::load_default(&tmp);
    let snapshot = project.snapshot_resolution(app_library(&project)).unwrap();
    assert_eq!(
        render_units(&project, &snapshot),
        EXPECTED_ACTIVATION_UNITS,
        "a unit records the composed predicate of every path that reaches it"
    );
    assert_eq!(
        render_edges(&project, &snapshot),
        EXPECTED_ACTIVATION_EDGES,
        "an edge records only the predicate its own declaration exposes"
    );
}

/// A non-library Cargo target sees its package library as an unconditional
/// unit, and a source both targets declare is stored once but instantiated in
/// each unit.
pub fn assert_same_package_library_unit() {
    let tmp = fixture::build_repository(SAME_PACKAGE_TARGETS, false);
    let project = fixture::load_default(&tmp);
    let library = app_library(&project);
    let binary = target_id(&project, "app", CargoTargetKind::Binary, "tool");
    let snapshot = project.snapshot_resolution(binary).unwrap();
    let library_unit = snapshot
        .units()
        .iter()
        .find(|unit| unit.target() == library)
        .expect("the binary snapshot includes its package library");
    let binary_unit = snapshot
        .units()
        .iter()
        .find(|unit| unit.target() == binary)
        .expect("the requested binary remains the root unit");

    assert_eq!(
        library_unit
            .sources()
            .iter()
            .map(|path| path.as_ref())
            .collect::<Vec<_>>(),
        ["src/common.rs", "src/lib.rs"],
        "the library keeps its own module closure"
    );
    assert_eq!(
        binary_unit
            .sources()
            .iter()
            .map(|path| path.as_ref())
            .collect::<Vec<_>>(),
        ["src/common.rs", "src/main.rs"],
        "the binary keeps its own module closure"
    );
    assert_eq!(
        snapshot
            .sources()
            .iter()
            .map(|source| source.path())
            .collect::<Vec<_>>(),
        ["src/common.rs", "src/lib.rs", "src/main.rs"],
        "the shared source is read and parsed once across both units"
    );

    let [edge] = snapshot.edges() else {
        panic!("the binary snapshot should contain only its implicit library edge");
    };
    assert_eq!(
        snapshot.unit(edge.source()).map(|unit| unit.target()),
        Some(binary),
        "the implicit edge starts at the requested binary"
    );
    assert_eq!(
        snapshot.unit(edge.target()).map(|unit| unit.target()),
        Some(library),
        "the implicit edge selects the same package's library"
    );
    assert_eq!(edge.name(), "app", "the edge uses the library crate name");
    assert_eq!(edge.kind(), CargoDependencyKind::Normal);
    assert_eq!(edge.activation(), &DependencyActivation::Always);
}

/// A dependency without a library, and a chain that repeats a package, are
/// typed refusals rather than partial unit sets.
pub fn assert_unit_rejections() {
    let missing = fixture::build_repository(MISSING_LIBRARY, false);
    let project = fixture::load_default(&missing);
    let error = project
        .snapshot_resolution(app_library(&project))
        .expect_err("a path dependency with no library target");
    assert_eq!(
        closure_kinds(&error),
        [SourceClosureFailureKind::MissingDependencyLibraryTarget],
        "a dependency package without a library cannot become a unit"
    );

    let cyclic = fixture::build_repository(DEPENDENCY_CYCLE, false);
    let project = fixture::load_default(&cyclic);
    let error = project
        .snapshot_resolution(app_library(&project))
        .expect_err("a cyclic dependency chain");
    assert_eq!(
        closure_kinds(&error),
        [SourceClosureFailureKind::DependencyCycle],
        "a package repeated in one chain is a typed cycle failure"
    );
}
