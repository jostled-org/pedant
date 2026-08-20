//! Where the Go module loader checks its ceilings, read from the production
//! source.
//!
//! "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back. So the admission owner is parsed and its statements are
//! read: the manifest-count check and the dependency-depth check both precede
//! the insertion into the retained module table, and neither the table nor the
//! pending queue has a second growth site that could take an unchecked route.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::{GO_MODULES, source_closure};
use crate::resolution::go::scan::{
    SourceScan, impl_method, statement_naming, statement_naming_field,
};

/// The sole module-admission owner.
const LOADER_MODULE: &str = "load.rs";

/// The one method every admitted module enters the project through.
const ADMISSION: &str = "retain_module";

/// The two checks that must dominate retention.
const MANIFEST_CHECK: &str = "check_manifest_capacity";
const DEPTH_CHECK: &str = "check_dependency_depth";

/// The retained tables the loader grows, written as the field each push names.
const MODULE_RETENTION: &str = "modules.push";
const REQUIREMENT_RETENTION: &str = "resolved.push";

/// 3.T4 (Invariant 5): the manifest-count and dependency-depth checks dominate
/// every insertion into the retained module table.
#[test]
fn go_project_limit_checks_dominate_manifest_and_dependency_retention() {
    let closure = source_closure();
    assert!(
        closure.len() > GO_MODULES.len(),
        "the closure must reach the shared resolution owners too"
    );

    assert_single_check_site(MANIFEST_CHECK);
    assert_single_check_site(DEPTH_CHECK);
    assert_single_retention_site(MODULE_RETENTION);
    assert_single_retention_site(REQUIREMENT_RETENTION);

    let loader = parse_rust_file(&go_path(LOADER_MODULE));
    let admission = impl_method(&loader, ADMISSION)
        .unwrap_or_else(|| panic!("{LOADER_MODULE} should declare `{ADMISSION}`"));
    let retention =
        statement_naming_field(&admission.block, MODULE_RETENTION).unwrap_or_else(|| {
            panic!("`{ADMISSION}` should retain a module through `{MODULE_RETENTION}`")
        });

    for check in [MANIFEST_CHECK, DEPTH_CHECK] {
        let checked = statement_naming(&admission.block, check)
            .unwrap_or_else(|| panic!("`{ADMISSION}` should state `{check}` as a statement"));
        assert!(
            checked < retention,
            "`{ADMISSION}` must reach `{check}` (statement {checked}) before `{MODULE_RETENTION}` (statement {retention})"
        );
    }
}

/// Exactly one Go module states `check`, and it states it once.
fn assert_single_check_site(check: &str) {
    let naming: Box<[(&str, usize)]> = GO_MODULES
        .iter()
        .map(|module| {
            (
                *module,
                SourceScan::of_file(&parse_rust_file(&go_path(module))).reaches(check),
            )
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    assert_eq!(
        &*naming,
        [(LOADER_MODULE, 1)],
        "`{check}` must have exactly one call site, in {LOADER_MODULE}"
    );
}

/// Exactly one Go module grows the named table, and it grows it once.
fn assert_single_retention_site(route: &str) {
    let naming: Box<[(&str, usize)]> = GO_MODULES
        .iter()
        .map(|module| {
            (
                *module,
                SourceScan::of_file(&parse_rust_file(&go_path(module))).reaches_on_field(route),
            )
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    assert_eq!(
        &*naming,
        [(LOADER_MODULE, 1)],
        "`{route}` must have exactly one retention site, in {LOADER_MODULE}"
    );
}

fn go_path(module: &str) -> std::path::PathBuf {
    crate_path("src/resolution/go").join(module)
}
