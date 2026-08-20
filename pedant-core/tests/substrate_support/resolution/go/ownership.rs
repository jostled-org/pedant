//! Where the Go module loader checks its ceilings, read from the production
//! source.
//!
//! "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back. So the admission owner is parsed and its statements are
//! read: the manifest-count check and the dependency-depth check both precede
//! every growth of the retained module table and of the pending queue, and
//! neither has a second growth site that could take an unchecked route.
//!
//! The requirement table is retained in another body, so order inside the
//! admission body says nothing about it directly. Its route is asserted
//! instead: a requirement is resolved only for a module the queue handed back,
//! and the queue is grown only after both ceilings pass.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::{GO_MODULES, source_closure};
use crate::resolution::go::scan::{
    SourceScan, impl_method, statement_naming, statement_naming_field,
};

/// The sole module-admission owner.
const LOADER_MODULE: &str = "load.rs";

/// The one method every admitted module enters the project through.
const ADMISSION: &str = "retain_module";

/// The method that drives the queue until no module is pending.
const DRIVER: &str = "run";

/// The stage that resolves one admitted module's requirements, and the body
/// that retains each one.
const REQUIREMENT_STAGE: &str = "resolve_module_requirements";
const REQUIREMENT_OWNER: &str = "resolve_requirement";

/// The two checks that must dominate retention.
const MANIFEST_CHECK: &str = "check_manifest_capacity";
const DEPTH_CHECK: &str = "check_dependency_depth";

/// The retained tables the loader grows, written as the field each push names.
const MODULE_RETENTION: &str = "modules.push";
const QUEUE_RETENTION: &str = "pending.push_back";
const REQUIREMENT_RETENTION: &str = "resolved.push";

/// The one route a queued module leaves the queue by.
const QUEUE_DRAIN: &str = "pop_front";

/// 3.T4 (Invariant 5): the manifest-count and dependency-depth checks dominate
/// every insertion into the retained project tables.
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
    assert_single_retention_site(QUEUE_RETENTION);
    assert_single_retention_site(REQUIREMENT_RETENTION);

    let loader = parse_rust_file(&go_path(LOADER_MODULE));
    assert_checks_dominate_admission(&loader);
    assert_requirements_are_retained_only_behind_the_queue(&loader);
}

/// Both ceilings are stated before the admission body grows either structure it
/// retains.
fn assert_checks_dominate_admission(loader: &syn::File) {
    let admission = method_body(loader, ADMISSION);
    for route in [MODULE_RETENTION, QUEUE_RETENTION] {
        let retention = statement_naming_field(admission, route)
            .unwrap_or_else(|| panic!("`{ADMISSION}` should grow `{route}`"));
        for check in [MANIFEST_CHECK, DEPTH_CHECK] {
            let checked = statement_naming(admission, check)
                .unwrap_or_else(|| panic!("`{ADMISSION}` should state `{check}` as a statement"));
            assert!(
                checked < retention,
                "`{ADMISSION}` must reach `{check}` (statement {checked}) before `{route}` (statement {retention})"
            );
        }
    }
}

/// A requirement is retained only for a module the queue handed back.
///
/// The single-site assertion alone would keep this predicate green while a
/// requirement was pushed from some body the ceilings never reached, so the
/// route is stated: `resolved.push` lives in one method, that method has one
/// caller, that caller has one caller, and it runs inside the queue drain.
fn assert_requirements_are_retained_only_behind_the_queue(loader: &syn::File) {
    assert!(
        statement_naming_field(
            method_body(loader, REQUIREMENT_OWNER),
            REQUIREMENT_RETENTION
        )
        .is_some(),
        "`{REQUIREMENT_OWNER}` should be the body that grows `{REQUIREMENT_RETENTION}`"
    );
    assert_sole_call_site(loader, REQUIREMENT_STAGE, REQUIREMENT_OWNER);
    assert_sole_call_site(loader, DRIVER, REQUIREMENT_STAGE);

    let driver = method_body(loader, DRIVER);
    let drained = statement_naming(driver, QUEUE_DRAIN)
        .unwrap_or_else(|| panic!("`{DRIVER}` should drain the queue through `{QUEUE_DRAIN}`"));
    let staged = statement_naming(driver, REQUIREMENT_STAGE)
        .unwrap_or_else(|| panic!("`{DRIVER}` should reach `{REQUIREMENT_STAGE}`"));
    assert_eq!(
        staged, drained,
        "`{DRIVER}` must reach `{REQUIREMENT_STAGE}` only inside the `{QUEUE_DRAIN}` drain"
    );
    assert_eq!(
        SourceScan::of_file(loader).reaches(QUEUE_DRAIN),
        1,
        "`{QUEUE_DRAIN}` must have exactly one site, in `{DRIVER}`"
    );
}

/// `route` has one call site in the loader, and `owner` is the body holding it.
fn assert_sole_call_site(loader: &syn::File, owner: &str, route: &str) {
    assert_eq!(
        SourceScan::of_file(loader).reaches(route),
        1,
        "`{route}` must have exactly one call site in {LOADER_MODULE}"
    );
    assert!(
        statement_naming(method_body(loader, owner), route).is_some(),
        "`{owner}` must be the one body that reaches `{route}`"
    );
}

/// The block of one inherent method the loader declares.
fn method_body<'file>(loader: &'file syn::File, name: &str) -> &'file syn::Block {
    &impl_method(loader, name)
        .unwrap_or_else(|| panic!("{LOADER_MODULE} should declare `{name}`"))
        .block
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
