//! Where the interface stage checks its ceiling, and why no candidate it
//! produces can reach a report around the record owner's own check.
//!
//! "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back. So the comparison owner is parsed and its statements
//! are compared.
//!
//! The candidate half is a claim about reach rather than order: the interface
//! stage states relations and implementor lists, never report records, so every
//! candidate it contributes — an implementation's interface and a dispatch's
//! targets alike — passes the record owner's candidate ceiling on its way in.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::RESOLVE_MODULES;
use crate::resolution::go::scan::{
    SourceScan, assert_single_go_site, impl_method, statement_naming,
};

/// The sole comparison owner, relative to `src/resolution/go`.
const COMPARISON_MODULE: &str = "resolve/implementations.rs";

/// The sole expansion owner, which reads interfaces and states no record.
const EXPANSION_MODULE: &str = "resolve/interfaces.rs";

/// The body that compares one concrete type against one interface.
const COMPARISON_OWNER: &str = "compare_pair";

/// The ceiling check, and the body that retains a compared relation.
const COMPARISON_CHECK: &str = "check_comparison_capacity";
const COMPARISON_RETENTION: &str = "retain_relation";

/// The report routes that turn a candidate into a published record.
///
/// Neither interface module may reach one: a candidate stated straight into the
/// report here would be a candidate the record owner never counted.
const REPORT_ROUTES: &[&str] = &["add_reference", "set_resolution", "add_definition"];

/// 10.T4 (Invariant 5): the comparison ceiling dominates relation retention,
/// and no interface candidate reaches a report except through the record owner.
#[test]
fn go_interface_limit_checks_dominate_candidate_retention() {
    assert!(
        RESOLVE_MODULES.contains(&COMPARISON_MODULE) && RESOLVE_MODULES.contains(&EXPANSION_MODULE),
        "the comparison and expansion owners must be modelled Go owners"
    );

    assert_single_go_site(COMPARISON_CHECK, COMPARISON_MODULE, 1);
    assert_single_go_site(COMPARISON_RETENTION, COMPARISON_MODULE, 1);

    let owner = parse_rust_file(&go_path(COMPARISON_MODULE));
    let body = &impl_method(&owner, COMPARISON_OWNER)
        .unwrap_or_else(|| panic!("{COMPARISON_MODULE} should declare `{COMPARISON_OWNER}`"))
        .block;
    let checked = statement_naming(body, COMPARISON_CHECK)
        .unwrap_or_else(|| panic!("`{COMPARISON_OWNER}` should state `{COMPARISON_CHECK}`"));
    let retained = statement_naming(body, COMPARISON_RETENTION)
        .unwrap_or_else(|| panic!("`{COMPARISON_OWNER}` should state `{COMPARISON_RETENTION}`"));
    assert!(
        checked < retained,
        "`{COMPARISON_OWNER}` must reach `{COMPARISON_CHECK}` (statement {checked}) before `{COMPARISON_RETENTION}` (statement {retained})"
    );

    assert_states_no_report_records();
}

/// Neither interface module writes into a report.
fn assert_states_no_report_records() {
    let reached: Box<[Box<str>]> = [COMPARISON_MODULE, EXPANSION_MODULE]
        .iter()
        .flat_map(|module| routes_reached(module).into_vec())
        .collect();
    assert_eq!(
        &*crate::resolution::go::views::borrowed(&reached),
        &[] as &[&str],
        "an interface module states relations, never report records"
    );
}

/// Every report route one module reaches, reported as `<module> reaches
/// <route>`.
fn routes_reached(module: &str) -> Box<[Box<str>]> {
    let scan = SourceScan::of_file(&parse_rust_file(&go_path(module)));
    REPORT_ROUTES
        .iter()
        .filter(|route| scan.reaches(route) > 0)
        .map(|route| format!("{module} reaches {route}").into_boxed_str())
        .collect()
}

fn go_path(module: &str) -> std::path::PathBuf {
    crate_path("src/resolution/go").join(module)
}
