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
//!
//! That half is asserted the way the check names are, over the whole Go surface
//! at once. Naming the two modules the claim happens to talk about would leave
//! the modules that build the candidates unscanned: an `add_reference` grown in
//! `resolve/dispatch.rs` or `resolve/relations.rs` would publish a candidate the
//! record owner never counted, and a two-module scan would report nothing.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::{RESOLVE_MODULES, go_module_paths};
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

/// The modules that build the candidates this case reasons about.
///
/// `dispatch.rs` seals a call's target list and `relations.rs` seals an
/// implementation's single interface candidate, so a reach claim that excluded
/// them would cover neither half of the claim it states.
const CANDIDATE_MODULES: &[&str] = &["resolve/dispatch.rs", "resolve/relations.rs"];

/// The report routes that turn a candidate into a published record.
///
/// No interface-stage module may reach one: a candidate stated straight into
/// the report here would be a candidate the record owner never counted.
const REPORT_ROUTES: &[&str] = &["add_reference", "set_resolution", "add_definition"];

/// Every site across the Go surface that reaches a report route, written
/// `<module> reaches <route>`.
///
/// Written down rather than discovered, as [`RESOLVE_MODULES`] itself is: a set
/// read back off the tree agrees with whatever the tree holds, so it would
/// accept the very route this case exists to refuse.
const REPORT_REACHERS: &[&str] = &[
    "resolve/definitions.rs reaches add_definition",
    "resolve/records.rs reaches add_reference",
    "resolve/records.rs reaches set_resolution",
];

/// 10.T4 (Invariant 5): the comparison ceiling dominates relation retention,
/// and no interface candidate reaches a report except through the record owner.
#[test]
fn go_interface_limit_checks_dominate_candidate_retention() {
    let scanned: Box<[&str]> = [COMPARISON_MODULE, EXPANSION_MODULE]
        .into_iter()
        .chain(CANDIDATE_MODULES.iter().copied())
        .filter(|module| !RESOLVE_MODULES.contains(module))
        .collect();
    assert_eq!(
        &*scanned,
        &[] as &[&str],
        "every interface-stage owner this case names must be a modelled Go owner"
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

    assert_report_records_have_one_owner_pair();
}

/// The report routes are reached from exactly the record owners, across every
/// Go module — so no interface-stage module states a record of its own.
fn assert_report_records_have_one_owner_pair() {
    let reached: Box<[Box<str>]> = go_module_paths()
        .iter()
        .flat_map(|(label, path)| routes_reached(label, path).into_vec())
        .collect();
    assert_eq!(
        &*crate::resolution::go::views::borrowed(&reached),
        REPORT_REACHERS,
        "a report record is stated by its owner alone; an interface module states relations"
    );
}

/// Every report route one module reaches, reported as `<module> reaches
/// <route>`.
fn routes_reached(module: &str, path: &std::path::Path) -> Box<[Box<str>]> {
    let scan = SourceScan::of_file(&parse_rust_file(path));
    REPORT_ROUTES
        .iter()
        .filter(|route| scan.reaches(route) > 0)
        .map(|route| format!("{module} reaches {route}").into_boxed_str())
        .collect()
}

fn go_path(module: &str) -> std::path::PathBuf {
    crate_path("src/resolution/go").join(module)
}
