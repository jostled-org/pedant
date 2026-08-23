//! Where the Go resolver checks its one ceiling, and where the published
//! wrapper proves what it publishes, read from the production source.
//!
//! "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back. So the record owner is parsed and its statements are
//! compared: the candidate check precedes the body that turns slots into
//! candidates, and neither has a second site an unchecked route could take.
//!
//! The wrapper's claims are read the same way and stated apart, because a
//! coordinate, a kind, and a snapshot identity are validation rules rather than
//! lowerable ceilings: they are proved before the value exists, not sized by a
//! caller.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::RESOLVE_MODULES;
use crate::resolution::go::scan::{
    assert_single_go_site, free_function, impl_method, statement_naming,
};

/// The sole record owner, relative to `src/resolution/go`.
const RECORD_MODULE: &str = "resolve/records.rs";

/// The sole wrapper owner, relative to `src/resolution/go`.
const WRAPPER_MODULE: &str = "resolve/target.rs";

/// The body that answers one reference.
const RECORD_OWNER: &str = "write_one";

/// The ceiling check, and the body that turns proved slots into candidates.
const CANDIDATE_CHECK: &str = "check_candidate_capacity";
const CANDIDATE_RETENTION: &str = "retained_candidates";

/// The wrapper constructor, and the three claims it must prove first.
const WRAPPER_OWNER: &str = "try_new";
const WRAPPER_CLAIMS: &[&str] = &[
    "bind_units",
    "validate_definition_kinds",
    "validate_reference_kinds",
    "validate_snapshot_sites",
];

/// 8.T3 (Invariant 5): the candidate ceiling dominates candidate retention, and
/// the wrapper proves every binding, kind, and coordinate before it publishes.
#[test]
fn go_resolution_limit_checks_dominate_candidate_retention() {
    assert!(
        RESOLVE_MODULES.contains(&RECORD_MODULE) && RESOLVE_MODULES.contains(&WRAPPER_MODULE),
        "the record and wrapper owners must be modelled Go owners"
    );

    assert_single_go_site(CANDIDATE_CHECK, RECORD_MODULE, 1);
    assert_single_go_site(CANDIDATE_RETENTION, RECORD_MODULE, 1);

    let records = parse_rust_file(&go_path(RECORD_MODULE));
    let body = &free_function(&records, RECORD_OWNER)
        .unwrap_or_else(|| panic!("{RECORD_MODULE} should declare `{RECORD_OWNER}`"))
        .block;
    let checked = statement_naming(body, CANDIDATE_CHECK)
        .unwrap_or_else(|| panic!("`{RECORD_OWNER}` should state `{CANDIDATE_CHECK}`"));
    let retained = statement_naming(body, CANDIDATE_RETENTION)
        .unwrap_or_else(|| panic!("`{RECORD_OWNER}` should state `{CANDIDATE_RETENTION}`"));
    assert!(
        checked < retained,
        "`{RECORD_OWNER}` must reach `{CANDIDATE_CHECK}` (statement {checked}) before `{CANDIDATE_RETENTION}` (statement {retained})"
    );

    assert_wrapper_proves_before_publishing();
}

/// Every wrapper claim is stated before the published value is built.
fn assert_wrapper_proves_before_publishing() {
    let wrapper = parse_rust_file(&go_path(WRAPPER_MODULE));
    let body = &impl_method(&wrapper, WRAPPER_OWNER)
        .unwrap_or_else(|| panic!("{WRAPPER_MODULE} should declare `{WRAPPER_OWNER}`"))
        .block;
    let published = body.stmts.len() - 1;
    for claim in WRAPPER_CLAIMS {
        assert_single_go_site(claim, WRAPPER_MODULE, 1);
        let stated = statement_naming(body, claim)
            .unwrap_or_else(|| panic!("`{WRAPPER_OWNER}` should state `{claim}`"));
        assert!(
            stated < published,
            "`{WRAPPER_OWNER}` must prove `{claim}` (statement {stated}) before it publishes (statement {published})"
        );
    }
}

fn go_path(module: &str) -> std::path::PathBuf {
    crate_path("src/resolution/go").join(module)
}
