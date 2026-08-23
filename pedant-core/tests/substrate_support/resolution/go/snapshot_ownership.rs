//! Where the Go snapshot checks its ceilings and confines its paths, read from
//! the production source.
//!
//! "Refused before the excess was retained" and "confined before the bytes were
//! opened" are claims about order, and a behavioral case cannot tell a check
//! that ran first from one that ran after a push and rolled back. So the store,
//! the package walk, and the snapshot constructor are parsed and their
//! statements are read: every ceiling precedes the growth it pays for, every
//! read is preceded by the confinement that admitted its path, and no retained
//! table has a second growth site that could take an unchecked route.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::{GO_MODULES, SNAPSHOT_MODULES};
use crate::resolution::go::scan::{
    SourceScan, free_function, impl_method, statement_naming, statement_naming_field,
};

/// The owners the claim is read from.
const STORE: &str = "store.rs";
const WALK: &str = "discovery.rs";
const CONSTRUCTOR: &str = "unit_table.rs";

/// The store's one interning body, and the two bodies it drives.
const INTERN: &str = "intern";
const READER: &str = "read_and_walk";
const EXTRACTION: &str = "extract";

/// The fact ceilings the snapshot converts, the two walks they bound, and the
/// digest and inventory those walks pay for.
const FACT_CEILINGS: &str = "fact_limits";
const PARSE_ROUTE: &str = "parse_bound";
const FACT_WALK: &str = "go_file_facts";
const SOURCE_DIGEST: &str = "digest_bytes";
const INVENTORY: &str = "conditions_of";

/// The ceilings the store owns.
///
/// The two byte ceilings are stated as the bounds handed to the one bounded
/// reader rather than as checks the store runs itself: the length a ceiling is
/// compared against has to be the length that was read, which only the reader
/// holds.
const SOURCE_CHECK: &str = "check_source_capacity";
const BYTE_BOUNDS: &str = "bounds";

/// The tables the store and the constructor grow.
const SOURCE_RETENTION: &str = "stored.push";
const INDEX_RETENTION: &str = "indexes.insert";
const UNIT_RETENTION: &str = "drafts.push";

/// The package walk's bodies, its budget, and the confinement it applies.
const LISTING: &str = "listing";
const WALKER: &str = "descend";
const DIRECTORY_OWNER: &str = "retain";
const BUDGET_CHECK: &str = "spend";
const CONFINEMENT: &str = "canonical_in_root";
const ENTRY_ADMISSION: &str = "admitted";
const DIRECTORY_RETENTION: &str = "found.push";

/// The constructor's unit ceiling and the body that grows the unit table.
const UNIT_CHECK: &str = "check_unit_capacity";
const UNIT_OWNER: &str = "retain_unit";

/// The two filesystem routes the snapshot takes, each of which must have one
/// site.
///
/// The source route is the bounded reader, which is the only body that opens a
/// source at all: an unbounded `std::fs::read` beside it would be a second
/// route past the byte ceilings.
const FILE_READ: &str = "bounded";
const DIRECTORY_READ: &str = "read_dir";

/// 4.T8 (Invariants 4, 5): canonical confinement dominates every source read,
/// the directory-entry check dominates package-walk retention, the fact
/// ceilings dominate the one parse and the one fact walk they bound, and every
/// source, byte, and unit ceiling dominates the table it pays for.
#[test]
fn go_snapshot_limit_checks_dominate_source_and_unit_retention() {
    assert_store_checks_dominate_retention();
    assert_fact_ceilings_dominate_the_walk_they_bound();
    assert_walk_confines_and_budgets_before_retention();
    assert_unit_check_dominates_unit_retention();
    assert_single_site(SOURCE_CHECK, STORE);
    assert_single_site(BYTE_BOUNDS, STORE);
    assert_single_site(UNIT_CHECK, CONSTRUCTOR);
    assert_single_site(BUDGET_CHECK, WALK);
    assert_single_site(DIRECTORY_READ, WALK);
    assert_single_site(FACT_CEILINGS, STORE);
    assert_single_site(PARSE_ROUTE, STORE);
    assert_single_site(FACT_WALK, STORE);
    assert_single_snapshot_site(SOURCE_DIGEST, STORE);
    assert_single_snapshot_site(FILE_READ, STORE);
    assert_single_retention_site(SOURCE_RETENTION, STORE);
    assert_single_retention_site(INDEX_RETENTION, STORE);
    assert_single_retention_site(UNIT_RETENTION, CONSTRUCTOR);
    assert_single_retention_site(DIRECTORY_RETENTION, WALK);
}

/// The snapshot converts its own fact ceilings, hands them to the one bounded
/// walk, and keeps nothing the walk produced until it has returned.
///
/// The other ceilings are checked in the body that grows a table. The two fact
/// ceilings are not: they are spent inside `pedant-syntax`, which owns the
/// order proof for descent and insertion. What this owner has to state instead
/// is that they reach that walk at all, and that the parse, the walk, and the
/// retention run in that order — an extraction that digested and stored the
/// source first would be bounded by nothing this snapshot configured.
fn assert_fact_ceilings_dominate_the_walk_they_bound() {
    let store = parsed(STORE);
    let reader = &method(&store, READER).block;
    let converted = statement_naming(reader, FACT_CEILINGS).unwrap_or_else(|| {
        panic!("`{READER}` should convert its ceilings through `{FACT_CEILINGS}`")
    });
    let retained = statement_naming(reader, SOURCE_DIGEST).unwrap_or_else(|| {
        panic!("`{READER}` should mint the entry it keeps through `{SOURCE_DIGEST}`")
    });
    assert!(
        converted < retained,
        "`{READER}` must bound its walk (statement {converted}) before it mints a stored source (statement {retained})"
    );

    let extraction = &free(&store, EXTRACTION).block;
    let parse = statement_naming(extraction, PARSE_ROUTE)
        .unwrap_or_else(|| panic!("`{EXTRACTION}` should parse through `{PARSE_ROUTE}`"));
    let walk = statement_naming(extraction, FACT_WALK)
        .unwrap_or_else(|| panic!("`{EXTRACTION}` should walk through `{FACT_WALK}`"));
    let inventory = statement_naming(extraction, INVENTORY)
        .unwrap_or_else(|| panic!("`{EXTRACTION}` should state the retained inventory"));
    assert!(
        parse < walk,
        "`{EXTRACTION}` must parse once (statement {parse}) before it walks for facts (statement {walk})"
    );
    assert!(
        walk < inventory,
        "`{EXTRACTION}` must walk under its ceilings (statement {walk}) before it retains an inventory (statement {inventory})"
    );
}

/// The store checks its count before it grows, and its bytes before it reads.
fn assert_store_checks_dominate_retention() {
    let store = parsed(STORE);
    let intern = &method(&store, INTERN).block;
    let checked = statement_naming(intern, SOURCE_CHECK)
        .unwrap_or_else(|| panic!("`{INTERN}` should state `{SOURCE_CHECK}`"));
    for route in [SOURCE_RETENTION, INDEX_RETENTION] {
        let retention = statement_naming_field(intern, route)
            .unwrap_or_else(|| panic!("`{INTERN}` should grow `{route}`"));
        assert!(
            checked < retention,
            "`{INTERN}` must reach `{SOURCE_CHECK}` (statement {checked}) before `{route}` (statement {retention})"
        );
    }

    let read = statement_naming(intern, READER)
        .unwrap_or_else(|| panic!("`{INTERN}` should state `{READER}`"));
    let charged = statement_naming_field(intern, "consumed.saturating_add")
        .unwrap_or_else(|| panic!("`{INTERN}` should charge the total it read"));
    assert!(
        read < charged,
        "`{INTERN}` must read a source (statement {read}) before charging its length (statement {charged})"
    );

    let reader = &method(&store, READER).block;
    let opened = statement_naming(reader, FILE_READ)
        .unwrap_or_else(|| panic!("`{READER}` must be the one body that opens a source"));
    let bounded = statement_naming(reader, BYTE_BOUNDS)
        .unwrap_or_else(|| panic!("`{READER}` should hand its byte ceilings to the read"));
    assert_eq!(
        opened, bounded,
        "`{READER}` must bound the same statement that opens the source"
    );
}

/// The walk charges its budget and confines every path before it keeps one.
fn assert_walk_confines_and_budgets_before_retention() {
    let walk = parsed(WALK);
    let listing = &method(&walk, LISTING).block;
    let read = statement_naming(listing, DIRECTORY_READ)
        .unwrap_or_else(|| panic!("`{LISTING}` should list through `{DIRECTORY_READ}`"));
    let spent = statement_naming(listing, BUDGET_CHECK)
        .unwrap_or_else(|| panic!("`{LISTING}` should charge the budget"));
    assert!(
        read < spent,
        "`{LISTING}` lists a directory (statement {read}) then charges every entry it yielded (statement {spent})"
    );

    let walker = &method(&walk, WALKER).block;
    let listed = statement_naming(walker, LISTING)
        .unwrap_or_else(|| panic!("`{WALKER}` should reach `{LISTING}`"));
    let retention = statement_naming(walker, DIRECTORY_OWNER)
        .unwrap_or_else(|| panic!("`{WALKER}` should reach `{DIRECTORY_OWNER}`"));
    assert!(
        listed < retention,
        "`{WALKER}` must charge the budget (statement {listed}) before retaining a package directory (statement {retention})"
    );
    assert!(
        statement_naming_field(&method(&walk, DIRECTORY_OWNER).block, DIRECTORY_RETENTION)
            .is_some(),
        "`{DIRECTORY_OWNER}` must be the one body that grows `{DIRECTORY_RETENTION}`"
    );

    assert!(
        statement_naming(&method(&walk, ENTRY_ADMISSION).block, CONFINEMENT).is_some(),
        "`{ENTRY_ADMISSION}` must confine every path it admits"
    );
    assert_confinement_is_owned_by_the_two_stages();
}

/// The confinement route is reached by the loader and the walk, and by nothing
/// else that could open a path without it.
fn assert_confinement_is_owned_by_the_two_stages() {
    let naming: Box<[&str]> = GO_MODULES
        .iter()
        .filter(|module| SourceScan::of_file(&parsed(module)).reaches(CONFINEMENT) > 0)
        .copied()
        .collect();
    assert_eq!(
        &*naming,
        [WALK, "load.rs"],
        "`{CONFINEMENT}` must be called by the loader and the package walk alone"
    );
}

/// The unit ceiling is stated before the unit table grows.
fn assert_unit_check_dominates_unit_retention() {
    let constructor = parsed(CONSTRUCTOR);
    let owner = &method(&constructor, UNIT_OWNER).block;
    let checked = statement_naming(owner, UNIT_CHECK)
        .unwrap_or_else(|| panic!("`{UNIT_OWNER}` should state `{UNIT_CHECK}`"));
    let retention = statement_naming_field(owner, UNIT_RETENTION)
        .unwrap_or_else(|| panic!("`{UNIT_OWNER}` should grow `{UNIT_RETENTION}`"));
    assert!(
        checked < retention,
        "`{UNIT_OWNER}` must reach `{UNIT_CHECK}` (statement {checked}) before `{UNIT_RETENTION}` (statement {retention})"
    );
}

/// Exactly one snapshot owner states `route`, and it states it once.
///
/// Scoped to the snapshot stage on purpose: the loader opens manifests through
/// the same route name, and a claim over the whole Go surface would report that
/// read as a second source read.
fn assert_single_snapshot_site(route: &str, owner: &str) {
    let naming: Box<[(&str, usize)]> = SNAPSHOT_MODULES
        .iter()
        .map(|module| (*module, SourceScan::of_file(&parsed(module)).reaches(route)))
        .filter(|(_, count)| *count > 0)
        .collect();
    assert_eq!(
        &*naming,
        [(owner, 1)],
        "`{route}` must have exactly one site among the snapshot owners, in {owner}"
    );
}

/// Exactly one Go module states `route`, and it states it once.
fn assert_single_site(route: &str, owner: &str) {
    let naming: Box<[(&str, usize)]> = GO_MODULES
        .iter()
        .map(|module| (*module, SourceScan::of_file(&parsed(module)).reaches(route)))
        .filter(|(_, count)| *count > 0)
        .collect();
    assert_eq!(
        &*naming,
        [(owner, 1)],
        "`{route}` must have exactly one site, in {owner}"
    );
}

/// Exactly one Go module grows the named table, and it grows it once.
fn assert_single_retention_site(route: &str, owner: &str) {
    let naming: Box<[(&str, usize)]> = GO_MODULES
        .iter()
        .map(|module| {
            (
                *module,
                SourceScan::of_file(&parsed(module)).reaches_on_field(route),
            )
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    assert_eq!(
        &*naming,
        [(owner, 1)],
        "`{route}` must have exactly one retention site, in {owner}"
    );
}

fn parsed(module: &str) -> syn::File {
    parse_rust_file(&crate_path("src/resolution/go").join(module))
}

fn method<'file>(file: &'file syn::File, name: &str) -> &'file syn::ImplItemFn {
    impl_method(file, name).unwrap_or_else(|| panic!("the owner should declare `{name}`"))
}

fn free<'file>(file: &'file syn::File, name: &str) -> &'file syn::ItemFn {
    free_function(file, name).unwrap_or_else(|| panic!("the owner should declare `{name}`"))
}
