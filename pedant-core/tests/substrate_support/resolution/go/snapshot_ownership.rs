//! Where the Go snapshot checks its ceilings and confines its paths, read from
//! the production source.
//!
//! "Refused before the excess was retained" and "confined before the bytes were
//! opened" are claims about order, and a behavioral case cannot tell a check
//! that ran first from one that ran after a push and rolled back. So the shared
//! snapshot store, the Go store above it, the shared record cache, the package
//! walk, and the snapshot constructor are parsed and their statements are read:
//! every ceiling precedes the growth it pays for, every read is preceded by the
//! confinement that admitted its path, and no retained table has a second growth
//! site that could take an unchecked route.
//!
//! The interning table left the Go store when both languages began retaining
//! through one, so the order claim below reads a language-neutral body and holds
//! Rust to the same sequence. What stayed behind is the one ceiling Go adds.
//!
//! How that surface is parsed, counted, and located is
//! [`super::snapshot_reading`]. Only the claims are here.

use crate::resolution::go::owners::{GO_MODULES, SNAPSHOT_MODULES};
use crate::resolution::go::scan::statement_naming_field;
use crate::resolution::go::snapshot_reading::{CACHE, GoReading, Named, SNAPSHOT_STORE, located};

/// The Go owners the claim is read from.
///
/// The read and the walk left the store when a source became something several
/// project slices share, the admission sequence left the provider when both
/// languages read through one cache, and the interning table followed when both
/// retained through one store. The provider owns what Go decides, the inventory
/// owns the one parse and the one fact walk, and the store owns the one extra
/// ceiling a retained Go record owes.
const STORE: &str = "store.rs";
const PROVIDER: &str = "provider.rs";
const INVENTORY_OWNER: &str = "inventory.rs";
const WALK: &str = "discovery.rs";
const CONSTRUCTOR: &str = "unit_table.rs";

/// The bodies each order claim is read from.
///
/// Each is the sequence itself, not the entry point naming it. In the cache
/// `admit` is the refusal memo and `attempt` the sequence; in the shared store
/// the split runs the other way, and `admit` is the sequence `intern` calls.
const INTERN: &str = "intern";
const ADMISSION: &str = "admit";
const READER: &str = "attempt";
const CONVERSION: &str = "inventory";
const EXTRACTION: &str = "of_source";

/// The route the shared store reaches a record through, the normalization gate
/// it passes first, and the record the Go callback builds.
///
/// `NORMALIZATION` is the tail of `SourcePath::new`: the scan keys a call on its
/// last path segment, the segment a rename changes.
const SUPPLY: &str = "supply";
const NORMALIZATION: &str = "new";
const RECORD_CONSTRUCTOR: &str = "of_record";

/// The fact ceilings the snapshot converts, the two walks they bound, and the
/// digest and inventory those walks pay for.
const FACT_CEILINGS: &str = "fact_limits";
const PARSE_ROUTE: &str = "parse_bound";
const FACT_WALK: &str = "go_file_facts";
const SOURCE_DIGEST: &str = "digest_bytes";
const INVENTORY: &str = "conditions_of";

/// The ceilings the shared store owns, the one Go adds, and the one the cache
/// hands its reader.
///
/// The two byte ceilings are stated as the bounds handed to the one bounded
/// reader rather than as checks anything runs itself: the length a ceiling is
/// compared against has to be the length that was read, which only the reader
/// holds. The store recharges that length through `charge`, because a shared
/// read is not a free source for the corpus that selected it, and Go's
/// `check_retention` then holds the record to the facts and depth only Go bounds.
const SOURCE_CHECK: &str = "check_capacity";
const BYTE_CHARGE: &str = "charge";
const RETENTION_CHECK: &str = "check_retention";
const BYTE_BOUNDS: &str = "bounds";

/// The callback a language hands the shared store, which is the last ceiling
/// that store spends before it grows.
///
/// The same spelling as `DIRECTORY_OWNER` and a different claim: one is the
/// package walk's own retention body, the other the argument the store calls.
const LANGUAGE_RETENTION: &str = "retain";

/// The tables the shared store and the constructor grow, and the running total
/// the store charges before it grows them.
const TOTAL_CHARGE: &str = "consumed.saturating_add";
const SOURCE_RETENTION: &str = "stored.push";
const INDEX_RETENTION: &str = "indexes.insert";
const UNIT_RETENTION: &str = "drafts.push";

/// The one order the shared store admits a source in, first statement to last.
///
/// The whole sequence rather than its two endpoints: every step between the
/// count ceiling and the table it pays for is itself a ceiling or a charge, and
/// a claim naming only the ends would accept a store that spent the byte charge
/// after the record was built.
const ADMISSION_ORDER: &[Named] = &[
    Named::Route(SOURCE_CHECK),
    Named::Route(NORMALIZATION),
    Named::Route(SUPPLY),
    Named::Route(BYTE_CHARGE),
    Named::Route(LANGUAGE_RETENTION),
    Named::Growth(TOTAL_CHARGE),
    Named::Growth(INDEX_RETENTION),
    Named::Growth(SOURCE_RETENTION),
];

/// The package walk's bodies, its budget, and the confinement it applies.
///
/// Only a link is confined: an ordinary file or directory is named beneath a
/// canonical directory and so is already canonical, leaving `sort_link` the one
/// body resolving a target its name does not state. `ENTRY_FILING` names the
/// route and not the receiver, because the two admitted lists are local buffers
/// rather than fields and both arms sit in the one closing `match`.
const LISTING: &str = "listing";
const WALKER: &str = "descend";
const DIRECTORY_OWNER: &str = "retain";
const BUDGET_CHECK: &str = "spend";
const CONFINEMENT: &str = "canonical_in_root";
const MANIFEST_CONFINEMENT: &str = "confined_manifest";
const LINK_ADMISSION: &str = "sort_link";
const ENTRY_FILING: &str = "push";
const DIRECTORY_RETENTION: &str = "found.push";

/// The constructor's unit ceiling and the body that grows the unit table.
const UNIT_CHECK: &str = "check_unit_capacity";
const UNIT_OWNER: &str = "retain_unit";

/// The two filesystem routes the snapshot takes, each of which must have one
/// site.
///
/// The source route is the bounded reader, the only body that opens a source at
/// all: an unbounded `std::fs::read` beside it would be a second route past the
/// byte ceilings.
const FILE_READ: &str = "bounded";
const DIRECTORY_READ: &str = "read_dir";

/// Every route one shared owner states, with the Go scope it must be absent
/// from.
///
/// A table rather than a call per row: the rows differ only in what they name
/// and where, and as calls the scope was an argument read one line at a time.
const SHARED_SITES: &[(Named, &str, &[&str])] = &[
    (Named::Route(SOURCE_CHECK), SNAPSHOT_STORE, GO_MODULES),
    (Named::Route(BYTE_BOUNDS), CACHE, GO_MODULES),
    (Named::Route(SOURCE_DIGEST), CACHE, SNAPSHOT_MODULES),
    (Named::Route(FILE_READ), CACHE, SNAPSHOT_MODULES),
    (Named::Growth(SOURCE_RETENTION), SNAPSHOT_STORE, GO_MODULES),
    (Named::Growth(INDEX_RETENTION), SNAPSHOT_STORE, GO_MODULES),
];

/// Every route exactly one Go module states, with the module that states it.
const GO_SITES: &[(Named, &str)] = &[
    (Named::Route(RETENTION_CHECK), STORE),
    (Named::Route(UNIT_CHECK), CONSTRUCTOR),
    (Named::Route(BUDGET_CHECK), WALK),
    (Named::Route(DIRECTORY_READ), WALK),
    (Named::Route(FACT_CEILINGS), PROVIDER),
    (Named::Route(PARSE_ROUTE), INVENTORY_OWNER),
    (Named::Route(FACT_WALK), INVENTORY_OWNER),
    (Named::Growth(UNIT_RETENTION), CONSTRUCTOR),
    (Named::Growth(DIRECTORY_RETENTION), WALK),
];

/// 4.T8 (Invariants 4, 5): canonical confinement dominates every source read,
/// the directory-entry check dominates package-walk retention, the fact
/// ceilings dominate the one parse and the one fact walk they bound, and every
/// source, byte, and unit ceiling dominates the table it pays for.
#[test]
fn go_snapshot_limit_checks_dominate_source_and_unit_retention() {
    let reading = GoReading::read();
    assert_store_checks_dominate_retention(&reading);
    assert_fact_ceilings_dominate_the_walk_they_bound(&reading);
    assert_walk_confines_and_budgets_before_retention(&reading);
    assert_confinement_is_owned_by_the_two_stages(&reading);
    assert_unit_check_dominates_unit_retention(&reading);
    assert!(
        !SHARED_SITES.is_empty() && !GO_SITES.is_empty(),
        "the two site tables are everything the loops below range over, so an emptied one \
         states no single-site claim and reports success"
    );
    for (named, owner, scope) in SHARED_SITES.iter().copied() {
        assert_shared_site(&reading, named, owner, scope);
    }
    for (named, owner) in GO_SITES.iter().copied() {
        assert_single_site(&reading, named, owner);
    }
}

/// The shared admission sequence states every ceiling it owes before it grows
/// the tables that ceiling pays for, Go's own ceiling runs inside the callback
/// that sequence spends last, and the cache bounds the read it owns.
///
/// One site covering both languages. The order used to be read out of the Go
/// store's own `intern`, so the Rust store could have disagreed with it and
/// nothing here would have said so.
///
/// Go's half is a claim about one statement: its ceiling and the record that
/// ceiling guards both sit inside the one closure argument, so all three routes
/// resolve to the same statement of `intern`. A ceiling moved out of the
/// callback would land in a later one, after the shared store had retained.
fn assert_store_checks_dominate_retention(reading: &GoReading) {
    let admit = &reading.method(SNAPSHOT_STORE, ADMISSION).block;
    let order: Box<[(&str, usize)]> = ADMISSION_ORDER
        .iter()
        .copied()
        .map(|step| (step.route(), located(admit, ADMISSION, step)))
        .collect();
    let ends = (order.first(), order.last());
    assert_eq!(
        (ends.0.map(|step| step.0), ends.1.map(|step| step.0)),
        (Some(SOURCE_CHECK), Some(SOURCE_RETENTION)),
        "the stated order must run from the first ceiling to the last table it pays for"
    );
    for (earlier, later) in order.iter().zip(order.iter().skip(1)) {
        assert!(
            earlier.1 < later.1,
            "`{ADMISSION}` must reach `{}` (statement {}) before `{}` (statement {})",
            earlier.0,
            earlier.1,
            later.0,
            later.1
        );
    }

    let intern = &reading.method(STORE, INTERN).block;
    let handed = located(intern, INTERN, Named::Route(INTERN));
    assert_eq!(
        (
            located(intern, INTERN, Named::Route(RETENTION_CHECK)),
            located(intern, INTERN, Named::Route(RECORD_CONSTRUCTOR)),
        ),
        (handed, handed),
        "`{RETENTION_CHECK}` and `{RECORD_CONSTRUCTOR}` must sit inside the callback `{INTERN}` hands the shared store (statement {handed})"
    );

    let reader = &reading.method(CACHE, READER).block;
    assert_eq!(
        located(reader, READER, Named::Route(FILE_READ)),
        located(reader, READER, Named::Route(BYTE_BOUNDS)),
        "`{READER}` must bound the same statement that opens the source"
    );
}

/// The snapshot converts its own fact ceilings, hands them to the one bounded
/// walk, and keeps nothing the walk produced until it has returned.
///
/// The other ceilings are checked in the body that grows a table. The two fact
/// ceilings are not: they are spent inside `pedant-syntax`, which owns the order
/// proof for descent and insertion. What this owner has to state instead is that
/// they reach that walk at all, and that the parse, the walk, and the retention
/// run in that order — an extraction that digested and stored the source first
/// would be bounded by nothing this snapshot configured.
fn assert_fact_ceilings_dominate_the_walk_they_bound(reading: &GoReading) {
    let conversion = &reading.method(PROVIDER, CONVERSION).block;
    assert_eq!(
        located(conversion, CONVERSION, Named::Route(FACT_CEILINGS)),
        located(conversion, CONVERSION, Named::Route(EXTRACTION)),
        "`{CONVERSION}` must hand the converted ceilings to the same statement that extracts"
    );

    let reader = &reading.method(CACHE, READER).block;
    let inventoried = located(reader, READER, Named::Route(CONVERSION));
    let retained = located(reader, READER, Named::Route(SOURCE_DIGEST));
    assert!(
        inventoried < retained,
        "`{READER}` must take the bounded inventory (statement {inventoried}) before it mints a stored source (statement {retained})"
    );

    let extraction = &reading.method(INVENTORY_OWNER, EXTRACTION).block;
    let parse = located(extraction, EXTRACTION, Named::Route(PARSE_ROUTE));
    let walk = located(extraction, EXTRACTION, Named::Route(FACT_WALK));
    let inventory = located(extraction, EXTRACTION, Named::Route(INVENTORY));
    assert!(
        parse < walk,
        "`{EXTRACTION}` must parse once (statement {parse}) before it walks for facts (statement {walk})"
    );
    assert!(
        walk < inventory,
        "`{EXTRACTION}` must walk under its ceilings (statement {walk}) before it retains an inventory (statement {inventory})"
    );
}

/// The walk charges its budget before it keeps a directory, and confines every
/// link before it files what the link resolved to.
fn assert_walk_confines_and_budgets_before_retention(reading: &GoReading) {
    let listing = &reading.method(WALK, LISTING).block;
    let read = located(listing, LISTING, Named::Route(DIRECTORY_READ));
    let spent = located(listing, LISTING, Named::Route(BUDGET_CHECK));
    assert!(
        read < spent,
        "`{LISTING}` lists a directory (statement {read}) then charges every entry it yielded (statement {spent})"
    );

    let walker = &reading.method(WALK, WALKER).block;
    let listed = located(walker, WALKER, Named::Route(LISTING));
    let retention = located(walker, WALKER, Named::Route(DIRECTORY_OWNER));
    assert!(
        listed < retention,
        "`{WALKER}` must charge the budget (statement {listed}) before retaining a package directory (statement {retention})"
    );
    let owner = &reading.method(WALK, DIRECTORY_OWNER).block;
    assert!(
        statement_naming_field(owner, DIRECTORY_RETENTION).is_some(),
        "`{DIRECTORY_OWNER}` must be the one body that grows `{DIRECTORY_RETENTION}`"
    );

    let link = &reading.method(WALK, LINK_ADMISSION).block;
    let confined = located(link, LINK_ADMISSION, Named::Route(CONFINEMENT));
    let filed = located(link, LINK_ADMISSION, Named::Route(ENTRY_FILING));
    assert!(
        confined < filed,
        "`{LINK_ADMISSION}` must confine a link (statement {confined}) before filing what it resolved to (statement {filed})"
    );
}

/// The generic confinement route is owned by the path helper, package walk,
/// and provider. Loader and package discovery share the manifest helper.
///
/// The provider joined that list when the read moved out of the store: it is the
/// one body that opens a source, and a public provider may be handed a path no
/// earlier stage confined. The walk stayed on it for the one entry whose target
/// its name does not state — a link.
fn assert_confinement_is_owned_by_the_two_stages(reading: &GoReading) {
    let naming: Box<[&str]> = reading
        .stated_in(GO_MODULES, Named::Route(CONFINEMENT))
        .iter()
        .map(|(module, _)| *module)
        .collect();
    assert_eq!(&*naming, [WALK, "load.rs", "paths.rs", PROVIDER]);

    let manifests: Box<[&str]> = reading
        .stated_in(GO_MODULES, Named::Route(MANIFEST_CONFINEMENT))
        .iter()
        .map(|(module, _)| *module)
        .collect();
    assert_eq!(&*manifests, [WALK, "load.rs"]);
}

/// The unit ceiling is stated before the unit table grows.
fn assert_unit_check_dominates_unit_retention(reading: &GoReading) {
    let owner = &reading.method(CONSTRUCTOR, UNIT_OWNER).block;
    let checked = located(owner, UNIT_OWNER, Named::Route(UNIT_CHECK));
    let retention = located(owner, UNIT_OWNER, Named::Growth(UNIT_RETENTION));
    assert!(
        checked < retention,
        "`{UNIT_OWNER}` must reach `{UNIT_CHECK}` (statement {checked}) before `{UNIT_RETENTION}` (statement {retention})"
    );
}

/// One shared owner states `named` exactly once, and no owner in `scope` states
/// it at all.
///
/// Both halves are the claim. The shared half keeps the single-site guarantee
/// the Go tree used to make about itself; the scope half stops that guarantee
/// being reopened by a Go module which started opening, bounding, digesting, or
/// retaining a source of its own. The scope is the caller's, because the loader
/// opens manifests and digests their bytes through the same route names.
fn assert_shared_site(reading: &GoReading, named: Named, owner: &str, scope: &[&str]) {
    let route = named.route();
    let naming = reading.stated_in(scope, named);
    assert!(
        naming.is_empty(),
        "`{route}` belongs to {owner}; no Go owner in scope may state it: {naming:?}"
    );
    assert_eq!(
        reading.shared_count(owner, named),
        1,
        "`{route}` must have exactly one site, in {owner}"
    );
}

/// Exactly one Go module states `named`, and it states it once.
fn assert_single_site(reading: &GoReading, named: Named, owner: &str) {
    let route = named.route();
    assert_eq!(
        &*reading.stated_in(GO_MODULES, named),
        [(owner, 1)],
        "`{route}` must have exactly one site, in {owner}"
    );
}
