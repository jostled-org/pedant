//! The audit that admitted every third-party crate the product ships.
//!
//! `DependencyCapability` is a closed enum with no write, spawn, or socket
//! variant, so a claim read only out of the model cannot fail: the table agrees
//! with itself. The evidence behind the table is elsewhere — `pedant
//! supply-chain` vendors the locked graph, runs the production capability
//! detector over each crate, and commits the verdict. This module reads those
//! verdicts.
//!
//! Two claims, and the second needs the first. Every registry crate the lockfile
//! states carries an attestation at exactly that version, so an edge added
//! without an audit has no file to read. Then each admitted crate's attestation
//! states no write, spawn, or socket beyond the sites the audit accepted by
//! name, so a bumped watcher that grew a process spawner fails here rather than
//! arriving with the model still saying "read-only".

use std::collections::BTreeSet;
use std::str::FromStr;

use pedant_types::Capability;

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::dependency_model::{
    ADMITTED_DEPENDENCIES, ATTESTATION_ROOT, AcceptedFinding, AdmittedDependency,
    FORBIDDEN_CAPABILITIES, WORKSPACE_LOCKFILE,
};
use crate::resolution::manifest_reader::manifest_table;
use crate::resolution::tracked_index::tracked_paths;

/// One locked registry crate: the name it publishes under and the exact version
/// this workspace resolves to.
struct LockedPackage {
    /// The published crate name.
    name: Box<str>,
    /// The exact version the lockfile pins.
    version: Box<str>,
}

/// 4.T3's audit half: the admitted closure's read-only claim is backed by a
/// committed pedant verdict rather than by the enum that states it.
pub(crate) fn assert_every_admitted_dependency_carries_an_audit() {
    let locked = locked_registry_packages();
    assert_the_locked_graph_is_attested(&locked);
    assert_the_admitted_closure_states_only_audited_capabilities(&locked);
}

/// Every locked registry crate has an attestation, and every attestation names a
/// locked registry crate.
///
/// The comparison runs both ways. A membership check would accept a graph that
/// grew an unaudited crate, and its reverse would accept a baseline tree still
/// carrying the verdict for a crate the lockfile dropped — which is exactly the
/// shape a swapped dependency hides in.
fn assert_the_locked_graph_is_attested(locked: &[LockedPackage]) {
    assert!(
        !locked.is_empty(),
        "{WORKSPACE_LOCKFILE} states no registry dependency, so an attestation claim over it \
         would range over nothing"
    );
    let expected: BTreeSet<String> = locked.iter().map(LockedPackage::identity).collect();
    let attested = committed_attestations();
    // Three hundred agreeing rows say nothing, and printing them buries the two
    // that disagree. Only the difference is reported, in both directions.
    let unaudited: Box<[&String]> = expected.difference(&attested).collect();
    let orphaned: Box<[&String]> = attested.difference(&expected).collect();
    assert!(
        unaudited.is_empty() && orphaned.is_empty(),
        "the committed pedant attestations and the locked registry graph disagree: {unaudited:?} \
         is locked with no committed audit, and {orphaned:?} is attested with no locked package. \
         Run `cargo run -p pedant -- supply-chain update` and read the verdict for every crate \
         the run adds"
    );
}

/// Each admitted crate's audit was taken over real files and states no forbidden
/// capability the audit did not accept by name.
fn assert_the_admitted_closure_states_only_audited_capabilities(locked: &[LockedPackage]) {
    let mut audited = BTreeSet::new();
    for admitted in ADMITTED_DEPENDENCIES {
        let package = admitted.edge.package;
        let version = locked_version(locked, package);
        let attestation = attestation_of(package, version);
        assert_the_audit_read_the_crate(&attestation, package);
        let reported = forbidden_sites(&attestation, package);
        assert_eq!(
            reported,
            accepted_sites(admitted),
            "the {package}@{version} attestation and the audit that admitted it disagree about \
             which forbidden capabilities it states"
        );
        audited.extend(reported);
    }
    assert!(
        !audited.is_empty(),
        "no admitted crate's attestation states a forbidden capability, so the detector behind \
         every one of these verdicts may have stopped reporting"
    );
}

/// Every lockfile entry that resolves through a registry, in lockfile order.
///
/// A workspace member states no `source`, and it has no upstream to audit: it is
/// the tree these predicates already read directly.
///
/// Settled at construction and read through borrows by both consumers, so it
/// owns no buffer it can grow.
fn locked_registry_packages() -> Box<[LockedPackage]> {
    let lockfile = manifest_table(WORKSPACE_LOCKFILE);
    lockfile
        .get("package")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{WORKSPACE_LOCKFILE} states a [[package]] array"))
        .iter()
        .filter(|package| package.get("source").is_some())
        .map(locked_package)
        .collect()
}

/// One `[[package]]` entry, read as the pair an attestation is filed under.
fn locked_package(package: &toml::Value) -> LockedPackage {
    LockedPackage {
        name: lock_field(package, "name").into(),
        version: lock_field(package, "version").into(),
    }
}

/// One required string field of a lockfile entry.
fn lock_field<'lock>(package: &'lock toml::Value, key: &str) -> &'lock str {
    package
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("every {WORKSPACE_LOCKFILE} entry states a {key}"))
}

/// The one version the lockfile resolves an admitted crate to.
///
/// Two locked versions of an admitted crate would mean the product links a copy
/// nobody chose, and the audit could not say which one it read.
fn locked_version<'lock>(locked: &'lock [LockedPackage], package: &str) -> &'lock str {
    let mut matches = locked
        .iter()
        .filter(|entry| &*entry.name == package)
        .map(|entry| &*entry.version);
    let version = matches
        .next()
        .unwrap_or_else(|| panic!("{WORKSPACE_LOCKFILE} locks the admitted crate {package}"));
    let extra: Box<[&str]> = matches.collect();
    assert!(
        extra.is_empty(),
        "{WORKSPACE_LOCKFILE} locks {package} at {version} and also at {extra:?}, so no single \
         attestation answers for what the product links"
    );
    version
}

/// Every attestation committed beneath the baseline root, as `name version`.
///
/// Git is asked rather than the directory walked, because `committed` is the
/// whole claim. `pedant supply-chain update` writes a file for every crate it
/// audits, so a walk answers "the audit ran on this disk once" — which stays
/// true for a verdict nobody added, and which no other checkout can see. An
/// unstaged attestation is exactly the shape a new edge slips through in, so
/// the reader that admits it must not be the one the working tree answers.
fn committed_attestations() -> BTreeSet<String> {
    tracked_paths(ATTESTATION_ROOT)
        .iter()
        .map(|path| attestation_identity(path))
        .collect()
}

/// One tracked attestation path, read as the pair it is filed under.
///
/// Every rejection below is a path Git tracks beneath the baseline root that
/// this reader cannot turn into an identity. Skipping one would drop a crate
/// out of the comparison silently, and a dropped crate is an unaudited one.
fn attestation_identity(path: &str) -> String {
    let filed = path
        .strip_prefix(&format!("{ATTESTATION_ROOT}/"))
        .unwrap_or_else(|| {
            panic!("git listed {path}, which does not sit beneath {ATTESTATION_ROOT}")
        });
    let (name, file) = filed
        .split_once('/')
        .unwrap_or_else(|| panic!("{path} is not filed under a crate directory"));
    let version = file
        .strip_suffix(".json")
        .unwrap_or_else(|| panic!("{path} is not an attestation this reader can name"));
    assert!(
        !name.is_empty() && !version.is_empty() && !version.contains('/'),
        "{path} names no single crate and version"
    );
    format!("{name} {version}")
}

/// One crate's committed attestation, parsed.
fn attestation_of(package: &str, version: &str) -> serde_json::Value {
    let relative = format!("{ATTESTATION_ROOT}/{package}/{version}.json");
    serde_json::from_str(&read_text(&relative))
        .unwrap_or_else(|error| panic!("{relative} should parse as JSON: {error}"))
}

/// The audit opened files, and read every one it opened.
///
/// A verdict over no file reports no capability, so a forbid over it would hold
/// for a crate the audit never opened. `skipped_files` closes the smaller hole
/// beside it: a file the walk reached and then could not read would leave the
/// forbid ranging over less than the walk itself covered.
///
/// A zero here does not say the walk reached the whole package, and this
/// predicate does not claim it. `pedant supply-chain` follows the module tree a
/// crate declares, and `sha2` declares its per-architecture backends inside a
/// `cfg_if!` that a syntactic walk does not expand — so its verdict covers 5 of
/// 27 published sources while still reporting nothing skipped. What the module
/// tree never reaches is carried outside this predicate by a whole-tree
/// `cargo run -p pedant -- capabilities` scan over each admitted crate's
/// unpacked sources, recorded in the Step 4 dependency-audit receipt: it reads
/// every file on disk and found no write, spawn, socket, or network site the
/// attestations do not already state.
fn assert_the_audit_read_the_crate(attestation: &serde_json::Value, package: &str) {
    let completeness = required(attestation, "analysis_completeness", package);
    let analyzed = count(completeness, "analyzed_files", package);
    let skipped = count(completeness, "skipped_files", package);
    assert!(
        analyzed > 0,
        "the {package} attestation analyzed no file, so every claim over it is vacuous"
    );
    assert_eq!(
        skipped, 0,
        "the {package} attestation skipped {skipped} file(s), so it answers for less than the \
         crate the product links"
    );
}

/// Every finding in one attestation whose capability this closure forbids.
fn forbidden_sites(attestation: &serde_json::Value, package: &str) -> BTreeSet<String> {
    let profile = required(attestation, "profile", package);
    required(profile, "findings", package)
        .as_array()
        .unwrap_or_else(|| panic!("the {package} attestation states a findings array"))
        .iter()
        .filter_map(|finding| forbidden_site(finding, package))
        .collect()
}

/// One finding, rendered when it states a forbidden capability and dropped when
/// it does not.
fn forbidden_site(finding: &serde_json::Value, package: &str) -> Option<String> {
    let capability = capability_of(finding, package);
    FORBIDDEN_CAPABILITIES.contains(&capability).then(|| {
        let location = required(finding, "location", package);
        site(
            capability,
            text(location, "file", package),
            text(finding, "evidence", package),
        )
    })
}

/// The capability one finding states, as the type the model is written in.
fn capability_of(finding: &serde_json::Value, package: &str) -> Capability {
    let stated = text(finding, "capability", package);
    Capability::from_str(stated)
        .unwrap_or_else(|error| panic!("the {package} attestation states {stated}: {error}"))
}

/// Every forbidden capability one admitted crate's audit accepted.
fn accepted_sites(admitted: &AdmittedDependency) -> BTreeSet<String> {
    admitted
        .accepted_findings
        .iter()
        .map(|accepted| {
            assert_the_row_excuses_something(admitted.edge.package, accepted);
            site(accepted.capability, accepted.file, accepted.evidence)
        })
        .collect()
}

/// One accepted row names a capability this closure forbids, and says why.
///
/// A row for a capability nothing forbade could never match a reported site. It
/// would sit in the table reading like an audit finding and excuse nothing.
fn assert_the_row_excuses_something(package: &str, accepted: &AcceptedFinding) {
    assert!(
        FORBIDDEN_CAPABILITIES.contains(&accepted.capability),
        "{package} accepts {} for {}, which this closure never forbade",
        accepted.capability,
        accepted.file
    );
    assert!(
        !accepted.reason.is_empty(),
        "{package} accepts the {} site at {} with no reason",
        accepted.evidence,
        accepted.file
    );
}

/// One capability site, as the row both sides of the comparison are rendered to.
///
/// The line is left out on purpose. A patch bump that moves a test module would
/// otherwise rewrite the accepted table, and a table nobody can read across a
/// bump stops being an audit record; the file and the named symbol still refuse
/// a spawn, a socket, or a write the audit never saw.
fn site(capability: Capability, file: &str, evidence: &str) -> String {
    format!("{capability} {file} {evidence}")
}

/// One required member of a parsed attestation.
///
/// `Value` indexing answers a missing key with null, which reads downstream as
/// an empty finding list — the one answer a proof like this must never accept
/// silently.
fn required<'json>(
    value: &'json serde_json::Value,
    key: &str,
    package: &str,
) -> &'json serde_json::Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("the {package} attestation states {key}"))
}

/// One required string member of a parsed attestation.
fn text<'json>(value: &'json serde_json::Value, key: &str, package: &str) -> &'json str {
    required(value, key, package)
        .as_str()
        .unwrap_or_else(|| panic!("the {package} attestation states {key} as a string"))
}

/// One required count member of a parsed attestation.
fn count(value: &serde_json::Value, key: &str, package: &str) -> u64 {
    required(value, key, package)
        .as_u64()
        .unwrap_or_else(|| panic!("the {package} attestation states {key} as a count"))
}

impl LockedPackage {
    /// The `name version` pair an attestation is filed under.
    fn identity(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}
