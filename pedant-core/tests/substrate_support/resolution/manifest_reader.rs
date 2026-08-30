//! Reading a tracked Cargo manifest the way every structural claim reads one.
//!
//! Three trees ask the same three questions of a manifest — what does this
//! feature select, what does this edge declare, and what is on by default — and
//! three private copies of the answer are three places for one of them to start
//! treating a missing table as an empty one. A missing `[features]` table and a
//! feature that selects nothing are different facts, and only the first is a
//! reason to stop.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::resolution::authority_scan::read_text;

/// Parse one tracked manifest, failing loudly rather than treating it as empty.
///
/// Read and parsed once for the process and keyed by path, the way the tracked
/// index is. This used to read and parse on every call — alone among the shared
/// readers here — so its callers grew private memos of their own: one hosted
/// row table hand-rolled a per-package map, and one feature loop re-parsed the
/// same manifest once per row. A cache the reader owns is a cache none of them
/// has to.
pub(crate) fn manifest_table(relative: &str) -> &'static toml::Table {
    static PARSED: OnceLock<Mutex<BTreeMap<Box<str>, &'static toml::Table>>> = OnceLock::new();
    let mut cache = PARSED
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        // A poisoned lock means an earlier parse panicked and already reported
        // itself. Taking the map back lets this caller state its own subject
        // rather than reporting the first caller's failure a second time.
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache
        .entry(relative.into())
        .or_insert_with(|| parse_manifest(relative))
}

/// One tracked manifest read and parsed, held for the rest of the process.
///
/// Leaked rather than cloned per caller: a parsed manifest is settled the
/// moment it is read, every answer taken from it is a borrow, and the process
/// is one test binary that reads a dozen files.
fn parse_manifest(relative: &str) -> &'static toml::Table {
    let table: toml::Table = toml::from_str(&read_text(relative))
        .unwrap_or_else(|error| panic!("{relative} should parse as TOML: {error}"));
    Box::leak(Box::new(table))
}

/// The manifest tables a dependency can be declared in.
///
/// Cargo resolves all three. A claim about what a package requires that read
/// only the first would pass a dev-dependency or a build-dependency edge
/// pointing the wrong way.
pub(crate) const DEPENDENCY_KINDS: [&str; 3] =
    ["dependencies", "dev-dependencies", "build-dependencies"];

/// One manifest table's string array, which is empty when the key is absent.
///
/// A key a manifest never states and a key it states as an empty list mean the
/// same thing to every caller here: the row selects nothing. A key stated as
/// anything but a list means neither, and it stops here — folding
/// `default = "checks"` into "selects nothing" would answer every membership
/// question with "no".
///
/// The entries are borrowed from the parsed manifest, which outlives every
/// answer taken from it. An owned copy per entry made a lookup cost a second
/// allocation at each call site that only wanted to compare.
pub(crate) fn string_array(value: Option<&toml::Value>) -> Box<[&str]> {
    match value {
        None => Box::default(),
        Some(stated) => stated
            .as_array()
            .expect("a manifest key this reader takes a list from states a list")
            .iter()
            .map(|entry| entry.as_str().expect("a manifest list entry is a string"))
            .collect(),
    }
}

/// One package's `[features]` table, which every published member declares.
///
/// A package that declares none has no feature claim to make, so the caller is
/// told rather than handed an empty table it would read as "selects nothing".
pub(crate) fn feature_table<'manifest>(
    manifest: &'manifest toml::Table,
    package: &str,
) -> &'manifest toml::Table {
    manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{package} declares a [features] table"))
}

/// What one feature selects, in the order the manifest states it.
///
/// A feature the table does not state stops here. [`string_array`] reads an
/// absent key as an empty list, which is the right answer for a key a caller
/// says is optional and the wrong one for a named feature: a feature renamed or
/// deleted out of the manifest would read as one that selects nothing, and
/// every membership question asked of it would answer "no" — the same silent
/// pass the module header names as the reason a missing table and an empty
/// selection are different facts.
pub(crate) fn feature_selection<'manifest>(
    manifest: &'manifest toml::Table,
    package: &str,
    feature: &str,
) -> Box<[&'manifest str]> {
    let stated = feature_table(manifest, package)
        .get(feature)
        .unwrap_or_else(|| panic!("{package} declares no `{feature}` feature to select with"));
    string_array(Some(stated))
}

/// One package's default feature list, which is empty when it selects nothing.
///
/// Read through [`feature_table`] like every other feature question. A manifest
/// with no `[features]` table has no default selection to report, and answering
/// "selects nothing" would satisfy every caller asking whether a feature is off.
pub(crate) fn default_features(manifest: &toml::Table) -> Box<[&str]> {
    string_array(feature_table(manifest, package_name(manifest)).get("default"))
}

/// The package one manifest names, for the failure that has to name it.
///
/// Only a refusal reads this. A manifest that names no package is already the
/// wrong subject for a feature question, and the message must say which file it
/// could not answer for rather than name nothing.
fn package_name(manifest: &toml::Table) -> &str {
    manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("a manifest that names no package")
}

/// One declared dependency edge, in whichever of Cargo's two spellings it uses.
pub(crate) fn dependency_value<'manifest>(
    manifest: &'manifest toml::Table,
    owner: &str,
    package: &str,
) -> &'manifest toml::Value {
    manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{owner} declares a [dependencies] table"))
        .get(package)
        .unwrap_or_else(|| panic!("{owner} declares a {package} dependency"))
}

/// One declared dependency edge, as the table it is spelled with.
///
/// A bare `name = "1"` string edge states no path, no version bound this
/// repository controls, and no feature selection, so a caller whose claim is
/// about one of those is told the edge is not in the shape it asked about.
pub(crate) fn dependency_edge<'manifest>(
    manifest: &'manifest toml::Table,
    owner: &str,
    package: &str,
) -> &'manifest toml::Table {
    dependency_value(manifest, owner, package)
        .as_table()
        .unwrap_or_else(|| panic!("{owner}'s {package} edge must be a table, not a bare version"))
}

/// The features one declared edge selects, whatever spelling it uses.
///
/// A bare version edge selects nothing beyond its crate's defaults, and that is
/// a legitimate shape for a dependency with no selection to make. A scan over
/// every edge must read it as "selects no feature" rather than stop on it.
pub(crate) fn dependency_features<'manifest>(
    manifest: &'manifest toml::Table,
    owner: &str,
    package: &str,
) -> Box<[&'manifest str]> {
    match dependency_value(manifest, owner, package).as_table() {
        Some(table) => string_array(table.get("features")),
        None => Box::default(),
    }
}

/// Every dependency `owner` declares, in name order.
pub(crate) fn dependency_names<'manifest>(
    manifest: &'manifest toml::Table,
    owner: &str,
) -> Box<[&'manifest str]> {
    manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{owner} declares a [dependencies] table"))
        .keys()
        .map(String::as_str)
        .collect()
}

/// Every package one manifest requires, across every dependency kind, in name
/// order.
///
/// A kind the manifest never states holds no requirement, so it contributes
/// nothing rather than stopping the reading: a package with no build script
/// declares no `[build-dependencies]`, and that is a shape rather than a fault.
pub(crate) fn required_packages(manifest: &toml::Table) -> BTreeSet<&str> {
    DEPENDENCY_KINDS
        .iter()
        .filter_map(|kind| manifest.get(*kind).and_then(toml::Value::as_table))
        .flat_map(|table| table.keys().map(String::as_str))
        .collect()
}

/// One tracked manifest requires none of the named packages.
///
/// The one owner of a "this edge must not exist" claim. Two products state it
/// about the navigation crate and one crate states it about its own consumers,
/// and every one of them is the same reading of the same three dependency
/// tables.
///
/// The floor is the half a hand-written `contains` kept losing. A manifest whose
/// dependency tables this reader found empty satisfies every absence clause
/// written over it, so the reading is proved to have found something before any
/// name is tested.
pub(crate) fn assert_requires_none(relative: &str, forbidden: &[&str]) {
    let manifest = manifest_table(relative);
    let required = required_packages(manifest);
    assert!(
        !required.is_empty(),
        "{relative} declares no dependency at all, so a claim about what it must not require \
         reads nothing"
    );
    for package in forbidden {
        assert!(
            !required.contains(package),
            "{relative} requires {package}, and it must require none of {forbidden:?}"
        );
    }
}
